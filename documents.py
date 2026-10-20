import hashlib
import os
import re
import uuid
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DbSession

import audit
import models
from auth import get_current_user
from database import get_db
from permissions import get_document_or_404

router = APIRouter(prefix="/documents", tags=["documents"])

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(Path(__file__).parent / "uploads")))
MAX_BYTES = 5 * 1024 * 1024  # 5 MB

# type -> (content type, allowed extensions)
KINDS = {
    "pdf": ("application/pdf", {".pdf"}),
    "png": ("image/png", {".png"}),
    "jpeg": ("image/jpeg", {".jpg", ".jpeg"}),
    "text": ("text/plain", {".txt"}),
}


def detect_kind(data: bytes):
    """Decide the file type from its CONTENT, never from what the client says."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    try:
        if b"\x00" not in data:
            data.decode("utf-8")
            return "text"
    except UnicodeDecodeError:
        pass
    return None


def clean(text: str, limit: int = 100) -> str:
    text = os.path.basename(text.replace("\\", "/"))
    text = re.sub(r"[^A-Za-z0-9._ -]", "_", text).strip()
    return text[:limit] or "file"


# ---------- upload ----------
@router.post("", status_code=201)
async def upload(
    file: UploadFile = File(...),
    category: str = Form("general"),
    user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    if user.role != "owner":
        audit.log(db, user.id, "upload", None, "denied", "role not allowed")
        raise HTTPException(403, "Only document owners can upload")

    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        audit.log(db, user.id, "upload", None, "denied", "too large")
        raise HTTPException(413, "File too large (max 5 MB)")
    if len(data) == 0:
        raise HTTPException(400, "Empty file")

    name = clean(file.filename or "file")
    kind = detect_kind(data)
    ext = os.path.splitext(name)[1].lower()
    if kind is None or ext not in KINDS[kind][1]:
        audit.log(db, user.id, "upload", None, "denied", f"rejected type: {name}")
        raise HTTPException(415, "Allowed: PDF, PNG, JPG, TXT (content must match extension)")

    stored_name = uuid.uuid4().hex  # random, never derived from user input
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / stored_name).write_bytes(data)

    doc = models.Document(
        name=name, category=clean(category, 50), owner_id=user.id,
        stored_name=stored_name, content_type=KINDS[kind][0],
        size=len(data), sha256=hashlib.sha256(data).hexdigest(),
    )
    db.add(doc)
    db.commit()
    audit.log(db, user.id, "upload", doc.id, "allowed", name)
    return {"id": doc.id, "name": doc.name}


# ---------- list and search ----------
@router.get("")
def list_documents(
    name: str | None = None,
    category: str | None = None,
    owner_email: str | None = None,
    created_from: date | None = None,
    created_to: date | None = None,
    user: models.User = Depends(get_current_user),
    db: DbSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    granted = select(models.Grant.document_id).where(
        models.Grant.user_id == user.id,
        models.Grant.revoked_at.is_(None),
        or_(models.Grant.expires_at.is_(None), models.Grant.expires_at > now),
    )
    q = (
        select(models.Document, models.User.email)
        .join(models.User, models.User.id == models.Document.owner_id)
        .where(
            models.Document.deleted_at.is_(None),
            or_(models.Document.owner_id == user.id, models.Document.id.in_(granted)),
        )
    )
    if name:
        q = q.where(func.lower(models.Document.name).contains(name.lower(), autoescape=True))
    if category:
        q = q.where(models.Document.category == category)
    if owner_email:
        q = q.where(models.User.email == owner_email.lower())
    if created_from:
        q = q.where(models.Document.created_at >= datetime.combine(created_from, time.min, tzinfo=timezone.utc))
    if created_to:
        q = q.where(models.Document.created_at <= datetime.combine(created_to, time.max, tzinfo=timezone.utc))
    rows = db.execute(q.order_by(models.Document.created_at.desc())).all()
    return [
        {"id": d.id, "name": d.name, "category": d.category, "owner": email,
         "size": d.size, "created_at": d.created_at.isoformat()}
        for d, email in rows
    ]


# ---------- download ----------
@router.get("/{doc_id}/download")
def download(doc_id: str, user: models.User = Depends(get_current_user),
             db: DbSession = Depends(get_db)):
    # THE authorisation decision for downloads
    doc = get_document_or_404(db, user, doc_id, "read", audit_action="download")
    path = UPLOAD_DIR / doc.stored_name      # the name comes from the database only
    if not path.is_file():
        audit.log(db, user.id, "download", doc.id, "denied", "file missing on disk")
        raise HTTPException(404, "Not found")
    audit.log(db, user.id, "download", doc.id, "allowed")
    return FileResponse(
        path, media_type=doc.content_type, filename=doc.name,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
    )


# ---------- edit (rename / recategorise) ----------
class EditIn(BaseModel):
    name: str | None = None
    category: str | None = None


@router.patch("/{doc_id}")
def edit(doc_id: str, body: EditIn, user: models.User = Depends(get_current_user),
         db: DbSession = Depends(get_db)):
    doc = get_document_or_404(db, user, doc_id, "edit")
    old = f"{doc.name}/{doc.category}"
    if body.name:
        doc.name = clean(body.name)
    if body.category:
        doc.category = clean(body.category, 50)
    db.commit()
    audit.log(db, user.id, "edit", doc.id, "allowed", f"{old} -> {doc.name}/{doc.category}")
    return {"ok": True}


# ---------- delete (soft) ----------
@router.delete("/{doc_id}")
def delete(doc_id: str, user: models.User = Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    doc = get_document_or_404(db, user, doc_id, "delete")
    doc.deleted_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, user.id, "delete", doc.id, "allowed", doc.name)
    return {"ok": True}


# ---------- grants ----------
class GrantIn(BaseModel):
    email: str
    level: Literal["read", "edit"]
    hours: int | None = Field(default=None, ge=1, le=24 * 90)   # None = until revoked


@router.post("/{doc_id}/grants", status_code=201)
def grant(doc_id: str, body: GrantIn, user: models.User = Depends(get_current_user),
          db: DbSession = Depends(get_db)):
    doc = get_document_or_404(db, user, doc_id, "share")
    target = db.scalar(select(models.User).where(models.User.email == body.email.lower()))
    if target is None or not target.is_active:
        raise HTTPException(404, "User not found")
    if target.id == user.id:
        raise HTTPException(400, "You already own this document")

    now = datetime.now(timezone.utc)
    for old in db.scalars(select(models.Grant).where(
            models.Grant.document_id == doc.id, models.Grant.user_id == target.id,
            models.Grant.revoked_at.is_(None))):
        old.revoked_at = now  # replace, never stack grants

    expires = now + timedelta(hours=body.hours) if body.hours else None
    db.add(models.Grant(document_id=doc.id, user_id=target.id, level=body.level,
                        granted_by=user.id, expires_at=expires))
    db.commit()
    audit.log(db, user.id, "share", doc.id, "allowed",
              f"{target.email}:{body.level}:{'until ' + expires.isoformat() if expires else 'no expiry'}")
    return {"ok": True}


@router.get("/{doc_id}/grants")
def list_grants(doc_id: str, user: models.User = Depends(get_current_user),
                db: DbSession = Depends(get_db)):
    doc = get_document_or_404(db, user, doc_id, "share")
    rows = db.execute(
        select(models.Grant, models.User.email)
        .join(models.User, models.User.id == models.Grant.user_id)
        .where(models.Grant.document_id == doc.id, models.Grant.revoked_at.is_(None))
    ).all()
    return [{"user_id": g.user_id, "email": email, "level": g.level,
             "expires_at": g.expires_at.isoformat() if g.expires_at else None}
            for g, email in rows]


@router.delete("/{doc_id}/grants/{target_id}")
def revoke(doc_id: str, target_id: str, user: models.User = Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    doc = get_document_or_404(db, user, doc_id, "share")
    now = datetime.now(timezone.utc)
    count = 0
    for g in db.scalars(select(models.Grant).where(
            models.Grant.document_id == doc.id, models.Grant.user_id == target_id,
            models.Grant.revoked_at.is_(None))):
        g.revoked_at = now
        count += 1
    db.commit()
    audit.log(db, user.id, "revoke", doc.id, "allowed", f"user {target_id}, {count} grant(s)")
    return {"revoked": count}