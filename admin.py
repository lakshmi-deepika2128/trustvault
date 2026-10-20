from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

import audit
import models
from auth import get_current_user
from database import get_db

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(user: models.User = Depends(get_current_user),
                  db: DbSession = Depends(get_db)) -> models.User:
    if user.role != "admin":
        audit.log(db, user.id, "admin_access", None, "denied", "not an admin")
        raise HTTPException(403, "Admins only")
    return user


def _row(r: models.AuditLog) -> dict:
    return {"id": r.id, "time": r.ts.isoformat(), "actor_id": r.actor_id,
            "action": r.action, "document_id": r.document_id,
            "outcome": r.outcome, "detail": r.detail}


@router.get("/activity")
def activity(action: str | None = None, outcome: str | None = None,
             document_id: str | None = None, actor_id: str | None = None,
             limit: int = Query(100, ge=1, le=500),
             admin: models.User = Depends(require_admin),
             db: DbSession = Depends(get_db)):
    q = select(models.AuditLog)
    if action:
        q = q.where(models.AuditLog.action == action)
    if outcome:
        q = q.where(models.AuditLog.outcome == outcome)
    if document_id:
        q = q.where(models.AuditLog.document_id == document_id)
    if actor_id:
        q = q.where(models.AuditLog.actor_id == actor_id)
    rows = db.scalars(q.order_by(models.AuditLog.id.desc()).limit(limit)).all()
    return [_row(r) for r in rows]


@router.get("/permission-changes")
def permission_changes(limit: int = Query(100, ge=1, le=500),
                       admin: models.User = Depends(require_admin),
                       db: DbSession = Depends(get_db)):
    q = (select(models.AuditLog)
         .where(models.AuditLog.action.in_(["share", "revoke"]))
         .order_by(models.AuditLog.id.desc()).limit(limit))
    return [_row(r) for r in db.scalars(q)]


@router.get("/documents")
def all_documents(admin: models.User = Depends(require_admin),
                  db: DbSession = Depends(get_db)):
    """Metadata only. There is deliberately no admin route to file contents."""
    rows = db.execute(
        select(models.Document, models.User.email)
        .join(models.User, models.User.id == models.Document.owner_id)
        .order_by(models.Document.created_at.desc())
    ).all()
    return [{"id": d.id, "name": d.name, "owner": email, "category": d.category,
             "size": d.size, "created_at": d.created_at.isoformat(),
             "deleted": d.deleted_at is not None} for d, email in rows]


@router.get("/alerts")
def alerts(admin: models.User = Depends(require_admin),
           db: DbSession = Depends(get_db)):
    """What I decided is worth noticing: repeated refusals and failed logins."""
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    refused = db.execute(
        select(models.AuditLog.actor_id, func.count())
        .where(models.AuditLog.outcome == "denied",
               models.AuditLog.action != "login",
               models.AuditLog.actor_id.is_not(None),
               models.AuditLog.ts >= since)
        .group_by(models.AuditLog.actor_id)
        .having(func.count() >= 3)
    ).all()
    logins = db.execute(
        select(models.AuditLog.detail, func.count())
        .where(models.AuditLog.action == "login",
               models.AuditLog.outcome == "denied",
               models.AuditLog.ts >= since)
        .group_by(models.AuditLog.detail)
        .having(func.count() >= 3)
    ).all()
    return {
        "window_hours": 24,
        "users_with_3_or_more_refused_requests": [
            {"actor_id": a, "count": c} for a, c in refused],
        "accounts_with_3_or_more_failed_logins": [
            {"account": d, "count": c} for d, c in logins],
    }


@router.get("/verify-chain")
def verify(admin: models.User = Depends(require_admin),
           db: DbSession = Depends(get_db)):
    ok, broken_id = audit.verify_chain(db)
    return {"intact": ok, "first_broken_row": broken_id}