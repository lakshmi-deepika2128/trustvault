from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

import audit
import models

LEVEL = {"read": 1, "edit": 2}


def can(db: DbSession, user: models.User, doc: models.Document, action: str) -> bool:
    """action is one of: read, edit, delete, share"""
    if not user.is_active or doc.deleted_at is not None:
        return False

    # The owner can do everything with their own document
    if doc.owner_id == user.id:
        return True

    # Only the owner can delete or share. Admins get no access to contents.
    if action in ("delete", "share"):
        return False
    if action not in LEVEL:
        return False

    grants = db.scalars(
        select(models.Grant).where(
            models.Grant.document_id == doc.id,
            models.Grant.user_id == user.id,
            models.Grant.revoked_at.is_(None),
        )
    )
    return any(LEVEL[g.level] >= LEVEL[action] for g in grants)


def get_document_or_404(db: DbSession, user: models.User, doc_id: str,
                        action: str, audit_action: str | None = None):
    doc = db.get(models.Document, doc_id)
    if doc is None or not can(db, user, doc, action):
        audit.log(db, user.id, audit_action or action, doc_id, "denied")
        # Same answer whether it doesn't exist or you aren't allowed
        raise HTTPException(status_code=404, detail="Not found")
    return doc
   