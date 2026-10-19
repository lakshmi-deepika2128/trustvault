import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

import models
import threading
from sqlalchemy.exc import IntegrityError

GENESIS = "0" * 64
_lock = threading.Lock()

def _norm(ts: datetime) -> str:
    # SQLite returns naive datetimes, so normalise to naive UTC before hashing
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    return ts.isoformat()


def _compute(prev_hash, ts, actor_id, action, document_id, outcome, detail) -> str:
    payload = json.dumps(
        [prev_hash, _norm(ts), actor_id, action, document_id, outcome, detail],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def log(db: DbSession, actor_id, action, document_id, outcome, detail=""):
    for _ in range(5):
        with _lock:
            last = db.scalar(select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(1))
            prev = last.hash if last else GENESIS
            ts = datetime.now(timezone.utc)
            row = models.AuditLog(
                ts=ts, actor_id=actor_id, action=action, document_id=document_id,
                outcome=outcome, detail=detail, prev_hash=prev,
                hash=_compute(prev, ts, actor_id, action, document_id, outcome, detail),
            )
            db.add(row)
            try:
                db.commit()
                return row
            except IntegrityError:
                db.rollback()  # someone else extended the chain first; retry
    raise RuntimeError("audit chain contention")


def verify_chain(db: DbSession):
    """Returns (True, None) if intact, else (False, id of first broken row)."""
    prev = GENESIS
    for row in db.scalars(select(models.AuditLog).order_by(models.AuditLog.id)):
        expected = _compute(prev, row.ts, row.actor_id, row.action,
                            row.document_id, row.outcome, row.detail)
        if row.prev_hash != prev or row.hash != expected:
            return False, row.id
        prev = row.hash
    return True, None