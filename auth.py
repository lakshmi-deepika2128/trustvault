import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session as DbSession

import models
from database import get_db

ph = PasswordHasher()
bearer = HTTPBearer(auto_error=False)
SESSION_HOURS = 8


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except Exception:
        return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    # SQLite returns naive datetimes; treat them as UTC
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_session(db: DbSession, user: models.User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(models.Session(
        token_hash=_hash_token(token),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    return token


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: DbSession = Depends(get_db),
) -> models.User:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = db.get(models.Session, _hash_token(creds.credentials))
    if (
        session is None
        or session.revoked_at is not None
        or _aware(session.expires_at) < datetime.now(timezone.utc)
    ):
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = db.get(models.User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user