from datetime import datetime, timezone, timedelta
from sqlalchemy import select, func
import audit
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession
import documents
import models
from auth import (verify_password, create_session, get_current_user,
                  bearer, _hash_token)
from database import engine, Base, get_db

Base.metadata.create_all(engine)

app = FastAPI(title="TrustVault")
app.include_router(documents.router)
class LoginIn(BaseModel):
    email: str
    password: str


@app.get("/")
def home():
    return {"status": "TrustVault is running"}
MAX_FAILS = 5
WINDOW = timedelta(minutes=15)


@app.post("/auth/login")
def login(body: LoginIn, db: DbSession = Depends(get_db)):
    email = body.email.lower()[:200]
    marker = f"email={email}"
    since = datetime.now(timezone.utc) - WINDOW
    fails = db.scalar(
        select(func.count()).select_from(models.AuditLog).where(
            models.AuditLog.action == "login",
            models.AuditLog.outcome == "denied",
            models.AuditLog.detail == marker,
            models.AuditLog.ts >= since,
        )
    )
    if fails >= MAX_FAILS:
        audit.log(db, None, "login", None, "denied", marker)
        raise HTTPException(429, "Too many failed attempts. Try again later.")

    user = db.scalar(select(models.User).where(models.User.email == email))
    if user is None or not user.is_active or not verify_password(user.password_hash, body.password):
        audit.log(db, user.id if user else None, "login", None, "denied", marker)
        raise HTTPException(401, "Invalid email or password")
    audit.log(db, user.id, "login", None, "allowed", marker)
    return {"token": create_session(db, user), "role": user.role}

@app.post("/auth/login")
def login(body: LoginIn, db: DbSession = Depends(get_db)):
    user = db.scalar(select(models.User).where(models.User.email == body.email.lower()))
    if user is None or not user.is_active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"token": create_session(db, user), "role": user.role}


@app.post("/auth/logout")
def logout(creds=Depends(bearer), user=Depends(get_current_user),
           db: DbSession = Depends(get_db)):
    session = db.get(models.Session, _hash_token(creds.credentials))
    session.revoked_at= datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}