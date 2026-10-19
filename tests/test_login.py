from sqlalchemy import select

import models
from database import SessionLocal


def bad(client):
    return client.post("/auth/login", json={"email": "owner@t.test", "password": "wrong"})


def test_failed_login_is_audited(client):
    assert bad(client).status_code == 401
    with SessionLocal() as db:
        rows = db.scalars(select(models.AuditLog).where(
            models.AuditLog.action == "login", models.AuditLog.outcome == "denied")).all()
    assert len(rows) == 1


def test_account_locks_after_repeated_failures(client):
    for _ in range(5):
        bad(client)
    r = client.post("/auth/login", json={"email": "owner@t.test", "password": "Owner-pass-1"})
    assert r.status_code == 429
    