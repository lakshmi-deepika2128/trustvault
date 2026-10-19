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
def test_unknown_email_still_runs_the_password_hash(client, monkeypatch):
    import main
    calls = []
    real = main.verify_password

    def spy(stored_hash, password):
        calls.append(1)
        return real(stored_hash, password)

    monkeypatch.setattr(main, "verify_password", spy)
    r = client.post("/auth/login", json={"email": "nobody@t.test", "password": "x"})
    assert r.status_code == 401
    assert calls == [1]   # the slow check ran even though the user does not exist    