import os
import tempfile
from pathlib import Path

# Point the app at a throwaway database and upload folder BEFORE importing it
_tmp = Path(tempfile.mkdtemp())
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["UPLOAD_DIR"] = str(_tmp / "uploads")

import pytest
from fastapi.testclient import TestClient

import models
from auth import hash_password
from database import Base, SessionLocal, engine
from main import app

PASSWORDS = {
    "admin@t.test": ("admin", "Admin-pass-1"),
    "owner@t.test": ("owner", "Owner-pass-1"),
    "owner2@t.test": ("owner", "Owner-pass-2"),
    "viewer@t.test": ("viewer", "Viewer-pass-1"),
    "viewer2@t.test": ("viewer", "Viewer-pass-2"),
}


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        for email, (role, pw) in PASSWORDS.items():
            db.add(models.User(email=email, password_hash=hash_password(pw), role=role))
        db.commit()
    yield


@pytest.fixture
def client():
    return TestClient(app)


def login(client, email):
    pw = PASSWORDS[email][1]
    r = client.post("/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def upload(client, headers, name="secret.txt", data=b"top secret salary letter"):
    r = client.post("/documents", files={"file": (name, data, "text/plain")}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]