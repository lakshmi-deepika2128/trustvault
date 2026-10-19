from sqlalchemy import select, update

import audit
import models
from database import SessionLocal
from conftest import login, upload


# ---------- THREAT: a stranger reaching someone else's document ----------

def test_stranger_cannot_download(client):
    doc = upload(client, login(client, "owner@t.test"))
    for who in ("viewer@t.test", "owner2@t.test", "admin@t.test"):
        r = client.get(f"/documents/{doc}/download", headers=login(client, who))
        assert r.status_code == 404, who


def test_stranger_cannot_edit_delete_or_share(client):
    doc = upload(client, login(client, "owner@t.test"))
    other = login(client, "owner2@t.test")
    assert client.patch(f"/documents/{doc}", json={"name": "x.txt"}, headers=other).status_code == 404
    assert client.delete(f"/documents/{doc}", headers=other).status_code == 404
    assert client.get(f"/documents/{doc}/grants", headers=other).status_code == 404
    r = client.post(f"/documents/{doc}/grants",
                    json={"email": "owner2@t.test", "level": "edit"}, headers=other)
    assert r.status_code == 404


def test_stranger_does_not_see_document_in_list(client):
    upload(client, login(client, "owner@t.test"))
    r = client.get("/documents", headers=login(client, "viewer@t.test"))
    assert r.status_code == 200 and r.json() == []


def test_unauthenticated_is_rejected(client):
    doc = upload(client, login(client, "owner@t.test"))
    assert client.get(f"/documents/{doc}/download").status_code == 401
    assert client.get("/documents").status_code == 401


def test_missing_and_forbidden_look_identical(client):
    doc = upload(client, login(client, "owner@t.test"))
    h = login(client, "viewer@t.test")
    a = client.get(f"/documents/{doc}/download", headers=h)
    b = client.get("/documents/does-not-exist/download", headers=h)
    assert a.status_code == b.status_code == 404 and a.json() == b.json()


# ---------- THREAT: grants are narrower than they look ----------

def test_read_grant_cannot_edit_delete_or_share(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants",
                json={"email": "viewer@t.test", "level": "read"}, headers=owner)
    v = login(client, "viewer@t.test")
    assert client.get(f"/documents/{doc}/download", headers=v).status_code == 200
    assert client.patch(f"/documents/{doc}", json={"name": "x.txt"}, headers=v).status_code == 404
    assert client.delete(f"/documents/{doc}", headers=v).status_code == 404
    r = client.post(f"/documents/{doc}/grants",
                    json={"email": "viewer2@t.test", "level": "read"}, headers=v)
    assert r.status_code == 404


def test_edit_grant_allows_edit_but_not_delete(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants",
                json={"email": "viewer@t.test", "level": "edit"}, headers=owner)
    v = login(client, "viewer@t.test")
    assert client.patch(f"/documents/{doc}", json={"name": "ok.txt"}, headers=v).status_code == 200
    assert client.delete(f"/documents/{doc}", headers=v).status_code == 404


def test_grant_to_one_person_does_not_help_another(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants",
                json={"email": "viewer@t.test", "level": "read"}, headers=owner)
    r = client.get(f"/documents/{doc}/download", headers=login(client, "viewer2@t.test"))
    assert r.status_code == 404


# ---------- THREAT: revocation must be immediate ----------

def test_revoke_takes_effect_immediately_with_existing_token(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants",
                json={"email": "viewer@t.test", "level": "read"}, headers=owner)
    v = login(client, "viewer@t.test")             # token issued BEFORE revocation
    assert client.get(f"/documents/{doc}/download", headers=v).status_code == 200
    grants = client.get(f"/documents/{doc}/grants", headers=owner).json()
    client.delete(f"/documents/{doc}/grants/{grants[0]['user_id']}", headers=owner)
    assert client.get(f"/documents/{doc}/download", headers=v).status_code == 404


def test_logout_kills_the_token(client):
    h = login(client, "owner@t.test")
    assert client.get("/me", headers=h).status_code == 200
    client.post("/auth/logout", headers=h)
    assert client.get("/me", headers=h).status_code == 401


def test_deactivated_user_loses_access_at_once(client):
    h = login(client, "owner@t.test")
    with SessionLocal() as db:
        db.execute(update(models.User).where(models.User.email == "owner@t.test")
                   .values(is_active=False))
        db.commit()
    assert client.get("/me", headers=h).status_code == 401


def test_deleted_document_is_unreachable_even_for_owner(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.delete(f"/documents/{doc}", headers=owner)
    assert client.get(f"/documents/{doc}/download", headers=owner).status_code == 404


# ---------- THREAT: audit trail ----------

def test_refused_attempts_are_audited(client):
    doc = upload(client, login(client, "owner@t.test"))
    client.get(f"/documents/{doc}/download", headers=login(client, "viewer@t.test"))
    with SessionLocal() as db:
        rows = db.scalars(select(models.AuditLog).where(
            models.AuditLog.action == "download", models.AuditLog.outcome == "denied")).all()
    assert len(rows) == 1 and rows[0].document_id == doc


def test_successful_actions_are_audited(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.get(f"/documents/{doc}/download", headers=owner)
    with SessionLocal() as db:
        actions = {r.action for r in db.scalars(select(models.AuditLog))}
    assert {"upload", "download"} <= actions


def test_audit_chain_detects_tampering(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.get(f"/documents/{doc}/download", headers=owner)
    with SessionLocal() as db:
        assert audit.verify_chain(db) == (True, None)
        first = db.scalars(select(models.AuditLog).order_by(models.AuditLog.id)).first()
        first.detail = "edited by an attacker"
        db.commit()
        ok, broken_id = audit.verify_chain(db)
    assert ok is False and broken_id == first.id


# ---------- THREAT: uploads ----------

def test_upload_rejects_disguised_file(client):
    h = login(client, "owner@t.test")
    r = client.post("/documents",
                    files={"file": ("invoice.pdf", b"MZ\x90\x00 fake exe bytes", "application/pdf")},
                    headers=h)
    assert r.status_code == 415


def test_viewer_cannot_upload(client):
    r = client.post("/documents",
                    files={"file": ("a.txt", b"hello", "text/plain")},
                    headers=login(client, "viewer@t.test"))
    assert r.status_code == 403


def test_path_traversal_in_filename_is_neutralised(client):
    h = login(client, "owner@t.test")
    doc = upload(client, h, name="../../etc/passwd.txt")
    docs = client.get("/documents", headers=h).json()
    assert docs[0]["name"] == "passwd.txt"
    assert client.get(f"/documents/{doc}/download", headers=h).status_code == 200