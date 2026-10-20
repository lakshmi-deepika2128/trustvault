from conftest import login, upload


def test_only_admin_can_see_admin_routes(client):
    for path in ("/admin/activity", "/admin/permission-changes", "/admin/documents",
                 "/admin/alerts", "/admin/verify-chain"):
        assert client.get(path).status_code == 401
        for who in ("owner@t.test", "viewer@t.test"):
            assert client.get(path, headers=login(client, who)).status_code == 403, (path, who)
        assert client.get(path, headers=login(client, "admin@t.test")).status_code == 200, path


def test_admin_sees_refused_attempts(client):
    doc = upload(client, login(client, "owner@t.test"))
    client.get(f"/documents/{doc}/download", headers=login(client, "viewer@t.test"))
    rows = client.get("/admin/activity?outcome=denied&action=download",
                      headers=login(client, "admin@t.test")).json()
    assert len(rows) == 1 and rows[0]["document_id"] == doc


def test_admin_sees_permission_changes(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants",
                json={"email": "viewer@t.test", "level": "read"}, headers=owner)
    target = client.get(f"/documents/{doc}/grants", headers=owner).json()[0]["user_id"]
    client.delete(f"/documents/{doc}/grants/{target}", headers=owner)
    rows = client.get("/admin/permission-changes", headers=login(client, "admin@t.test")).json()
    assert {r["action"] for r in rows} == {"share", "revoke"}


def test_admin_lists_documents_but_cannot_read_them(client):
    doc = upload(client, login(client, "owner@t.test"))
    admin = login(client, "admin@t.test")
    listed = client.get("/admin/documents", headers=admin).json()
    assert listed[0]["id"] == doc and "stored_name" not in listed[0]
    assert client.get(f"/documents/{doc}/download", headers=admin).status_code == 404


def test_alert_for_repeated_refusals(client):
    doc = upload(client, login(client, "owner@t.test"))
    v = login(client, "viewer@t.test")
    for _ in range(3):
        client.get(f"/documents/{doc}/download", headers=v)
    out = client.get("/admin/alerts", headers=login(client, "admin@t.test")).json()
    assert len(out["users_with_3_or_more_refused_requests"]) == 1