from datetime import datetime, timedelta, timezone

from sqlalchemy import update

import models
from database import SessionLocal
from conftest import login, upload


def test_expired_grant_stops_working(client):
    owner = login(client, "owner@t.test")
    doc = upload(client, owner)

    # Owner shares the document for 1 hour
    r = client.post(f"/documents/{doc}/grants",
                    json={"email": "viewer@t.test", "level": "read", "hours": 1},
                    headers=owner)
    assert r.status_code == 201

    # While the grant is valid, the viewer can download and see it in the list
    viewer = login(client, "viewer@t.test")
    assert client.get(f"/documents/{doc}/download", headers=viewer).status_code == 200
    assert len(client.get("/documents", headers=viewer).json()) == 1

    # Move the expiry time into the past, as if the hour had gone by
    with SessionLocal() as db:
        db.execute(update(models.Grant).values(
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)))
        db.commit()

    # Now the same token no longer works for this document
    assert client.get(f"/documents/{doc}/download", headers=viewer).status_code == 404
    assert client.get("/documents", headers=viewer).json() == []