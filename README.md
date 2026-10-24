# TrustVault
Secure document sharing with a tamper-evident audit trail.

## Live URL
https://trustvault-o2m4.onrender.com
# TrustVault
Secure document sharing with per-document grants, immediate revocation and a
hash-chained audit trail. Python, FastAPI, PostgreSQL.

Live: https://trustvault-o2m4.onrender.com   (API docs at /docs)
The first request can take about a minute while the free server wakes up.

## Demo accounts
| Role   | Email                  | Password        |
|--------|------------------------|-----------------|
| admin  | admin@trustvault.test  | Admin#Demo2026  |
| owner  | owner@trustvault.test  | Owner#Demo2026  |
| viewer | viewer@trustvault.test | Viewer#Demo2026 |
An account locks for 15 minutes after 5 failed logins.

## Run locally
    git clone https://github.com/lakshmi-deepika2128/trustvault.git
    cd trustvault
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    python seed.py
    uvicorn main:app --reload      (open http://127.0.0.1:8000/docs)
    python -m pytest tests

## Roles
- owner: uploads documents; grants and revokes read/edit (optionally for a number of hours); deletes own documents.
- viewer: sees only documents granted to them.
- admin: sees activity, permission changes, alerts and the chain check. Cannot read file contents.

## API: who may call what
| Endpoint | Who |
|---|---|
| POST /auth/login | anyone |
| POST /auth/logout, GET /me | any logged-in user |
| POST /documents | owner role only |
| GET /documents | logged in; returns only own or granted documents |
| GET /documents/{id}/download | the owner, or a holder of a read/edit grant |
| PATCH /documents/{id} | the owner, or a holder of an edit grant |
| DELETE /documents/{id} | the owner only |
| POST/GET /documents/{id}/grants, DELETE /documents/{id}/grants/{user} | the owner only |
| GET /admin/activity, /permission-changes, /documents, /alerts, /verify-chain | admin only |

## Permission model
Per-document grants, no inheritance. can() in permissions.py is the single decision
point and reads the database on every request, so revoking works at once.

## Not built / known gaps
- No frontend; the API is used through /docs.
- No AI suggestion feature.
- Uploaded files are on the server disk and are lost when Render redeploys.
- The audit chain can be rebuilt by someone with full database write access (see THREATS.md).
- No outside sharing, versions, retention or recovery of deleted files.