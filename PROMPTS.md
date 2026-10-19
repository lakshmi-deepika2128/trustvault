# Prompts log
# PROMPTS.md

How I used AI (Claude) on this project, with the mistakes I found.
I work alone. The AI wrote code; I ran it, tested it and have to explain it.

## 19 Oct 2026: Project setup and password hashing
**Asked:** how to set up a FastAPI project and hash passwords.
**Produced:** a library list that included passlib for hashing.
**Wrong:** passlib is unmaintained and can break on newer Python.
The AI corrected this itself when I asked for the next step. I did not catch it.
**Did instead:** used argon2-cffi directly. Commit: <link>

## 19 Oct 2026: Deployment on Render
**Asked:** how to deploy to Render.
**Produced:** a runtime.txt file to set the Python version.
**Wrong:** that is a Heroku mechanism; Render uses the PYTHON_VERSION env variable.
The AI corrected this itself afterwards.
**Did instead:** set PYTHON_VERSION=3.13.11 on Render. Commit: <link>

## 19 Oct 2026: Audit log and can()   (AUTHORISATION / AUDIT)
**Asked:** design a hash-chained audit log and a single permission function.
**Produced:** audit.py and permissions.py.
**Wrong:** (write only what YOU find after reading it)
**Did instead:** (fix, with commit link)

## Context I reuse
AI_RULES.md
## 20 Oct 2026: Failed logins were not in the audit trail  (AUDIT TRAIL)
**Asked:** the AI to build login with sessions.
**Produced:** a /auth/login route that checked the password and returned a
token. It wrote nothing to the audit log when a login failed.
**Wrong:** the challenge says refused attempts must be recorded. With this
code, someone guessing passwords would leave no trace. Login also had no
limit on attempts.
**How it came to light:** the AI listed it as a gap in its own code, and I
then wrote a test (test_failed_login_is_audited) to prove the fix.
**Did instead:** log every failed and successful login to the audit table,
and return 429 after 5 failures for the same email in 15 minutes.
Commit: https://github.com/lakshmi-deepika2128/trustvault/commit/<hash>
**Cost I accepted:** an attacker can lock a real user out on purpose.
## 20 Oct 2026: Audit chain race condition  (AUDIT TRAIL)
**Asked:** the AI for a tamper-evident audit log using a hash chain.
**Produced:** audit.log(), which reads the last row's hash, then writes a new
row pointing at it.
**Wrong:** two requests at the same moment can both read the same last row,
so two rows claim the same previous row. The chain forks and the verifier
then reports tampering that never happened.
**How it came to light:** the AI pointed out the gap when I asked it to
review the code. I did not find it myself.
**Did instead:** made prev_hash UNIQUE in the database, added a lock inside
the server process, and retry if the database rejects a duplicate.
Commit: https://github.com/lakshmi-deepika2128/trustvault/commit/<hash>