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
## 20 Oct 2026: Refused downloads logged under the wrong name (AUDIT TRAIL)
**Asked:** a permission check that records refused attempts.
**Produced:** refusals logged as "read" while successful downloads were "download".
**Wrong:** one action had two names, so searching the audit trail for refused
downloads would find nothing.
**Found by:** my own test, test_refused_attempts_are_audited, failed.
**Did instead:** added an audit_action parameter to get_document_or_404. Commit <hash>.

## 21 Oct 2026: Failed logins and a forkable audit chain (AUDIT TRAIL)
**Asked:** login with sessions, and a hash-chained audit log.
**Produced:** a login that recorded nothing on failure and had no attempt limit,
and a log() that could fork the chain if two requests wrote at once.
**Wrong:** the challenge says refused attempts must be recorded, and a forked
chain makes the verifier report tampering that never happened.
**Found by:** the AI pointed both out when I asked it to review its own code; I
wrote the tests and applied the fixes. I did not find them myself.
**Did instead:** log every login result, lock an account for 15 minutes after 5
failures, make prev_hash UNIQUE, add a lock and a retry. Commit <hash>.

## 22 Oct 2026: Login timing leak (ACCESS CONTROL)
**Asked:** safer login.
**Produced:** a check that skipped the password hash when the email did not exist,
so unknown emails answered faster.
**Found by:** my test, test_unknown_email_still_runs_the_password_hash, failed
with "assert [] == [1]". The cause was that the old line was still in main.py.
**Did instead:** always run the hash, using a dummy hash for unknown emails.
Commit <hash>.

## 23 Oct 2026: Admin routes returned 404
**Produced:** admin.py, but the router was not registered in main.py.
**Found by:** 5 failing tests (404 instead of 401).
**Did instead:** registered the router. Commit <hash>.

## 24 Oct 2026: An instruction that deleted a function
**Asked:** to add expiring grants.
**Produced:** an instruction to replace code "to the last line" of permissions.py,
which also deleted get_document_or_404.
**Found by:** the red underline on the import in documents.py.
**Did instead:** replaced the whole file with a complete version. Commit <hash>.

## 25 Oct 2026: requirements.txt saved in the wrong encoding
**Produced:** the command pip freeze > requirements.txt, which in PowerShell
writes UTF-16.
**Found by:** findstr printed "input file is in Unicode format".
**Did instead:** rewrote it with Set-Content -Encoding ascii. Commit <hash>.






<!-- ## 20 Oct 2026: Refused downloads logged under the wrong name (AUDIT TRAIL)
**Asked:** a permission check that records refused attempts.
**Produced:** refusals logged as "read" while successful downloads were "download".
**Wrong:** one action had two names, so searching the audit trail for refused
downloads would find nothing.
**Found by:** my own test, test_refused_attempts_are_audited, failed.
**Did instead:** added an audit_action parameter to get_document_or_404. Commit <hash>.

## 20 Oct 2026: Failed logins and a forkable audit chain (AUDIT TRAIL)
**Asked:** login with sessions, and a hash-chained audit log.
**Produced:** a login that recorded nothing on failure and had no attempt limit,
and a log() that could fork the chain if two requests wrote at once.
**Wrong:** the challenge says refused attempts must be recorded, and a forked
chain makes the verifier report tampering that never happened.
**Found by:** the AI pointed both out when I asked it to review its own code; I
wrote the tests and applied the fixes. I did not find them myself.
**Did instead:** log every login result, lock an account for 15 minutes after 5
failures, make prev_hash UNIQUE, add a lock and a retry. Commit <hash>.

## 20 Oct 2026: Login timing leak (ACCESS CONTROL)
**Asked:** safer login.
**Produced:** a check that skipped the password hash when the email did not exist,
so unknown emails answered faster.
**Found by:** my test, test_unknown_email_still_runs_the_password_hash, failed
with "assert [] == [1]". The cause was that the old line was still in main.py.
**Did instead:** always run the hash, using a dummy hash for unknown emails.
Commit <hash>.

## 20 Oct 2026: Admin routes returned 404
**Produced:** admin.py, but the router was not registered in main.py.
**Found by:** 5 failing tests (404 instead of 401).
**Did instead:** registered the router. Commit <hash>.

## 20 Oct 2026: An instruction that deleted a function
**Asked:** to add expiring grants.
**Produced:** an instruction to replace code "to the last line" of permissions.py,
which also deleted get_document_or_404.
**Found by:** the red underline on the import in documents.py.
**Did instead:** replaced the whole file with a complete version. Commit <hash>.

## 20 Oct 2026: requirements.txt saved in the wrong encoding
**Produced:** the command pip freeze > requirements.txt, which in PowerShell
writes UTF-16.
**Found by:** findstr printed "input file is in Unicode format".
**Did instead:** rewrote it with Set-Content -Encoding ascii. Commit <hash>. -->