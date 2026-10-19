# Threats
# THREATS.md

Ways I believe TrustVault could be broken, what I did, and what I accepted.
Status: CLOSED (defended and tested), PARTIAL, or ACCEPTED (known weakness).

## A. Reaching a document you were not given

**A1. Stranger downloads, edits, deletes or shares someone else's document**
- Attack: call the endpoint directly with another user's token, skipping the UI.
- Defence: every document route calls get_document_or_404(), which calls can()
  against the database on each request. No check lives in the front end.
- Tests: test_stranger_cannot_download, test_stranger_cannot_edit_delete_or_share
- Status: CLOSED

**A2. Guessing document ids (IDOR)**
- Attack: try other ids to find files.
- Defence: ids are random UUIDs, and a missing document and a forbidden one both
  return the same 404, so existence is not revealed.
- Test: test_missing_and_forbidden_look_identical
- Status: CLOSED

**A3. Listing or search leaking other people's documents**
- Defence: the list query only returns documents the user owns or holds an active grant on.
- Test: test_stranger_does_not_see_document_in_list
- Status: CLOSED

**A4. A read grant used to edit, delete or share**
- Defence: can() maps action to level; only the owner may delete or share.
- Tests: test_read_grant_cannot_edit_delete_or_share, test_edit_grant_allows_edit_but_not_delete
- Status: CLOSED

**A5. Admin reading document contents**
- Defence: admins get no special path to file contents. can() gives no role bypass.
- Test: test_stranger_cannot_download includes the admin account.
- Status: CLOSED

**A6. Path traversal through the file name**
- Attack: upload a file named ../../etc/passwd.
- Defence: the name is cleaned, and the file is stored under a random name that
  comes from the server, never from user input.
- Test: test_path_traversal_in_filename_is_neutralised
- Status: CLOSED

## B. Taking access away

**B1. Revoked user keeps reading with a token issued earlier**
- Defence: grants are not stored in the token. They are read from the database on every request.
- Test: test_revoke_takes_effect_immediately_with_existing_token
- Status: CLOSED

**B2. Token still works after logout or deactivation**
- Defence: sessions live in the database and are checked on every request.
- Tests: test_logout_kills_the_token, test_deactivated_user_loses_access_at_once
- Status: CLOSED

**B3. Deleted document still reachable**
- Defence: can() returns false when deleted_at is set.
- Test: test_deleted_document_is_unreachable_even_for_owner
- Status: CLOSED

**B4. A file already downloaded cannot be taken back**
- Revoking stops future access only. Nothing can recall a copy someone already saved.
- Status: ACCEPTED. This is inherent to any file sharing system.

## C. The audit trail

**C1. Refused attempts not recorded**
- Defence: refused document access and failed logins are written to the log.
- Tests: test_refused_attempts_are_audited, test_failed_login_is_audited
- Status: CLOSED

**C2. Editing an old audit row**
- Defence: each row's hash includes the previous row's hash, and verify_chain() detects a change.
- Test: test_audit_chain_detects_tampering
- Status: PARTIAL. See C3.

**C3. Someone with database write access rebuilds the whole chain**
- They could recompute every hash after an edit. The chain detects careless
  tampering, not a determined attacker with full database control.
- Not done: restrict the app's database user to INSERT only, and keep the latest
  hash somewhere the database admin cannot change.
- Status: ACCEPTED for now.

**C4. Two requests forking the chain**
- Defence: prev_hash is UNIQUE, there is a lock, and writes retry on conflict.
- Status: CLOSED. No automated test for the multi-process case.

## D. Accounts and sessions

**D1. Password guessing**
- Defence: passwords are hashed with argon2, and an account locks for 15 minutes
  after 5 failures.
- Test: test_account_locks_after_repeated_failures
- Status: CLOSED

**D2. The lockout itself as an attack**
- Someone can lock a real user out by failing on purpose, and the limit is per
  email, not per IP.
- Status: ACCEPTED. I chose protecting passwords over availability.

**D3. Telling whether an email exists**
- Login returns the same message for a wrong email and a wrong password, and
  always runs the argon2 check (against a dummy hash if the user does not exist),
  so response time does not reveal which emails are registered.
- Test: test_unknown_email_still_runs_the_password_hash
- Status: CLOSED (checked by a test that the hash runs, not by measuring time)

**D4. A user making themselves admin**
- There is no endpoint that sets a role, and role is never read from the request.
- Status: CLOSED by absence. No test yet.

**D5. A stolen token**
- Tokens are random, stored only as hashes, and expire after 8 hours. Anyone who
  steals a live token can use it until it expires or is revoked.
- Status: ACCEPTED

## E. Uploads

**E1. A disguised file (exe renamed to .pdf)**
- Defence: type is decided from the file's content, and must match the extension.
- Test: test_upload_rejects_disguised_file
- Status: CLOSED for the four allowed types

**E2. Oversized uploads**
- Defence: 5 MB limit. Status: CLOSED. No test yet.

**E3. A viewer uploading**
- Defence: only the owner role can upload.
- Test: test_viewer_cannot_upload
- Status: CLOSED

## F. Not done yet (honest list)
- No virus scanning of uploads.
- Uploaded files are on the server disk. On Render's free plan they are lost on redeploy.
- No rate limit except on login.
- No sharing with people outside the company, no versions, no recovery of deleted files.
- Security headers and CORS settings are not reviewed yet.