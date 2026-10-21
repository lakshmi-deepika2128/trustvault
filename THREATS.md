# THREATS.md

Ways I believe TrustVault could be broken, what I did, and what I accepted.
Status: CLOSED (defended and tested), PARTIAL, or ACCEPTED (known weakness).

## A. Reaching a document you were not given

**A1. A stranger downloads, edits, deletes or shares someone else's document**
- Attack: call the endpoint directly with another user's token, skipping any screen.
- Defence: every document route calls get_document_or_404(), which calls can()
  against the database on each request. Nothing relies on a hidden button.
- Tests: test_stranger_cannot_download, test_stranger_cannot_edit_delete_or_share
- Status: CLOSED

**A2. Guessing document ids**
- Defence: ids are random UUIDs. A missing document and a forbidden one both
  return the same 404, so existence is not revealed.
- Test: test_missing_and_forbidden_look_identical
- Status: CLOSED

**A3. Listing or search leaking other people's documents**
- Defence: the list query only returns documents the user owns or holds an
  active, unexpired grant on.
- Test: test_stranger_does_not_see_document_in_list
- Status: CLOSED

**A4. A read grant used to edit, delete or share**
- Defence: can() maps each action to a level; only the owner may delete or share.
- Tests: test_read_grant_cannot_edit_delete_or_share, test_edit_grant_allows_edit_but_not_delete
- Status: CLOSED

**A5. A grant to one person helping another**
- Test: test_grant_to_one_person_does_not_help_another
- Status: CLOSED

**A6. Path traversal through the file name**
- Attack: upload a file named ../../etc/passwd.txt.
- Defence: the name is cleaned, and the file is stored under a random name made
  by the server, never taken from user input.
- Test: test_path_traversal_in_filename_is_neutralised
- Status: CLOSED

**A7. Admin reading document contents**
- Defence: there is no admin route to file contents, and can() has no role bypass.
- Test: test_admin_lists_documents_but_cannot_read_them
- Status: CLOSED. Cost: an admin cannot recover a file for a user who lost access.

## B. Taking access away

**B1. A revoked user keeps reading with a token issued earlier**
- Defence: grants are never stored in the token; they are read from the database
  on every request.
- Test: test_revoke_takes_effect_immediately_with_existing_token
- Status: CLOSED

**B2. A token still works after logout or deactivation**
- Defence: sessions live in the database and are checked on every request.
- Tests: test_logout_kills_the_token, test_deactivated_user_loses_access_at_once
- Status: CLOSED

**B3. A deleted document is still reachable**
- Test: test_deleted_document_is_unreachable_even_for_owner
- Status: CLOSED

**B4. A forgotten grant stays valid forever**
- Defence: owners can set a number of hours on a grant; can() and the document
  list ignore expired grants.
- Test: test_expired_grant_stops_working   (keep only if tests/test_expiry.py exists)
- Status: CLOSED

**B5. A file already downloaded cannot be taken back**
- Revoking stops future access only. No system can recall a saved copy.
- Status: ACCEPTED

## C. The audit trail

**C1. Refused attempts not recorded**
- Defence: refused document access, refused uploads, refused admin access and
  failed logins are all written to the log.
- Tests: test_refused_attempts_are_audited, test_failed_login_is_audited, test_admin_sees_refused_attempts
- Status: CLOSED

**C2. Editing an old audit row**
- Defence: each row's hash includes the previous row's hash; verify_chain() and
  /admin/verify-chain detect a change.
- Test: test_audit_chain_detects_tampering
- Status: PARTIAL, see C3 and C4

**C3. Someone with database write access rebuilds the whole chain**
- They could recompute every hash after an edit. The chain catches careless
  tampering, not a determined attacker with full database control.
- Not done: restrict the app's database user to INSERT only, and store the latest
  hash somewhere the database administrator cannot change.
- Status: ACCEPTED

**C4. Deleting the newest rows**
- verify_chain only checks that the rows that exist link together, so removing
  the last rows goes unnoticed.
- Status: ACCEPTED

**C5. Two requests forking the chain**
- Defence: prev_hash is UNIQUE, there is a lock, and writes retry on conflict.
- Status: CLOSED. No automated test for the multi-process case.

**C6. The action and its audit row are not saved in one transaction**
- A crash between the two could leave an action unrecorded.
- Status: ACCEPTED

**C7. Arbitrary text in the audit log**
- get_document_or_404 logs the document id from the URL even when no such
  document exists, so an attacker can put chosen text in the log.
- Status: ACCEPTED. It does not break the chain or leak data.

## D. Accounts and sessions

**D1. Password guessing**
- Defence: argon2 hashing, and an account locks for 15 minutes after 5 failures.
- Test: test_account_locks_after_repeated_failures
- Status: CLOSED

**D2. The lockout used as an attack**
- Someone can lock a real user out by failing on purpose, and the limit is per
  email, not per IP.
- Status: ACCEPTED. I chose protecting passwords over availability.

**D3. Finding out which emails exist**
- Login returns one message for a wrong email and a wrong password, and always
  runs the argon2 check (against a dummy hash if the user does not exist).
- Test: test_unknown_email_still_runs_the_password_hash
- Status: CLOSED. Tested by checking the hash runs, not by measuring time.

**D4. A user making themselves admin**
- No endpoint sets a role, and role is never read from a request.
- Status: CLOSED by absence. No test.

**D5. A stolen token**
- Tokens are random, stored only as hashes, and expire after 8 hours. A thief
  can use a live token until it expires or is revoked.
- Status: ACCEPTED

**D6. Old session rows pile up**
- Expired and revoked sessions are rejected but never deleted.
- Status: ACCEPTED

## E. Uploads

**E1. A disguised file (an exe renamed to .pdf)**
- Defence: the type comes from the file's content and must match the extension.
- Test: test_upload_rejects_disguised_file
- Status: CLOSED for the four allowed types

**E2. Oversized uploads**
- Defence: 5 MB limit.
- Test: test_oversized_upload_is_rejected   (keep only if you added it)
- Status: CLOSED

**E3. A viewer uploading**
- Test: test_viewer_cannot_upload
- Status: CLOSED

## F. The admin view

**F1. A non-admin reaching admin routes**
- Defence: every admin route depends on require_admin, which checks the role
  from the database on each request and logs the refusal.
- Test: test_only_admin_can_see_admin_routes
- Status: CLOSED

**F2. A rogue admin**
- An admin can see who accessed what but has no separate approval step, and
  could change data directly in the database.
- Status: ACCEPTED

**F3. The owner's grant list shows grants that have already expired**
- Not a security hole (can() ignores them) but misleading.
- Status: ACCEPTED

## G. Not built (honest list)
- No frontend; the API is used through /docs.
- No AI suggestion feature for owners.
- Uploaded files are on the server disk and are lost when Render redeploys.
- No virus scanning, no rate limit except on login.
- No sharing with outside people, versions, retention or recovery of deleted files.
- Security headers and CORS settings were not reviewed.