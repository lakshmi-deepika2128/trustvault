# Rules for the AI on this project
- Every document route must call get_document_or_404() or can(). No exceptions.
- Authorisation is decided on the server, from the database, on every request.
- Never put permissions inside a token.
- Return 404, not 403, for documents the user cannot see.
- Every allowed AND denied action must be written to the audit log.
- Explain each change so I can defend it in an interview.