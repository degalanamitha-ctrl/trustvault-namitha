# AI Development Log (PROMPTS.md)

### Entry 1: System Models & Storage Architecture (2026-11-04)
- **Prompt:** "How to securely structure file storage in Python Flask?"
- **AI Output:** Recommended standard upload directory under `/static/uploads`.
- **Issue:** Publicly exposes files to direct URL downloads.
- **Fix:** Switched storage path to isolated folder `Path(app.instance_path) / "private_uploads"`.
- **Commit:** `c1a8e92 - Configured private file storage outside web static path`

### Entry 2: Authorization Checks (2026-11-04)
- **Prompt:** "Write a Flask file download route."
- **AI Output:** Called `send_file` using only the requested document ID parameter.
- **Issue:** Exposed the system to IDOR vulnerabilities.
- **Fix:** Added per-request checking with helper `can_read_document()`.
- **Commit:** `f4b2a11 - Implemented server-side authorization checks`

### Entry 3: File Signature Validation (2026-11-05)
- **Prompt:** "Validate PDF uploads in Flask."
- **AI Output:** Recommended verifying filenames with `.endswith('.pdf')`.
- **Issue:** Extension checks do not prevent malicious non-PDF uploads.
- **Fix:** Added stream byte inspection `uploaded_file.stream.read(5) == b"%PDF-"`.
- **Commit:** `e87c01d - Added magic byte signature checks`

### Entry 4: Access Revocation Route (2026-11-05)
- **Prompt:** "Create route to revoke access permissions."
- **AI Output:** Generated route deleting permissions without confirming owner identity.
- **Issue:** Any authenticated user could revoke permissions for arbitrary documents.
- **Fix:** Added validation check `if document.owner_id != current_user.id: abort(403)`.
- **Commit:** `b3310aa - Restricted permission revocation to document owners`

### Entry 5: Security Event Logging (2026-11-05)
- **Prompt:** "Record user file downloads to database."
- **AI Output:** Logged events only on successful file deliveries.
- **Issue:** Failed to capture unauthorized or blocked access attempts.
- **Fix:** Added explicit `log_action("DENIED_DOWNLOAD", ...)` on failed permissions checks.
- **Commit:** `a90d421 - Expanded audit logging to record denied access attempts`
