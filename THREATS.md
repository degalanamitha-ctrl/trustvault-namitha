# TrustVault Security Threat Model & Mitigations

| Threat Category | Target Endpoint | Prevention & Server Mitigation |
| :--- | :--- | :--- |
| **Insecure Direct Object Reference (IDOR)** | `/documents/<id>/download` | Request path parameters are ignored for access determination. Server runs `can_read_document()` live against SQLite DB permissions on every request. |
| **Direct Web URL Access** | `/static/uploads` | Documents are stored outside public paths in `instance/private_uploads/` using randomly generated UUID strings (`uuid.uuid4()`). |
| **Extension Spoofing & Remote Execution** | `/upload` | Checks magic byte signatures (`b"%PDF-"`) from the initial file stream, blocking non-binary script payloads. |
| **Permission Revocation Bypass** | `/documents/<id>/revoke/<uid>` | Revocation instantly deletes DB permissions; dynamic lookup blocks all subsequent file downloads immediately. |
| **Audit Log Tampering** | `/admin`, `/audit` | Audit log endpoints enforce `role == 'admin'` authority checks, returning `403 Forbidden` for unauthorized actors. |
