# Security Policy

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Report via email to **security@aiterm.io**. Include:

- Affected version (see `CONNECTOR_VERSION` in `connector.py`)
- Reproduction steps
- Impact assessment
- Suggested fix (if any)

We aim to acknowledge reports within 72 hours and issue a fix within 14 days for critical issues.

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Older versions are unsupported.

## Threat Model

The connector is designed around these trust boundaries:

| Trusted                                      | Untrusted                                    |
|----------------------------------------------|----------------------------------------------|
| The machine's owner (who installed it)        | Other local users on the same machine        |
| The paired hub (authenticated via token)      | Third parties on the network                 |
| The Ed25519 manifest signing key              | Non-signed update payloads                   |

### Known non-issues (by design)

- **`bash` as an AI type** — intentional. The connector is a multi-AI terminal incl. plain shell.
- **No CWD allowlist** — users must be able to work in arbitrary directories on their own machines.
- **`remote_uninstall` via paired token** — administrative UX; only authorized token holders can trigger it.
- **System-mode runs as root** — mirrors `sshd` / `docker-daemon` semantics. Per-user mode (`systemctl --user`) is available as an escape hatch.

### In-scope

- Remote code execution via hub messages or update manifest
- Credential leak from connector-process environment to spawned sessions
- Symlink / path-traversal attacks on the upload directory
- Authentication bypass on the hub connection
- Cryptographic weaknesses in update verification or cert pinning

## Security Design

- **Ed25519-signed updates**: `manifest.json` + `manifest.sig` verified against `MANIFEST_PUBKEY_HEX` before any file is written.
- **SHA-256 per-file integrity**: every updated file checked against the signed manifest.
- **TLS certificate pinning (TOFU)**: first-seen hub cert stored in `.cert_pin`; mismatch aborts.
- **Environment whitelist**: only `PATH, HOME, USER, SHELL, TERM, COLORTERM, LANG, LC_*, TZ, DISPLAY, XDG_*` are inherited by PTY sessions.
- **Upload hardening**: `O_NOFOLLOW | O_EXCL` on writes, symlink check on upload dir.
- **Systemd hardening**: `NoNewPrivileges`, `ProtectHome`, `ProtectKernel*`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality`.
- **Rate-limited hub auth**: 5 failed token authentications per IP in 5 minutes trigger a 15-minute lockout.

## Hall of Fame

Security researchers who have responsibly disclosed vulnerabilities will be acknowledged here (with permission).
