# Security Policy

[![Disclose.io Vulnerability Disclosure Policy](https://img.shields.io/badge/Disclose.io-Compliant-4B6FB2.svg)](https://disclose.io/policy/)
[![GitHub Private Vulnerability Reporting](https://img.shields.io/badge/Report-privately%20via%20GitHub-238636.svg)](https://github.com/aiterm-io/aiterm-connector/security/advisories/new)

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Two equally good channels:

1. **Email:** `security@aiterm.io`
2. **GitHub Private Vulnerability Reporting:** [aiterm-connector/security/advisories/new](https://github.com/aiterm-io/aiterm-connector/security/advisories/new) — end-to-end private, tied to your GitHub identity, good for coordinated disclosure.

Include:

- Affected version (see `CONNECTOR_VERSION` in `connector.py`)
- Reproduction steps
- Impact assessment
- Suggested fix (if any)

### Response commitments

| Severity | Acknowledgement | Fix target |
|----------|-----------------|------------|
| Critical (RCE, auth bypass, cryptographic) | 24 h | 7 days |
| High   | 72 h | 14 days |
| Medium | 5 business days | 30 days |
| Low    | 10 business days | next release |

We will credit you in the Hall of Fame below unless you prefer anonymity. We will coordinate disclosure timing with you.

## Safe Harbor

We support good-faith security research on AITerm and will not pursue or support legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, service degradation, data destruction, or interruption of service.
- Only interact with accounts you own or with explicit permission from the account holder.
- Do not exploit a security issue beyond what is necessary to demonstrate it.
- Report the vulnerability to us via one of the channels above and give us reasonable time to respond before public disclosure.
- Do not attempt to access, modify, or delete other users' data.

Activities consistent with this policy are considered authorised and we will not initiate or recommend legal action against you.

## Scope

### In scope

- The AITerm connector (`connector.py`, `pty-manager.py`, `aiterm` CLI, `install.sh`) in this repository
- Vulnerabilities in the self-update mechanism (manifest, Ed25519 signature, SHA-256 verification)
- Credential leakage from connector-process env into spawned PTY sessions
- Upload path vulnerabilities (symlink, path traversal, size DoS)
- The pairing flow and token exchange
- The hub WebSocket protocol as implemented by the connector

### Out of scope

- The aiterm.io hub internals — closed source, reported through same channels but not reward-eligible in this repo.
- Denial of Service via absolute resource exhaustion (CPU, bandwidth) beyond what the documented rate limits accept.
- Findings that require physical or local-user access to an already-compromised machine (the connector's threat model assumes the machine itself is trusted).
- Weaknesses in third-party dependencies that are reported upstream. We track them via `pip-audit` in CI.

## Supported Versions

Only the latest release on the `main` branch receives security fixes. Older versions are unsupported; please update via `aiterm update` or `curl -sSL https://aiterm.io/install | bash`.

## Threat Model

The connector is designed around these trust boundaries:

| Trusted                                      | Untrusted                                    |
|----------------------------------------------|----------------------------------------------|
| The machine's owner (who installed it)       | Other local users on the same machine        |
| The paired hub (authenticated via token)     | Third parties on the network                 |
| The Ed25519 manifest signing key             | Non-signed update payloads                   |

### Known non-issues (by design)

- **`bash` as an AI type** — intentional. The connector is a multi-AI terminal incl. plain shell.
- **No CWD allowlist** — users must be able to work in arbitrary directories on their own machines.
- **`remote_uninstall` via paired token** — administrative UX; only authorised token holders can trigger it.
- **System-mode runs as root** — mirrors `sshd` / `docker-daemon` semantics. Per-user mode (`systemctl --user`) is available as an escape hatch.

### In-scope

- Remote code execution via hub messages or update manifest
- Credential leak from connector-process environment to spawned sessions
- Symlink / path-traversal attacks on the upload directory
- Authentication bypass on the hub connection
- Cryptographic weaknesses in update verification or cert pinning

## Security Design

- **Ed25519-signed installer + updates.** Both `install.sh` (first-time install) and `connector.py` (self-update) verify a signed `manifest.json` against an embedded public key *before* any file is written. This closes the installer-chain hole: even a compromised TLS endpoint or CDN cannot ship malicious code.
- **SHA-256 per-file integrity** on every downloaded file, checked against the signed manifest.
- **TLS certificate pinning (TOFU)** — first-seen hub certificate stored in `.cert_pin`; any change aborts.
- **Environment whitelist** — spawned PTY sessions see only `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `COLORTERM`, `LANG`, `LC_*`, `TZ`, `DISPLAY`, `XDG_*`. `AWS_*`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `*_SECRET` are filtered out.
- **Upload hardening** — `O_NOFOLLOW | O_EXCL | O_CREAT` with mode `0600`. Upload directory `chmod 0700`. Encoded-length pre-check before base64 decode (prevents RAM DoS).
- **Systemd hardening** — `NoNewPrivileges`, `ProtectHome`, `ProtectKernel*`, `RestrictNamespaces`, `RestrictSUIDSGID`, `LockPersonality` on the connector service.
- **Hub-auth rate limiting** — 5 failed token authentications per IP trigger a 15-minute lockout. Loopback exempt.
- **Session content never persisted** — transient in RAM only, up to 200 KB rolling scrollback per session.

## Continuous security assurance

Each push to `main` runs:

- **CodeQL** (`security-and-quality` queries) — GitHub-native flow-analysis SAST
- **Bandit** — Python-specific SAST
- **pip-audit** — dependency CVE scan for `websockets`, `cryptography`
- **gitleaks** — commit-history secret scanning
- **ShellCheck** — `install.sh` and `aiterm` CLI
- **ruff** — Python lint (E,F,W,B)
- **py_compile** — syntax matrix across Python 3.9–3.12

A failing security job blocks merges to `main`.

## External review log

| Date | Reviewer | Scope | Public report |
|------|----------|-------|---------------|
| 2026-04-21 | Third-party AI-assisted red-team (adversary-perspective review of open repo + site) | Installer chain, upload path, auth model, TOFU trust boundary, legal posture | Findings addressed in commits [f2fe734](https://github.com/aiterm-io/connector/commit/f2fe734) and [df5af61](https://github.com/aiterm-io/aiterm-connector/commit/df5af61) |

Future formal audits (Cure53, Radically Open Security, or similar) will be linked here.

## Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be acknowledged here with their consent.

_This list is currently empty. Be the first._
