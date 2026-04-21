# AITerm Connector

Lightweight remote agent for [AITerm](https://aiterm.io) — a multi-AI terminal SaaS platform. This connector runs on your machines and relays terminal sessions to the AITerm hub so you can reach your AI backends from a browser.

The connector is **MIT-licensed and fully auditable**. The hub (backend, dashboard, billing) is closed source.

## What it does

- Discovers local AI backends (Claude Code, Ollama, llama.cpp, LM Studio, vLLM, GPT4All) plus plain bash.
- Spawns PTY sessions on demand and streams them to the hub.
- Connects **outbound** to the hub (push-model): works behind NAT, no inbound ports.
- Self-updates via Ed25519-signed manifest.

    Browser → Hub (wss://aiterm.io) ↔ Connector ↔ PTY Manager → AI process

## Install

    curl -sSL https://aiterm.io/install | bash

The installer asks whether to install **system-wide** (`/opt/aiterm`, systemd at boot) or **per-user** (`~/.local/share/aiterm`, `systemctl --user`). It prints a pairing URL — open it in your browser to link the machine to your account.

## Requirements

- Python 3.8+
- `websockets`, `cryptography` (installed automatically)
- `systemd` (optional — installer falls back to `nohup` otherwise)

## Components

| File               | Role                                                              |
|--------------------|-------------------------------------------------------------------|
| `connector.py`     | WebSocket client. Auth, self-update, file uploads, message relay. |
| `pty-manager.py`   | Multi-session PTY host. Survives connector restarts.              |
| `aiterm`           | CLI wrapper: `aiterm status / start / stop / update / uninstall`. |
| `install.sh`       | Installer + updater (dual-mode, hash-verified).                   |

The connector is a thin client: it relays JSON messages between the hub (WebSocket) and the PTY manager (Unix socket). No business logic lives here.

## Security

- **TLS certificate pinning (TOFU)** — first-seen hub cert is stored in `.cert_pin`; any change aborts with 60s backoff.
- **Ed25519-signed updates** — `remote_update` fetches `manifest.json` + `manifest.sig`, verifies against the public key embedded in `connector.py` (`MANIFEST_PUBKEY_HEX`). Tampered manifest = rejected.
- **SHA-256 per-file verification** — each downloaded file's hash must match the signed manifest.
- **Environment sanitization** — spawned PTY sessions get a whitelisted env (`PATH, HOME, USER, SHELL, TERM, COLORTERM, LANG, LC_*, TZ, DISPLAY, XDG_*`). `AWS_*`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `*_SECRET` and the like are **not** inherited.
- **Upload hardening** — `O_NOFOLLOW | O_EXCL` on writes, symlink check on the upload dir.
- **Systemd hardening** — `NoNewPrivileges`, `ProtectHome=read-only`, `ProtectKernel*`, `RestrictSUIDSGID`, `RestrictNamespaces`, `LockPersonality`.
- **Allowlisted upload extensions** — images, audio, video, PDF. No SVG (XSS risk).
- **Configurable hub URL** — `connector.json` can point at any WebSocket endpoint; this repo isn't tied to aiterm.io.

### Reviewing the update path

If you want to verify that `remote_update` cannot be used for remote code execution without the signing key:

1. `self_update()` in `connector.py` — fetches `manifest.json` + `manifest.sig`, verifies Ed25519 signature against `MANIFEST_PUBKEY_HEX` before trusting any hash.
2. Per-file SHA-256 check against the signed manifest. Mismatch → abort.
3. TLS cert pinning on the hub connection (`.cert_pin`).

A compromised hub cannot push a malicious update without also stealing the signing key, which lives offline of the hub.

### Reporting vulnerabilities

Please email `security@aiterm.io` rather than opening a public issue for anything that could affect running installations.

## CLI

    aiterm status      # Connection status, paths, versions
    aiterm start       # Start services
    aiterm stop        # Stop services
    aiterm restart     # Restart services
    aiterm update      # Self-update (signed)
    aiterm scan        # Scan local AI backends
    aiterm logs [N]    # Tail last N log lines
    aiterm uninstall   # Remove connector (confirmation required)

## Configuration

`connector.json` (mode `0600`) is generated at install time. Relevant keys:

    {
      "hub_url":        "wss://www.aiterm.io/connector",
      "hub_token":      "<paired token>",
      "default_cwd":    "/home/user",
      "upload_dir":     "/opt/aiterm/uploads",
      "max_upload_mb":  20
    }

You can point `hub_url` at your own hub if you run a compatible backend. The wire protocol is JSON-over-WebSocket (message types documented inline in `connector.py`).

## Contributing

PRs welcome — especially:

- New AI backends (`AI_COMMANDS` in `pty-manager.py`, `scan()` in `connector.py`).
- Systemd/launchd/Windows-service improvements.
- Translations for the CLI wrapper.

For substantial changes please open an issue first so we can align.

## License

MIT — see [LICENSE](LICENSE).
