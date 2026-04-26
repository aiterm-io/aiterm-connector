# Registries — How to add an AI, a guard pattern, or a doctor check

AITerm uses three signed JSON files as the single source of truth for the
parts of the system that change most often: which AIs exist, which shell
commands are dangerous, and which packages we recommend for hardening.

If you want AITerm to support your favourite new AI tool, recognise a
new attack pattern, or recommend a new security tool, you don't need to
rebuild anything — just edit one of these files, send a PR, and once
merged + signed, every AITerm installation worldwide picks up the change
on next `aiterm update`.

## The three files

| File | What it controls | Lives at |
|---|---|---|
| `registries/ai-registry.json` | AI CLIs the connector detects, the wizard advertises, and the dashboard renders | served at `/dl/ai-registry.json` |
| `registries/guard-patterns.json` | Bash command patterns that trigger Guard Mode confirmation | served at `/dl/guard-patterns.json` |
| `registries/doctor-checks.json` | Extra "is this installed?" advisories shown by `aiterm doctor` | served at `/dl/doctor-checks.json` |

All three are part of the Ed25519-signed manifest. The connector verifies
the signature on every download, so a tampered registry on a CDN edge or
an HTTP-injection attack cannot inject malicious patterns.

## Adding a new AI

Append a block to `registries/ai-registry.json`:

```json
{
  "id": "myai",
  "label": "MyAI",
  "icon": "M",
  "pricing_tag": "byok",
  "scan": {
    "binary": "myai",
    "extra_paths": ["~/.local/bin/myai", "/usr/local/bin/myai"],
    "version_arg": "--version",
    "running_patterns": ["myai chat", "myai run"]
  },
  "start": { "args": [], "needs_model": false },
  "wizard": {
    "tag": "Vendor X — bring your own key",
    "blurb": "One-line pitch for the wizard card.",
    "steps": [
      { "title": "Install", "code": "curl ... | bash" },
      { "title": "Sign in", "code": "myai login" }
    ],
    "docs_url": "https://myai.example.com/docs"
  }
}
```

Field guide:
- `id` — short stable identifier; lowercase, no spaces. Used as a key everywhere.
- `label` / `icon` — human display.
- `pricing_tag` — `free` (no cost) / `paid` (subscription) / `byok` (bring your own API key).
- `scan.binary` — what the connector greps for in PATH.
- `scan.extra_paths` — additional paths to check (use `~` for home).
- `scan.running_patterns` — substrings that, if found in `/proc/PID/cmdline`, mean "this AI is currently running".
- `scan.list_models_cmd` — optional, for AIs like Ollama where users pick a model.
- `start.args` — args appended to the binary to put it in interactive mode (e.g. `["session"]` for goose).
- `start.needs_model` — true for Ollama-style backends; the dashboard then asks the user which model.
- `wizard` — omit to hide from the first-run wizard. `hidden_in_wizard: true` also works.

After editing: run `python3 hub/sign-manifest.py` (maintainer side), commit,
push. Customer connectors pick it up on next `aiterm update`.

## Adding a guard pattern

Append to `registries/guard-patterns.json`:

```json
{
  "id": "evil-new-attack-2026",
  "regex": "evil-tool\\s+--steal-everything",
  "severity": "crit",
  "reason": "Pattern from CVE-2026-XXXX — exfiltration tool dropped by Mythos exploits.",
  "scope": "always"
}
```

- `severity`: `crit` / `warn` / `info`.
- `scope`:
  - `always` — enforced on every bash session with Guard Mode on.
  - `piloted` — enforced *only* when a Pilot Mode token is driving the session
    (the bar is higher when AI drives AI).
- `regex` — Python `re`-compatible.

## Adding a doctor advisory

Append to `registries/doctor-checks.json`:

```json
{
  "id": "newtool",
  "name": "newtool (security audit)",
  "kind": "binary_exists",
  "target": "newtool",
  "severity": "info",
  "why": "Why this tool helps in one sentence.",
  "fix": {
    "apt":     "sudo apt-get install -y newtool",
    "dnf":     "sudo dnf install -y newtool",
    "zypper":  "sudo zypper install -y newtool",
    "pacman":  "sudo pacman -S --noconfirm newtool"
  }
}
```

`kind` is one of:
- `binary_exists` — passes if `which {target}` finds something.
- `service_active` — passes if `systemctl is-active {target}` is `active`.
- `package_present` — same as `binary_exists` for now (placeholder for native package-manager queries later).

## What to do (not) do

**Do:**
- Send PRs against just `registries/*.json`. They merge fast.
- Quote real CVE numbers in `reason` fields when you can — helps audit trails.
- Test your regex with `python3 -c "import re; print(re.search(r'YOUR_REGEX', 'sample command'))"`.

**Don't:**
- Don't put install scripts of your own in here. AITerm shows install commands
  but never runs them on the customer filesystem (security boundary, not a
  technical limitation).
- Don't add patterns that match common-but-safe commands — false positives
  train users to click through.
- Don't introduce new field names without first opening an issue. Adding a
  field changes the parser contract on every customer connector.

## How updates flow

```
edit registries/foo.json
       ↓
PR to github.com/aiterm-io/aiterm-connector
       ↓
maintainer review + merge
       ↓
maintainer runs sign-manifest.py (signs new SHA-256s)
       ↓
manifest.json + manifest.sig published to /dl/
       ↓
customer connector runs `aiterm update`
       ↓
signed_download verifies signature, replaces local registry
       ↓
all consumers (connector scan, pty-manager guard,
dashboard wizard, doctor) pick up new entries
```

No restart on the hub side. No code release. JSON in → behaviour change out.

## Why this matters

If a new attack tool drops on a Tuesday, we want every AITerm installation
to recognise it by Wednesday. The slow path is "release a new connector
version, customers wait for auto-update window, half of them defer it" — by
which time the attacker has moved on. The fast path is one signed JSON edit.

That's what registries are for.
