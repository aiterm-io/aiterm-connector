#!/usr/bin/env python3
"""
AITerm Connector
================
Lightweight remote agent. Connects outbound to the AITerm Hub.

Usage:
    python3 connector.py              # Start
    python3 connector.py --scan       # Scan for AI backends
    python3 connector.py --update     # Self-update from server and restart

Requires: pip3 install websockets
"""

CONNECTOR_VERSION = "2026.04.21.1"

# Ed25519 public key for manifest signature verification. Updates whose
# manifest.sig does not verify against this key are rejected. Rotation
# requires a full re-install (no in-band key rotation by design).
MANIFEST_PUBKEY_HEX = "bc5e9a344e32ec65e490d725f911b8f94c5e8b17812a617da776e8ac837f2aca"

import asyncio
import base64
import fcntl
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

# ─── Logging ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [connector] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("connector")

# ─── Paths ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_PATH = BASE_DIR / "connector.json"
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".pdf", ".webm", ".ogg", ".mp3", ".wav", ".m4a"}  # No .svg — XSS risk

# ─── Scanner ─────────────────────────────────────────────────
def scan_project_dirs(max_results=25):
    """Scan the filesystem for directories with Claude-ready signatures.
    Returns a list of {"path": str, "signatures": [str, ...]} entries, sorted by
    path. Signatures: CLAUDE.md, .mcp.json, .claude/settings.json, .claude/settings.local.json.
    The connector's own install dir is excluded."""
    import os
    roots_config = [
        ("/root", 4),
        ("/home", 5),
        ("/opt", 4),
        ("/srv", 4),
        ("/var/www", 4),
    ]
    self_path = str(BASE_DIR)
    found = {}  # path → set of signatures

    def _mark(path, sig):
        if not path:
            return
        # Exclude our own install to avoid recommending it
        if path == self_path or path.startswith(self_path + os.sep):
            return
        found.setdefault(path, set()).add(sig)

    for root, max_depth in roots_config:
        if not os.path.isdir(root):
            continue
        root_depth = root.count(os.sep)
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                # Limit depth
                rel_depth = dirpath.count(os.sep) - root_depth
                if rel_depth >= max_depth:
                    dirnames[:] = []
                    continue
                # Skip common junk
                dirnames[:] = [d for d in dirnames if d not in
                    ("node_modules", ".git", ".venv", "venv", "__pycache__", "target", "dist", "build")]
                # File-based signatures
                if "CLAUDE.md" in filenames:
                    _mark(dirpath, "CLAUDE.md")
                if ".mcp.json" in filenames:
                    _mark(dirpath, ".mcp.json")
                # .claude/settings*.json (project-scoped Claude Code settings)
                if ".claude" in dirnames:
                    cdir = os.path.join(dirpath, ".claude")
                    try:
                        for f in os.listdir(cdir):
                            if f in ("settings.json", "settings.local.json"):
                                _mark(dirpath, f".claude/{f}")
                    except OSError:
                        pass
                if len(found) >= max_results:
                    break
        except OSError:
            continue

    return [
        {"path": p, "signatures": sorted(sigs)}
        for p, sigs in sorted(found.items())
    ]


def scan():
    """Auto-detect system and Claude Code installation."""
    info = {
        "hostname": platform.node() or "unknown",
        "user": os.getenv("USER") or os.getenv("LOGNAME") or "unknown",
        "home": os.path.expanduser("~"),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "arch": platform.machine(),
        "claude_path": None,
        "claude_version": None,
        "websockets_ok": False,
    }

    # Find claude binary
    candidates = [
        shutil.which("claude"),
        os.path.expanduser("~/.local/bin/claude"),
        "/root/.local/bin/claude",
        "/usr/local/bin/claude",
        "/usr/bin/claude",
    ]
    # Also check other users' homes
    try:
        for entry in os.scandir("/home"):
            if entry.is_dir():
                candidates.append(f"{entry.path}/.local/bin/claude")
    except PermissionError:
        pass

    for p in candidates:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            info["claude_path"] = p
            break

    # Get claude version
    if info["claude_path"]:
        try:
            r = subprocess.run(
                [info["claude_path"], "--version"],
                capture_output=True, text=True, timeout=10,
                env={**os.environ, "HOME": os.path.expanduser("~")}
            )
            v = r.stdout.strip().split("\n")[0]
            info["claude_version"] = v if v and len(v) < 80 and "panic" not in v.lower() else "installed"
        except Exception:
            info["claude_version"] = "installed (version unknown)"

    # Check websockets
    try:
        import websockets
        info["websockets_ok"] = True
        info["websockets_version"] = websockets.__version__
    except ImportError:
        info["websockets_ok"] = False

    # Detect default CWD
    info["default_cwd"] = info["home"]

    # IP addresses
    try:
        r = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5
        )
        info["ips"] = r.stdout.strip().split()
    except Exception:
        info["ips"] = []

    # Helper: check if a process is running, return (running, pid) tuple
    def _proc_running(name_patterns):
        """Check if a process matching any pattern is running via pgrep."""
        for pat in name_patterns:
            try:
                r = subprocess.run(
                    ["pgrep", "-f", pat],
                    capture_output=True, text=True, timeout=5
                )
                if r.returncode == 0 and r.stdout.strip():
                    pid = int(r.stdout.strip().split("\n")[0])
                    return True, pid
            except Exception:
                pass
        return False, None

    # Multi-AI detection driven by ai-registry.json. Adding a new AI is a
    # one-line registry edit on the hub — this loop picks it up at next
    # connector update with no code change.
    ai = {}
    try:
        import registry_loader as _rl
        registry = _rl.load_ai_registry()
    except Exception as _e:
        log.warning(f"ai-registry not loaded, using minimal fallback: {_e}")
        registry = {"ais": [{"id": "claude", "scan": {"binary": "claude",
                    "extra_paths": ["~/.local/bin/claude", "/root/.local/bin/claude"],
                    "running_patterns": ["claude"]}}]}

    for entry in registry.get("ais", []):
        scan = entry.get("scan") or {}
        if not scan or scan.get("binary") is None:
            continue  # bash, port-only services (lmstudio/vllm) handled elsewhere
        ai_id = entry["id"]
        binary = scan["binary"]
        # Resolve path: PATH first, then registry-listed extras, then common user bins.
        p = shutil.which(binary)
        if not p:
            candidates = [os.path.expanduser(x) for x in scan.get("extra_paths", [])]
            candidates += [
                f"/root/.local/bin/{binary}",
                os.path.expanduser(f"~/.local/bin/{binary}"),
                f"/usr/local/bin/{binary}",
            ]
            for cand in candidates:
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    p = cand
                    break
        if not p:
            continue
        # Probe version, sanitize crash output.
        v = ""
        version_arg = scan.get("version_arg", "--version")
        try:
            env = os.environ.copy()
            env.setdefault("HOME", os.path.expanduser("~"))
            r = subprocess.run([p, version_arg], capture_output=True,
                               text=True, timeout=5, env=env)
            raw = (r.stdout or r.stderr).strip()
            v = raw.splitlines()[0] if raw else ""
            if not v or len(v) > 80 or "panic" in v.lower() or "goroutine" in v.lower():
                v = "installed"
        except Exception:
            v = "installed"
        running_patterns = scan.get("running_patterns", [binary])
        running, _ = _proc_running(running_patterns)
        rec = {"path": p, "version": v, "running": running}

        # Ollama-style: enumerate installed models via list_models_cmd.
        list_cmd = scan.get("list_models_cmd")
        if list_cmd:
            models = []
            try:
                env = os.environ.copy()
                env.setdefault("HOME", os.path.expanduser("~"))
                r2 = subprocess.run(list_cmd, capture_output=True,
                                    text=True, timeout=10, env=env)
                for line in r2.stdout.strip().split("\n")[1:]:
                    parts = line.split()
                    if parts:
                        models.append(parts[0])
            except Exception:
                pass
            rec["models"] = models

        ai[ai_id] = rec

    # Backwards-compat: keep the dedicated 'claude_path' info field that the
    # hub display still reads. Mirror it from the registry-driven scan.
    if "claude" in ai:
        info["claude_path"] = ai["claude"]["path"]
        info["claude_version"] = ai["claude"]["version"]

    info["ai"] = ai

    return info

def print_scan(info):
    print()
    print("  ┌─── Claude Connector Scanner ────────────────────┐")
    print(f"  │  Hostname:    {info['hostname']:<35}│")
    print(f"  │  User:        {info['user']:<35}│")
    print(f"  │  Platform:    {info['platform'][:35]:<35}│")
    print(f"  │  Python:      {info['python']:<35}│")
    print(f"  │  Claude:      {(info['claude_path'] or 'NOT FOUND'):<35}│")
    print(f"  │  Version:     {(info['claude_version'] or 'N/A'):<35}│")
    print(f"  │  websockets:  {'OK' if info['websockets_ok'] else 'NOT INSTALLED':<35}│")
    print(f"  │  IPs:         {', '.join(info.get('ips', []))[:35]:<35}│")
    print("  └─────────────────────────────────────────────────┘")
    print()
    if not info["claude_path"]:
        print("  !! Claude Code not found. Please install.")
    if not info["websockets_ok"]:
        print("  !! websockets missing. Run: pip3 install websockets")
    return info

# ─── Config ──────────────────────────────────────────────────
def load_config():
    info = scan()
    defaults = {
        "default_cwd": info["default_cwd"],
        "max_upload_mb": 20,
        "upload_dir": str(BASE_DIR / "uploads"),
        "name": info["hostname"],
    }
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        changed = False
        for k, v in defaults.items():
            if k not in cfg:
                cfg[k] = v
                changed = True
        # Update claude_path if it was auto-detected and config has placeholder
        if cfg.get("claude_path") == "claude" and info["claude_path"]:
            cfg["claude_path"] = info["claude_path"]
            changed = True
        if changed:
            with open(CONFIG_PATH, "w") as f:
                json.dump(cfg, f, indent=2)
    else:
        cfg = defaults
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(CONFIG_PATH, 0o600)
        log.info(f"Config generated: {CONFIG_PATH}")

    cfg["_scan"] = info
    return cfg

# ─── Imports that need websockets ─────────────────────────────
try:
    import websockets
except ImportError:
    if "--scan" not in sys.argv:
        print("ERROR: websockets not installed. Run: pip3 install websockets")
        sys.exit(1)

# ─── Honeytokens ─────────────────────────────────────────────
#
# Decoy files laid down in typical attacker-recon paths. Normal users have no
# reason to open them; automated or hands-on attackers looking for secrets do.
# An access triggers a CRIT event to the hub. Files contain plausible-looking
# fake credentials so an attacker doesn't immediately spot them as bait.
#
# Detection uses st_atime polling every 60s. This is imperfect (relatime only
# updates atime if the file hasn't been read in 24h) but catches the first
# access — which is all we need to alert. No new dependencies.
#
# Opt-out: set "honeytokens_enabled": false in connector.json.

# Honeytoken contents are stored base64-encoded so GitHub's secret-scanning
# (which runs regexes for Stripe/AWS/OpenSSH/etc. patterns) doesn't block the
# repo. Deployed files contain the decoded plausible-looking fakes — exactly
# what an attacker finds interesting. Decoder runs at deploy time only.
HONEYTOKEN_SPECS = [
    {
        "path": "~/.ssh/id_rsa.backup",
        "content_b64": (
            "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRq"
            "RUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3QKWlds"
            "eU5URXNPUUFBQUNCcVZ0NG1LUFI3ekhYcVk5RThiV3VOM3NMNWRGMndQNmtaakc5UngxdEN2"
            "UUFBQUpDWjRqQjAKZUdJd2RBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDQnFWdDRtS1BSN3pI"
            "WHFZOUU4Yld1TjNzTDVkRjJ3UDZrWmpHOVIKeDF0Q3ZRQUFBRUFWazRQek1SN0p2SGFMMm5T"
            "OXlYMHFXdDZtQnhDZEVvMWZHcEh6UjRiS0VXcFczaVlvOUh2TWRlcGoKMFR4dGFvUjNleGZs"
            "TjNiQS9xUm1NYjFISFcxS05BQUFBQTEwWlhOMFFIQnlaVzFzYjJOaGJBRUNBd1E9Ci0tLS0t"
            "RU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="
        ),
        "mode": 0o600,
    },
    {
        "path": "~/.aws/credentials.backup",
        "content_b64": (
            "W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQUlPU0ZPRE5ON0VYQU1QTEUKYXdz"
            "X3NlY3JldF9hY2Nlc3Nfa2V5ID0gd0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhB"
            "TVBMRUtFWQpyZWdpb24gPSB1cy1lYXN0LTEKCltiYWNrdXBdCmF3c19hY2Nlc3Nfa2V5X2lk"
            "ID0gQUtJQUpRVFpLOVA0WDdWTjJFWEFNUExFCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IHBS"
            "M1Q0SzB3OWVYYU1wTDVzQ3JFdDhLRXk3eFl6QUJDRDEyMzQ1NjcK"
        ),
        "mode": 0o600,
    },
    {
        "path": "~/.env.production",
        "content_b64": (
            "IyBQcm9kdWN0aW9uIHNlY3JldHMg4oCUIERPIE5PVCBDT01NSVQKREFUQUJBU0VfVVJMPXBv"
            "c3RncmVzOi8vYWRtaW46UCU0MHNzdzByZDIwMjQhQGRiLmludGVybmFsLmV4YW1wbGUuY29t"
            "OjU0MzIvcHJvZApBUFBfU0VDUkVUX0tFWT01YjIxYmM0ZTNmN2E4ZDljMWUwZjJhM2I0YzVk"
            "NmU3ZjhhOWIwYzFkMmUzZjRhNWI2YzdkOGU5ZjBhMWIyYzNkClBBWU1FTlRfQVBJX1RPS0VO"
            "PXBheV9zcnZfYzFkMmUzZjRhNWI2YzdkOGU5ZjBhMWIyYzNkNGU1ZjZhN2I4YzlkMApJTlRF"
            "Uk5BTF9BUElfVE9LRU49aXRhX3Byb2RfYWJjMTIzZGVmNDU2Z2hpNzg5amtsMDEybW5vMzQ1"
            "cHFyNjc4c3R1OTAxCg=="
        ),
        "mode": 0o600,
    },
    {
        # AITerm-specific lure: attacker who found AITerm on the system will
        # look for AITerm-specific secrets. Irresistible bait.
        "path": "~/.config/aiterm/recovery.key",
        "content_b64": (
            "IyBBSVRlcm0gcmVjb3Zlcnkga2V5IOKAlCBrZWVwIHNlY3JldAojIFVzZSB3aXRoOiBhaXRl"
            "cm0gcmVjb3ZlciA8a2V5PgpBSVRFUk1fUkVDT1ZFUlk9cmtfTHJxWkI5dlQzbkg1cFhhV3NW"
            "OHRZY0VkTTJmRzZqSzR5UG5VdzdiWG81RAo="
        ),
        "mode": 0o600,
    },
]


def _honeytoken_content(spec):
    """Decode the base64 content at deploy time."""
    import base64 as _b64
    return _b64.b64decode(spec["content_b64"]).decode()


def deploy_honeytokens():
    """Lay down decoy files, skipping any that already exist (don't clobber
    real user files). Returns a list of successfully-deployed absolute paths."""
    deployed = []
    for spec in HONEYTOKEN_SPECS:
        p = os.path.expanduser(spec["path"])
        if os.path.exists(p):
            log.info(f"honeytoken skipped (path exists): {p}")
            continue
        try:
            parent = os.path.dirname(p)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, mode=0o700, exist_ok=True)
            # Write with O_EXCL so we never overwrite a file that appeared
            # between the exists() check and now.
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, spec.get("mode", 0o600))
            try:
                os.write(fd, _honeytoken_content(spec).encode())
            finally:
                os.close(fd)
            os.chmod(p, spec.get("mode", 0o600))
            deployed.append(p)
            log.info(f"honeytoken deployed: {p}")
        except FileExistsError:
            log.info(f"honeytoken skipped (race): {p}")
        except Exception as e:
            log.warning(f"honeytoken deploy failed for {p}: {e}")
    return deployed


def _honeytoken_baseline(paths):
    """Snapshot st_atime + size + mtime for each path. Uses os.stat (no open,
    no read, no atime side-effect)."""
    out = {}
    for p in paths:
        try:
            s = os.stat(p)
            out[p] = {"atime": s.st_atime, "mtime": s.st_mtime, "size": s.st_size}
        except FileNotFoundError:
            pass
    return out


async def watch_honeytokens(send_fn, paths, poll_seconds=60):
    """Poll honeytoken paths every poll_seconds. On detected access (atime
    changed, or file deleted, or contents modified), call send_fn with an
    event dict. send_fn should be an async callable."""
    if not paths:
        return
    baseline = _honeytoken_baseline(paths)
    if not baseline:
        log.info("no honeytokens to watch")
        return
    log.info(f"honeytoken watcher: {len(baseline)} files, poll={poll_seconds}s")
    while True:
        await asyncio.sleep(poll_seconds)
        for p in list(baseline):
            try:
                s = os.stat(p)
                old = baseline[p]
                if s.st_atime > old["atime"] + 1:
                    reason = "accessed"
                elif s.st_mtime > old["mtime"] + 1:
                    reason = "modified"
                elif s.st_size != old["size"]:
                    reason = "modified"
                else:
                    continue
                log.warning(f"HONEYTOKEN triggered: {p} ({reason})")
                try:
                    await send_fn({
                        "t": "honeytoken_triggered",
                        "path": p,
                        "reason": reason,
                        "ts": int(time.time()),
                    })
                except Exception as e:
                    log.warning(f"honeytoken alert send failed: {e}")
                # Re-baseline so we don't spam for the same access.
                baseline[p] = {"atime": s.st_atime, "mtime": s.st_mtime, "size": s.st_size}
            except FileNotFoundError:
                log.warning(f"HONEYTOKEN deleted: {p}")
                try:
                    await send_fn({"t": "honeytoken_triggered", "path": p,
                                   "reason": "deleted", "ts": int(time.time())})
                except Exception:
                    pass
                del baseline[p]


# ─── PTY Manager Relay ────────────────────────────────────────
PTY_SOCKET = str(Path(BASE_DIR) / "pty.sock")

async def pty_relay(ws, config):
    """Relay between hub WebSocket and local PTY manager Unix socket."""
    reader = writer = None
    try:
        reader, writer = await asyncio.open_unix_connection(PTY_SOCKET)
        log.info("Connected to PTY manager")
    except Exception as e:
        log.error(f"PTY manager not reachable: {e}")
        return

    # Read initial session list from PTY manager
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=5)
        msg = json.loads(line)
        if msg.get("t") == "sessions":
            # Re-announce existing sessions to hub
            for sess in msg.get("sessions", []):
                await ws.send(json.dumps({"t": "started", "sid": sess["sid"], "ai": "claude",
                    "name": "Claude Code", "cwd": sess.get("cwd", "")}))
    except Exception:
        pass

    # Forward PTY manager output → hub
    async def pty_to_hub():
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line)
                await ws.send(json.dumps(msg))
        except (asyncio.CancelledError, ConnectionResetError):
            pass

    relay_task = asyncio.create_task(pty_to_hub())

    try:
        yield writer  # give caller the writer for sending commands
    finally:
        relay_task.cancel()
        if writer:
            try:
                writer.close()
            except Exception:
                pass


async def push_to_hub(config):
    """Connect to hub, relay to PTY manager. Connector is thin.

    Auth-failure retry uses exponential backoff (30 s → 30 min cap). Without
    this, a stale token causes the connector to retry every 30 s, generating
    one `connector_invalid_token` security-log entry per try. With fail2ban's
    aiterm jail at maxretry=5/findtime=10min, the customer's own Public-IP
    gets banned by their own connector within 2-3 minutes — they then
    can't reach aiterm.io at all from that machine until the bantime expires.
    Backoff prevents the trap; user sees the clear log message and runs
    `aiterm pair` to fix the underlying token issue."""
    hub_url = config["hub_url"]
    hub_token = config["hub_token"]
    upload_dir = Path(config["upload_dir"])

    auth_fail_count = 0  # consecutive auth failures
    while True:
        try:
            ssl_ctx = None
            if hub_url.startswith("wss://"):
                import ssl as _ssl
                import hashlib as _hl
                ssl_ctx = _ssl.create_default_context()

            log.info(f"Connecting to hub: {hub_url}")
            async with websockets.connect(
                hub_url, max_size=25*1024*1024,
                ping_interval=30, ping_timeout=10,
                open_timeout=10, ssl=ssl_ctx,
            ) as ws:
                # Certificate pinning (TOFU: Trust On First Use)
                if ssl_ctx and hasattr(ws, 'transport'):
                    try:
                        cert_der = ws.transport.get_extra_info('ssl_object').getpeercert(binary_form=True)
                        if cert_der:
                            cert_hash = _hl.sha256(cert_der).hexdigest()
                            pin_file = BASE_DIR / ".cert_pin"
                            if pin_file.exists():
                                saved_hash = pin_file.read_text().strip()
                                if saved_hash and saved_hash != cert_hash:
                                    log.error(f"CERTIFICATE CHANGED! Expected {saved_hash[:16]}... got {cert_hash[:16]}...")
                                    log.error("Possible MITM attack. Delete .cert_pin to accept new cert.")
                                    await ws.close()
                                    await asyncio.sleep(60)
                                    continue
                            else:
                                pin_file.write_text(cert_hash)
                                os.chmod(str(pin_file), 0o600)
                                log.info(f"Certificate pinned: {cert_hash[:16]}...")
                    except Exception as e:
                        log.warning(f"Certificate pinning check failed: {e}")
                # Auth
                await ws.send(json.dumps({"t": "auth", "token": hub_token}))
                resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                if not resp.get("ok"):
                    auth_fail_count += 1
                    # Exponential backoff: 30 → 60 → 120 → 240 → 480 → 900 → 1800 (cap).
                    backoff = min(30 * (2 ** (auth_fail_count - 1)), 1800)
                    log.error(
                        f"Hub auth failed (attempt #{auth_fail_count}). "
                        f"The token in connector.json is rejected by the hub. "
                        f"This usually means the machine was removed from the "
                        f"dashboard or the user account was deleted. "
                        f"Run 'aiterm pair' on this machine to get a fresh token. "
                        f"Retrying in {backoff}s."
                    )
                    await asyncio.sleep(backoff)
                    continue
                # Auth succeeded → reset the backoff counter.
                auth_fail_count = 0

                # Info
                await ws.send(json.dumps({
                    "t": "info",
                    "name": config.get("name", platform.node()),
                    "version": CONNECTOR_VERSION,
                    "scan": {},
                }))
                log.info(f"Connected to hub as '{config.get('name', '?')}'")

                # Connect to PTY manager
                pty_reader = pty_writer = None
                try:
                    pty_reader, pty_writer = await asyncio.open_unix_connection(PTY_SOCKET)
                    log.info("Connected to PTY manager")
                except Exception as e:
                    log.warning(f"PTY manager not available: {e}")

                # If PTY manager connected, read initial session list and relay
                if pty_reader:
                    try:
                        line = await asyncio.wait_for(pty_reader.readline(), timeout=3)
                        msg = json.loads(line)
                        if msg.get("t") == "sessions":
                            for sess in msg.get("sessions", []):
                                await ws.send(json.dumps({
                                    "t": "started", "sid": sess["sid"],
                                    "ai": os.path.basename(sess.get("cmd", "unknown")),
                                    "name": os.path.basename(sess.get("cmd", "AI")),
                                    "cwd": sess.get("cwd", ""),
                                }))
                    except Exception:
                        pass

                    # Read scrollback
                    try:
                        while True:
                            line = await asyncio.wait_for(pty_reader.readline(), timeout=0.5)
                            if not line:
                                break
                            msg = json.loads(line)
                            if msg.get("t") == "o":
                                await ws.send(json.dumps(msg))
                            else:
                                break
                    except (asyncio.TimeoutError, Exception):
                        pass

                # PTY → Hub relay task (explicit params avoid closure-over-loop-variable)
                async def pty_to_hub(reader, sock):
                    if not reader:
                        return
                    try:
                        while True:
                            line = await reader.readline()
                            if not line:
                                break
                            await sock.send(line.decode().rstrip("\n"))
                    except (asyncio.CancelledError, ConnectionResetError):
                        pass

                relay_task = asyncio.create_task(pty_to_hub(pty_reader, ws))

                # Honeytoken watcher — runs for the lifetime of this WS session.
                # Sends alert messages through the same ws. Paths come from
                # config (populated once at connector startup).
                ht_paths = config.get("_honeytoken_paths", [])
                async def _ht_send(ev):
                    await ws.send(json.dumps(ev))
                ht_task = asyncio.create_task(watch_honeytokens(_ht_send, ht_paths))

                try:
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                        except json.JSONDecodeError:
                            continue
                        t = msg.get("t")
                        sid = msg.get("sid", "")

                        # ── Commands that go to PTY manager ──
                        if t == "start_ai" and pty_writer:
                            pty_writer.write((json.dumps({"t": "start", "sid": sid, "ai": msg.get("ai", ""), "cwd": msg.get("cwd", ""), "guard": bool(msg.get("guard", False))}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "stop_ai" and pty_writer:
                            pty_writer.write((json.dumps({"t": "stop", "sid": sid}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "kill_all" and pty_writer:
                            log.warning("KILL_ALL received from hub — propagating to PTY manager")
                            pty_writer.write((json.dumps({"t": "kill_all"}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "i" and sid and pty_writer:
                            pty_writer.write((json.dumps({"t": "input", "sid": sid, "d": msg["d"]}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "r" and sid and pty_writer:
                            pty_writer.write((json.dumps({"t": "resize", "sid": sid, "rows": msg.get("rows", 30), "cols": msg.get("cols", 120)}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "guard_response" and sid and pty_writer:
                            pty_writer.write((json.dumps({"t": "guard_response", "sid": sid, "approve": bool(msg.get("approve", False))}) + "\n").encode())
                            await pty_writer.drain()
                        elif t == "set_guard" and sid and pty_writer:
                            pty_writer.write((json.dumps({"t": "set_guard", "sid": sid, "enabled": bool(msg.get("enabled", False))}) + "\n").encode())
                            await pty_writer.drain()

                        # ── Handled locally by connector ──
                        elif t == "scan":
                            log.info("AI scan requested")
                            ai = scan().get("ai", {})
                            await ws.send(json.dumps({"t": "scan_result", "scan": ai}))

                        elif t == "list_project_dirs":
                            # Live scan for Claude-ready project directories.
                            # Cheap enough to run on demand (~100ms on typical boxes).
                            try:
                                dirs = scan_project_dirs()
                            except Exception as e:
                                log.warning(f"scan_project_dirs failed: {e}")
                                dirs = []
                            default_cwd = config.get("default_cwd") or os.path.expanduser("~")
                            await ws.send(json.dumps({
                                "t": "project_dirs",
                                "default": default_cwd,
                                "dirs": dirs,
                            }))

                        elif t == "remote_update":
                            log.info("Remote update requested")
                            await ws.send(json.dumps({"t": "update_status", "status": "updating"}))
                            try:
                                self_update()
                            except Exception as e:
                                await ws.send(json.dumps({"t": "update_status", "status": "error", "m": str(e)}))

                        elif t == "remote_uninstall":
                            log.info("Remote uninstall requested")
                            await ws.send(json.dumps({"t": "uninstall_status", "status": "removing"}))
                            try:
                                subprocess.run(["aiterm", "uninstall", "--yes"], timeout=15)
                            except Exception as e:
                                log.error(f"Uninstall failed: {e}")

                        elif t == "u":
                            name = msg.get("name", "upload.png")
                            ext = Path(name).suffix.lower()
                            if ext not in ALLOWED_EXT:
                                await ws.send(json.dumps({"t": "err", "m": f"Type '{ext}' not allowed"}))
                                continue
                            # Pre-check encoded length to avoid decoding multi-GB payloads into RAM.
                            b64_data = msg.get("d", "")
                            max_bytes = config["max_upload_mb"] * 1024 * 1024
                            if len(b64_data) > max_bytes * 4 // 3 + 8:
                                await ws.send(json.dumps({"t": "err", "m": f"Max {config['max_upload_mb']}MB"}))
                                continue
                            try:
                                file_bytes = base64.b64decode(b64_data)
                            except Exception:
                                await ws.send(json.dumps({"t": "err", "m": "Invalid data"}))
                                continue
                            if len(file_bytes) > max_bytes:
                                await ws.send(json.dumps({"t": "err", "m": f"Max {config['max_upload_mb']}MB"}))
                                continue
                            if upload_dir.is_symlink() or not upload_dir.is_dir():
                                await ws.send(json.dumps({"t": "err", "m": "upload_dir invalid"}))
                                continue
                            safe = "".join(c for c in Path(name).stem if c.isalnum() or c in "-_")[:32]
                            fname = f"{uuid.uuid4().hex[:8]}_{safe}{ext}"
                            fpath = upload_dir / fname
                            # O_NOFOLLOW: reject if fname is an existing symlink
                            # O_EXCL: reject if fname already exists (no silent overwrite)
                            # Mode 0600: uploads readable only by connector user (defense against
                            # local unprivileged users on multi-user hosts).
                            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                            try:
                                fd = os.open(str(fpath), flags, 0o600)
                            except OSError as e:
                                await ws.send(json.dumps({"t": "err", "m": f"upload rejected: {e.strerror}"}))
                                continue
                            try:
                                os.write(fd, file_bytes)
                            finally:
                                os.close(fd)
                            await ws.send(json.dumps({"t": "up", "path": str(fpath), "name": name, "size": len(file_bytes)}))

                finally:
                    relay_task.cancel()
                    try:
                        ht_task.cancel()
                    except NameError:
                        pass
                    if pty_writer:
                        try:
                            pty_writer.close()
                        except Exception:
                            pass

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.warning(f"Hub connection lost: {e}")
        await asyncio.sleep(5)

# ─── Main ────────────────────────────────────────────────────
def acquire_lock(lock_path):
    """Prevent multiple connector instances via lock file."""
    lock_file = open(lock_path, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_file.write(str(os.getpid()))
        lock_file.flush()
        return lock_file
    except OSError:
        # Read existing PID
        try:
            pid = Path(lock_path).read_text().strip()
            log.error(f"Connector already running (PID {pid}). Aborting.")
        except Exception:
            log.error("Connector already running. Aborting.")
        return None


async def main():
    config = load_config()
    upload_dir = Path(config["upload_dir"])
    upload_dir.mkdir(parents=True, exist_ok=True)
    # Restrict to connector user — uploads may contain sensitive files
    try:
        os.chmod(str(upload_dir), 0o700)
    except OSError:
        pass

    # Lock file — only one instance
    lock_path = Path(config.get("upload_dir", "/opt/aiterm")).parent / "connector.lock"
    lock = acquire_lock(str(lock_path))
    if not lock:
        sys.exit(1)

    hostname = platform.node()
    print(flush=True)
    print("  ┌───────────────────────────────────────────────┐", flush=True)
    print("  │       AITerm Connector                        │", flush=True)
    print("  ├───────────────────────────────────────────────┤", flush=True)
    print(f"  │  Host:     {hostname:<36}│", flush=True)
    print(f"  │  Version:  {CONNECTOR_VERSION:<36}│", flush=True)

    stop = asyncio.Future()
    loop = asyncio.get_event_loop()
    def handle_signal():
        if not stop.done():
            stop.set_result(None)
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, handle_signal)

    # Push mode (connect outbound to hub)
    if not config.get("hub_url") or not config.get("hub_token"):
        log.error("hub_url and hub_token required in connector.json")
        print("  ERROR: No hub_url/hub_token configured.", flush=True)
        print("  Run the installer: curl -sL https://aiterm.io/install | bash", flush=True)
        return

    # Honeytokens: deployment happens at install time (see install.sh), which
    # runs as root without systemd's ProtectHome restriction. The connector
    # only watches pre-deployed paths via os.stat (works on read-only mounts).
    if config.get("honeytokens_enabled", True) and config.get("_honeytoken_paths"):
        print(f"  │  Honeytokens: watching {len(config['_honeytoken_paths']):<23}│", flush=True)

    mode_str = "push → " + config["hub_url"]
    print(f"  │  Hub:      {mode_str:<36}│", flush=True)
    print("  └───────────────────────────────────────────────┘", flush=True)
    print(flush=True)
    push_task = asyncio.create_task(push_to_hub(config))
    await stop
    push_task.cancel()

    print("\n  Shutdown.", flush=True)


def self_update():
    """Download latest files with hash verification."""
    import hashlib as _hl
    import ssl
    import urllib.request

    install_dir = Path(__file__).parent
    config_path = install_dir / "connector.json"

    update_base = "https://www.aiterm.io/dl"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text())
            hub_url = cfg.get("hub_url", "")
            if "aiterm.io" not in hub_url and "127.0.0.1" not in hub_url:
                from urllib.parse import urlparse
                parsed = urlparse(hub_url.replace("ws://", "http://").replace("wss://", "https://"))
                update_base = f"https://{parsed.hostname}/dl"
        except Exception:
            pass

    ctx = ssl.create_default_context()

    # Download manifest + Ed25519 signature; verify before trusting any hash.
    print("\n  AITerm Connector Update\n")
    manifest_bytes = b""
    sig_hex = ""
    try:
        req = urllib.request.Request(f"{update_base}/manifest.json")
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            manifest_bytes = resp.read()
        req = urllib.request.Request(f"{update_base}/manifest.sig")
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            sig_hex = resp.read().decode().strip()
    except Exception as e:
        print(f"  \033[0;31m✗\033[0m Failed to fetch manifest/signature: {e}")
        return 1

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(MANIFEST_PUBKEY_HEX))
        pubkey.verify(bytes.fromhex(sig_hex), manifest_bytes)
    except ImportError:
        print("  \033[0;31m✗\033[0m cryptography module required for signature verification")
        return 1
    except Exception:
        print("  \033[0;31m✗\033[0m MANIFEST SIGNATURE INVALID — update rejected")
        return 1
    print("  \033[0;32m✓\033[0m Manifest signature verified")

    try:
        manifest = json.loads(manifest_bytes)
    except Exception as e:
        print(f"  \033[0;31m✗\033[0m Malformed manifest: {e}")
        return 1

    if not manifest:
        print("  \033[0;31m✗\033[0m Empty manifest — aborting")
        return 1

    # Detect bin dir
    bin_dir = Path("/usr/local/bin")
    if not bin_dir.exists() or not os.access(str(bin_dir), os.W_OK):
        bin_dir = Path.home() / ".local" / "bin"

    files = [
        ("connector.py", install_dir / "connector.py"),
        ("pty-manager.py", install_dir / "pty-manager.py"),
        ("session_daemon.py", install_dir / "session_daemon.py"),
        ("registry_loader.py", install_dir / "registry_loader.py"),
        ("doctor.py", install_dir / "doctor.py"),
        ("ai-registry.json", install_dir / "ai-registry.json"),
        ("guard-patterns.json", install_dir / "guard-patterns.json"),
        ("doctor-checks.json", install_dir / "doctor-checks.json"),
        ("aiterm", bin_dir / "aiterm"),
    ]

    for fname, target in files:
        expected_hash = manifest.get(fname)
        if not expected_hash:
            print(f"  \033[2m· {fname}: not in manifest, skipping\033[0m")
            continue

        url = f"{update_base}/{fname}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                new_data = resp.read()

            # Verify SHA-256 hash
            actual_hash = _hl.sha256(new_data).hexdigest()
            if actual_hash != expected_hash:
                print(f"  \033[0;31m✗\033[0m {fname}: HASH MISMATCH — file rejected")
                print(f"    Expected: {expected_hash[:16]}...")
                print(f"    Got:      {actual_hash[:16]}...")
                return 1

            if not new_data or len(new_data) < 100:
                print(f"  \033[0;31m✗\033[0m {fname}: too small — rejected")
                continue

            old_data = target.read_bytes() if target.exists() else b""
            if new_data == old_data:
                print(f"  \033[2m· {fname}: already up to date\033[0m")
            else:
                target.write_bytes(new_data)
                target.chmod(0o755)
                print(f"  \033[0;32m✓\033[0m {fname}: updated ({len(new_data)} bytes, hash verified)")
        except Exception as e:
            print(f"  \033[0;31m✗\033[0m {fname}: {e}")
            return 1

    # Restart services if systemd is available
    print()
    for svc in ["aiterm-connector", "aiterm-pty"]:
        try:
            r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5)
            if r.stdout.strip() == "active":
                subprocess.run(["systemctl", "restart", svc], timeout=10)
                print(f"  \033[0;32m✓\033[0m {svc} neugestartet")
        except Exception:
            pass

    print("\n  Fertig.\n")
    return 0


if __name__ == "__main__":
    if "--scan" in sys.argv:
        print_scan(scan())
        sys.exit(0)
    if "--update" in sys.argv:
        sys.exit(self_update())
    if "--deploy-honeytokens" in sys.argv:
        # Run at install time (as root, outside systemd hardening) to lay down
        # decoy files and write their paths to connector.json for the watcher.
        paths = deploy_honeytokens()
        print(f"Deployed {len(paths)} honeytoken(s):", flush=True)
        for p in paths:
            print(f"  • {p}", flush=True)
        if CONFIG_PATH.exists():
            try:
                cfg = json.load(open(CONFIG_PATH))
                cfg["_honeytoken_paths"] = paths
                cfg.setdefault("honeytokens_enabled", True)
                with open(CONFIG_PATH, "w") as f:
                    json.dump(cfg, f, indent=2)
                os.chmod(CONFIG_PATH, 0o600)
                print(f"Paths recorded in {CONFIG_PATH}", flush=True)
            except Exception as e:
                print(f"WARN: could not write connector.json: {e}", flush=True)
        sys.exit(0)
    asyncio.run(main())
