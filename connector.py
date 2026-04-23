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

    # Multi-AI detection (minimal checks, details handled server-side)
    ai = {}
    if info["claude_path"]:
        running, _ = _proc_running(["claude --chat", "claude chat", "claude -c"])
        ai["claude"] = {"path": info["claude_path"], "version": info.get("claude_version", ""), "running": running}
    if shutil.which("ollama"):
        v = ""
        try:
            env = os.environ.copy()
            env.setdefault("HOME", os.path.expanduser("~"))
            r = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5, env=env)
            v = r.stdout.strip()
            # Ignore crash output
            if not v or len(v) > 50 or "panic" in v.lower():
                v = "installed"
        except Exception:
            v = "installed"
        # Get installed models
        models = []
        try:
            env = os.environ.copy()
            env.setdefault("HOME", os.path.expanduser("~"))
            r2 = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=10, env=env)
            for line in r2.stdout.strip().split("\n")[1:]:  # skip header
                parts = line.split()
                if parts:
                    models.append(parts[0])  # model name like "llama3:latest"
        except Exception:
            pass
        running, _ = _proc_running(["ollama serve", "ollama run"])
        ai["ollama"] = {"version": v, "models": models, "running": running}
    for tool in ("llama-server", "llama-cli"):
        p = shutil.which(tool)
        if p:
            running, _ = _proc_running(["llama-server", "llama-cli"])
            ai["llamacpp"] = {"path": p, "running": running}
            break
    if shutil.which("local-ai"):
        running, _ = _proc_running(["local-ai"])
        ai["localai"] = {"path": shutil.which("local-ai"), "running": running}
    if shutil.which("gpt4all"):
        running, _ = _proc_running(["gpt4all"])
        ai["gpt4all"] = {"path": shutil.which("gpt4all"), "running": running}
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

# ─── PTY Manager Relay ────────────────────────────────────────
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
    """Connect to hub, relay to PTY manager. Connector is thin."""
    hub_url = config["hub_url"]
    hub_token = config["hub_token"]
    upload_dir = Path(config["upload_dir"])

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
                    log.error("Hub auth failed")
                    await asyncio.sleep(30)
                    continue

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
    asyncio.run(main())
