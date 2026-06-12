#!/usr/bin/env python3
"""AITerm Windows Connector (M1).

Single-process variant: owns PTY sessions directly (no separate pty-manager).
Protocol on the wire is byte-identical to the Linux connector so the hub
needs zero changes.

Differences vs Linux:
  - ConPTY via pywinpty instead of os.pty.fork + termios
  - PTY I/O via reader threads pushing to asyncio.Queue (ConPTY has no
    pollable fd in the Unix sense)
  - Sessions die when the connector restarts (M2 introduces detached
    spawn so they survive)
  - Cert pinning, manifest-signed updates, honeytokens deferred to M2/M3
  - Windows binary search paths (Program Files, AppData, npm) instead of
    /usr/local/bin

Minimum Windows: Win10 build 17763 (1809) — ConPTY requirement.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import platform
import shutil
import ssl
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

# pywinpty is only available on Windows. Import lazily so this file is
# inspectable / lintable on Linux dev hosts (the public mirror keeps both
# variants side by side and people will read both).
if platform.system() == "Windows":
    try:
        import winpty  # pywinpty package
    except ImportError:
        winpty = None
else:
    winpty = None

try:
    import websockets
except ImportError:
    websockets = None

# ─── Constants ─────────────────────────────────────────────────────────
CONNECTOR_VERSION = "2026.05.18.win.m1"
DEFAULT_HUB_URL = "wss://www.aiterm.io/connector"
DEFAULT_API_URL = "https://www.aiterm.io"

# Per-user install dir on Windows. We mirror the Unix layout
# (one self-contained tree) but rooted at %LOCALAPPDATA%.
INSTALL_DIR = Path(os.environ.get("AITERM_INSTALL_DIR",
    os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) ) / "AITerm"
CONFIG_PATH = INSTALL_DIR / "connector.json"
CERT_PIN_PATH = INSTALL_DIR / ".cert_pin"
LOG_PATH = INSTALL_DIR / "connector.log"

# Output framing: pywinpty emits text; the hub expects raw bytes base64-
# encoded. We round-trip through UTF-8.
PTY_READ_CHUNK = 4096

# ─── Logging ───────────────────────────────────────────────────────────
log = logging.getLogger("connector-win")


def _setup_logging(verbose=False):
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(str(LOG_PATH), encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(handler)
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(stream)
    log.setLevel(logging.DEBUG if verbose else logging.INFO)


# ─── Config ────────────────────────────────────────────────────────────
def load_config():
    if not CONFIG_PATH.exists():
        log.error(f"No config at {CONFIG_PATH}. Run --pair first or copy connector.json.example.")
        sys.exit(2)
    # utf-8-sig tolerates a leading BOM — PowerShell 5.1's default UTF8
    # writer prepends one, and older connector.json files from pre-2026-05-19
    # installs may still have it.
    with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
        cfg = json.load(f)
    cfg.setdefault("hub_url", DEFAULT_HUB_URL)
    cfg.setdefault("name", platform.node())
    cfg.setdefault("default_cwd", str(Path.home()))
    return cfg


# ─── Windows-specific AI scan ──────────────────────────────────────────
def _expand(p):
    return os.path.expandvars(os.path.expanduser(p))


def _which(binary):
    """Like shutil.which but also tries .exe / .cmd / .bat suffixes."""
    for suffix in ("", ".exe", ".cmd", ".bat"):
        hit = shutil.which(binary + suffix)
        if hit:
            return hit
    return None


def _windows_ai_paths():
    """Standard Windows install locations to probe for AI binaries.
    Returned as a dict keyed by AI id; values are lists of candidate paths.
    Used by scan() — not by start_ai (we re-resolve at spawn time).

    Kept in code (not registry) because Windows paths are intrinsically
    Windows-shaped: %LOCALAPPDATA%, %ProgramFiles%, npm-global dir, etc.
    The registry stays platform-agnostic for the message-level fields
    (label, icon, args)."""
    appdata = os.environ.get("APPDATA", "")
    local = os.environ.get("LOCALAPPDATA", "")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    home = str(Path.home())
    return {
        "claude": [
            _which("claude"),
            os.path.join(appdata, "npm", "claude.cmd"),
            os.path.join(appdata, "npm", "claude.exe"),
            os.path.join(home, ".local", "bin", "claude.exe"),
            os.path.join(local, "Programs", "claude", "claude.exe"),
        ],
        "ollama": [
            _which("ollama"),
            os.path.join(local, "Programs", "Ollama", "ollama.exe"),
            os.path.join(pf, "Ollama", "ollama.exe"),
        ],
        "lmstudio": [
            os.path.join(local, "LMStudio", "LM Studio.exe"),
            os.path.join(pf, "LM Studio", "LM Studio.exe"),
        ],
        "llamacpp": [
            _which("llama-server"),
            _which("llama-cli"),
        ],
        "gpt4all": [
            os.path.join(pf, "GPT4All", "bin", "chat.exe"),
            os.path.join(pf86, "GPT4All", "bin", "chat.exe"),
        ],
    }


def _proc_running_win(name_substrings):
    """Check tasklist for any process whose ImageName contains any substring.
    Returns (running, pid)."""
    try:
        r = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return False, None
        for line in r.stdout.splitlines():
            # CSV line: "imagename.exe","pid","Session","Num","Mem K"
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) < 2:
                continue
            img = parts[0].lower()
            for ss in name_substrings:
                if ss.lower() in img:
                    try:
                        return True, int(parts[1])
                    except (ValueError, IndexError):
                        return True, None
    except Exception as e:
        log.debug(f"tasklist probe failed: {e}")
    return False, None


def scan():
    """Detect available AI backends + system metadata. Schema matches Linux
    scan() so the dashboard renders identically."""
    info = {
        "hostname": platform.node() or "unknown",
        "user": os.environ.get("USERNAME") or "unknown",
        "home": str(Path.home()),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "arch": platform.machine(),
        "claude_path": None,
        "claude_version": None,
        "websockets_ok": websockets is not None,
        "winpty_ok": winpty is not None,
        "os": "windows",
    }

    ai_paths = _windows_ai_paths()

    # Claude
    for p in ai_paths["claude"]:
        if p and os.path.isfile(p):
            info["claude_path"] = p
            break
    if info["claude_path"]:
        try:
            r = subprocess.run(
                [info["claude_path"], "--version"],
                capture_output=True, text=True, timeout=10
            )
            v = (r.stdout or r.stderr).strip().split("\n")[0]
            info["claude_version"] = v if v and len(v) < 80 else "installed"
        except Exception:
            info["claude_version"] = "installed"

    # Build AI dict (same schema as Linux scan output)
    ai = {}
    if info["claude_path"]:
        running, pid = _proc_running_win(["claude.exe", "claude.cmd"])
        ai["claude"] = {
            "path": info["claude_path"],
            "version": info["claude_version"] or "unknown",
            "running": running,
            "pid": pid,
        }

    for p in ai_paths["ollama"]:
        if p and os.path.isfile(p):
            running, pid = _proc_running_win(["ollama.exe"])
            try:
                vr = subprocess.run([p, "--version"], capture_output=True, text=True, timeout=10)
                version = (vr.stdout or vr.stderr).strip().split("\n")[0][:80]
            except Exception:
                version = "installed"
            # Ollama model list (best-effort)
            models = []
            try:
                lr = subprocess.run([p, "list"], capture_output=True, text=True, timeout=8)
                for line in lr.stdout.splitlines()[1:]:
                    name = line.split()[0] if line.split() else ""
                    if name and name != "NAME":
                        models.append(name)
            except Exception:
                pass
            ai["ollama"] = {"path": p, "version": version, "running": running,
                            "pid": pid, "models": models}
            break

    for p in ai_paths["llamacpp"]:
        if p and os.path.isfile(p):
            ai["llamacpp"] = {"path": p, "version": "installed", "running": False}
            break

    for p in ai_paths["lmstudio"]:
        if os.path.isfile(p):
            ai["lmstudio"] = {"path": p, "version": "installed", "running": False}
            break

    info["ai"] = ai
    return info


# ─── PTY session wrapper ───────────────────────────────────────────────
class WinPtySession:
    """A single ConPTY-backed AI session. Holds a pywinpty PtyProcess and a
    reader thread that ferries output into an asyncio.Queue."""

    def __init__(self, sid, ai_type, name, cmd, cwd, rows, cols, loop, out_queue):
        self.sid = sid
        self.ai_type = ai_type
        self.name = name
        self.cwd = cwd
        self.started_at = time.time()
        self.loop = loop
        self.out_queue = out_queue
        self._stop_evt = threading.Event()

        if winpty is None:
            raise RuntimeError("pywinpty not available — install with: pip install pywinpty")

        # winpty.PtyProcess.spawn accepts a single command line string OR
        # an argv list depending on the version. We pass a list and let
        # pywinpty join it (it uses shlex.join semantics on Windows).
        # cwd is honored; env defaults to inherited.
        self.pty = winpty.PtyProcess.spawn(
            cmd,
            cwd=cwd,
            dimensions=(rows, cols),
        )
        log.info(f"[{sid}] spawned {ai_type} pid={self.pty.pid} cwd={cwd}")

        self._reader = threading.Thread(target=self._read_loop, daemon=True,
                                         name=f"pty-reader-{sid}")
        self._reader.start()

    def _read_loop(self):
        """Blocking-read pywinpty output on a dedicated thread; hand chunks
        to the asyncio loop via a thread-safe call_soon."""
        try:
            while not self._stop_evt.is_set():
                try:
                    data = self.pty.read(PTY_READ_CHUNK)
                except (EOFError, OSError):
                    break
                if not data:
                    # Heuristic: tight-loop guard if pywinpty returns empty
                    # without raising. Sleep briefly to avoid CPU spin.
                    if not self.pty.isalive():
                        break
                    time.sleep(0.02)
                    continue
                # pywinpty returns str; encode to bytes for the hub
                if isinstance(data, str):
                    data_b = data.encode("utf-8", errors="replace")
                else:
                    data_b = data
                payload = {"t": "o", "sid": self.sid,
                           "d": base64.b64encode(data_b).decode("ascii")}
                self.loop.call_soon_threadsafe(self.out_queue.put_nowait, payload)
        finally:
            log.info(f"[{self.sid}] reader thread exiting (alive={self._alive_safe()})")
            self.loop.call_soon_threadsafe(self.out_queue.put_nowait,
                                            {"t": "stopped", "sid": self.sid})

    def _alive_safe(self):
        try:
            return self.pty.isalive()
        except Exception:
            return False

    def write(self, data_bytes):
        """Send input to the PTY. Writes happen from the asyncio thread —
        pywinpty serializes writes internally."""
        if isinstance(data_bytes, bytes):
            self.pty.write(data_bytes.decode("utf-8", errors="replace"))
        else:
            self.pty.write(data_bytes)

    def resize(self, rows, cols):
        try:
            self.pty.setwinsize(rows, cols)
        except Exception as e:
            log.warning(f"[{self.sid}] resize failed: {e}")

    def terminate(self):
        self._stop_evt.set()
        try:
            self.pty.terminate(force=True)
        except Exception as e:
            log.debug(f"[{self.sid}] terminate raised (already dead?): {e}")


class SessionRegistry:
    """All live sessions on this connector, keyed by sid."""

    def __init__(self):
        self.sessions = {}  # sid -> WinPtySession
        self._lock = threading.Lock()

    def add(self, sess):
        with self._lock:
            self.sessions[sess.sid] = sess

    def get(self, sid):
        with self._lock:
            return self.sessions.get(sid)

    def remove(self, sid):
        with self._lock:
            return self.sessions.pop(sid, None)

    def all(self):
        with self._lock:
            return list(self.sessions.values())


# ─── AI launch ─────────────────────────────────────────────────────────
def scan_project_dirs_windows(max_results=25):
    """Find directories that look like Claude-ready projects.

    Mirrors the Linux scan_project_dirs(): each entry is
    {"path": str, "signatures": [str, ...]}. Signatures detected:
    CLAUDE.md, .mcp.json, .claude/settings.json, .claude/settings.local.json.

    Walks the conventional Windows project locations only — we deliberately
    avoid os.walk on the full %USERPROFILE% because it would dive into
    AppData, OneDrive caches etc. and cost seconds on every CWD-picker open.
    """
    home  = str(Path.home())
    roots = [
        (home,                                    2),   # top of homedir
        (os.path.join(home, "Documents"),         5),
        (os.path.join(home, "Desktop"),           3),
        (os.path.join(home, "Projects"),          5),
        (os.path.join(home, "source"),            5),   # VS default for git repos
        (os.path.join(home, "source", "repos"),   5),
        (os.path.join(home, "dev"),               5),
        (os.path.join(home, "code"),              5),
        (os.path.join(home, "git"),               5),
        (os.path.join(home, "workspace"),         5),
        ("C:\\dev",                                5),
        ("C:\\projects",                           5),
    ]
    skip_names = {
        "node_modules", ".git", ".venv", "venv", "__pycache__",
        "target", "dist", "build", ".next", ".nuxt", "bin", "obj",
        "AppData", "OneDrive", "$RECYCLE.BIN", "System Volume Information",
    }
    found = {}

    def _mark(path, sig):
        if not path:
            return
        found.setdefault(path, set()).add(sig)

    for root, max_depth in roots:
        if not os.path.isdir(root):
            continue
        root_depth = root.count(os.sep)
        try:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                rel_depth = dirpath.count(os.sep) - root_depth
                if rel_depth >= max_depth:
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in skip_names]
                if "CLAUDE.md" in filenames:
                    _mark(dirpath, "CLAUDE.md")
                if ".mcp.json" in filenames:
                    _mark(dirpath, ".mcp.json")
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
        if os.path.basename(p) != ".claude"
    ]


def run_doctor_windows():
    """Built-in diagnostic check set for Windows. No external doctor.py;
    returns a dict matching the dashboard's expected schema:
    {"distro": {...}, "checks": [{"id","name","summary","severity",
                                  "why" (opt), "fix" (opt)}]}.

    severity in {"ok", "warn", "crit"}.
    """
    checks = []

    def add(cid, name, summary, severity, why=None, fix=None):
        c = {"id": cid, "name": name, "summary": summary, "severity": severity}
        if why: c["why"] = why
        if fix: c["fix"] = fix
        checks.append(c)

    # Python version
    pv = sys.version_info
    if pv >= (3, 10):
        add("python", "Python version", f"{pv.major}.{pv.minor}.{pv.micro}", "ok")
    else:
        add("python", "Python version", f"{pv.major}.{pv.minor}.{pv.micro}", "warn",
            why="AITerm targets Python 3.10+",
            fix="winget install Python.Python.3.11")

    # Critical deps
    if winpty is not None:
        add("pywinpty", "pywinpty (ConPTY wrapper)", "installed", "ok")
    else:
        add("pywinpty", "pywinpty (ConPTY wrapper)", "missing", "crit",
            why="Required to spawn AI sessions with terminal semantics",
            fix="pip install pywinpty")

    if websockets is not None:
        add("websockets", "websockets (hub transport)", f"v{getattr(websockets,'__version__','?')}", "ok")
    else:
        add("websockets", "websockets (hub transport)", "missing", "crit",
            why="Required to connect to the hub",
            fix="pip install websockets")

    # Windows build
    build = sys.getwindowsversion().build if hasattr(sys, "getwindowsversion") else 0
    if build >= 17763:
        add("conpty", "Windows build", f"build {build} (ConPTY supported)", "ok")
    elif build:
        add("conpty", "Windows build", f"build {build} — too old", "crit",
            why="ConPTY requires Windows 10 build 17763 (1809) or newer.")
    else:
        add("conpty", "Windows build", "could not determine — likely not Windows", "warn")

    # AI binaries
    ai_paths = _windows_ai_paths()
    claude_hit = next((p for p in ai_paths["claude"] if p and os.path.isfile(p)), None)
    if claude_hit:
        add("claude", "Claude Code", claude_hit, "ok")
    else:
        add("claude", "Claude Code", "not installed", "warn",
            why="No AI to talk to yet — install one or more backends.",
            fix="npm install -g @anthropic-ai/claude-code  (needs Node.js)")
    ollama_hit = next((p for p in ai_paths["ollama"] if p and os.path.isfile(p)), None)
    if ollama_hit:
        add("ollama", "Ollama", ollama_hit, "ok")
    else:
        add("ollama", "Ollama", "not installed", "warn",
            fix="winget install Ollama.Ollama")

    # Config
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                cfg = json.load(f)
            if cfg.get("hub_token"):
                add("config", "Connector config", str(CONFIG_PATH), "ok")
            else:
                add("config", "Connector config", "no hub_token", "crit",
                    fix="iwr -useb https://aiterm.io/install.ps1 | iex")
        except Exception as e:
            add("config", "Connector config", f"unreadable: {e}", "crit")
    else:
        add("config", "Connector config", "missing", "crit",
            fix="iwr -useb https://aiterm.io/install.ps1 | iex")

    # Log file
    if LOG_PATH.exists():
        size = LOG_PATH.stat().st_size
        sev = "warn" if size > 50_000_000 else "ok"
        add("log", "Connector log", f"{size//1024} KB at {LOG_PATH}", sev,
            why="Log over 50 MB — consider rotating." if sev == "warn" else None)
    else:
        add("log", "Connector log", "no log yet", "warn")

    return {
        "distro": {"id": "windows", "family": "windows", "pkg": "winget"},
        "checks": checks,
    }


def _resolve_ai_command(ai_type, cwd):
    """Map an AI identifier (e.g. 'claude', 'ollama', 'ollama:llama3', 'bash')
    to a command list suitable for winpty.PtyProcess.spawn. Returns
    (cmd_list, friendly_name) or (None, error_message)."""
    ai_paths = _windows_ai_paths()
    base = ai_type.split(":", 1)[0]

    if base == "bash":
        # Windows has no /bin/bash; fall back to pwsh, powershell, then cmd.
        for shell in ("pwsh.exe", "powershell.exe", "cmd.exe"):
            p = _which(shell.replace(".exe", ""))
            if p:
                return [p], shell
        return None, "no shell found"

    if base == "claude":
        for p in ai_paths["claude"]:
            if p and os.path.isfile(p):
                return [p], "Claude Code"
        return None, "claude not installed"

    if base == "ollama":
        for p in ai_paths["ollama"]:
            if p and os.path.isfile(p):
                if ":" in ai_type:
                    model = ai_type.split(":", 1)[1]
                    return [p, "run", model], f"Ollama: {model}"
                return [p], "Ollama"
        return None, "ollama not installed"

    if base == "llamacpp":
        for p in ai_paths["llamacpp"]:
            if p and os.path.isfile(p):
                return [p], "llama.cpp"
        return None, "llama.cpp not installed"

    return None, f"unknown ai: {ai_type}"


# ─── Hub WebSocket loop ────────────────────────────────────────────────
async def hub_loop(config):
    if websockets is None:
        log.error("websockets package missing — pip install websockets")
        sys.exit(2)
    if winpty is None:
        log.error("pywinpty missing or not on Windows — pip install pywinpty")
        sys.exit(2)

    registry = SessionRegistry()
    out_queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    auth_fail_count = 0

    # SSL: stdlib defaults are fine for wss:// to aiterm.io (Let's Encrypt
    # via the system trust store). Pinning deferred to M2.
    ssl_ctx = ssl.create_default_context()

    while True:
        try:
            async with websockets.connect(
                config["hub_url"],
                ssl=ssl_ctx,
                max_size=25 * 1024 * 1024,
                ping_interval=30,
                ping_timeout=10,
            ) as ws:
                log.info(f"WS connected to {config['hub_url']}")

                # Auth
                await ws.send(json.dumps({"t": "auth", "token": config["hub_token"]}))
                resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
                if not resp.get("ok"):
                    auth_fail_count += 1
                    backoff = min(30 * (2 ** (auth_fail_count - 1)), 1800)
                    log.error(f"Hub auth failed (#{auth_fail_count}). "
                              f"Token likely revoked — re-pair to fix. "
                              f"Retry in {backoff}s.")
                    await asyncio.sleep(backoff)
                    continue
                auth_fail_count = 0

                # Send info + initial scan + install context (lets the hub
                # distinguish system-wide vs per-user installs that share a
                # hostname, same as on Linux).
                initial_scan = scan().get("ai", {})
                _run_user = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
                _pf = os.environ.get("ProgramFiles") or ""
                _is_system = bool(_pf) and str(INSTALL_DIR).lower().startswith(_pf.lower())
                _install_mode = "system" if _is_system else "user"
                await ws.send(json.dumps({
                    "t": "info",
                    "name": config.get("name", platform.node()),
                    "version": CONNECTOR_VERSION,
                    "scan": initial_scan,
                    "os": "windows",
                    "install_mode": _install_mode,
                    "run_user": _run_user,
                    "install_dir": str(INSTALL_DIR),
                }))
                log.info(f"Registered as '{config.get('name')}' "
                         f"v{CONNECTOR_VERSION} ({len(initial_scan)} AIs)")

                # Run two tasks: hub→sessions (input/control) and
                # sessions→hub (drain out_queue).
                sender_task = asyncio.ensure_future(_sender_loop(ws, out_queue))
                try:
                    await _receiver_loop(ws, registry, out_queue, loop)
                finally:
                    sender_task.cancel()
                    # Reap all sessions on disconnect to avoid orphan PTYs
                    for sess in registry.all():
                        sess.terminate()
                        registry.remove(sess.sid)
        except (websockets.ConnectionClosed, OSError, ConnectionError) as e:
            log.warning(f"WS dropped: {e}. Reconnecting in 5s.")
            await asyncio.sleep(5)
        except Exception as e:
            log.exception(f"WS loop unexpected error: {e}")
            await asyncio.sleep(15)


async def _sender_loop(ws, out_queue):
    """Drain out_queue (filled by PTY reader threads) and push to hub."""
    while True:
        msg = await out_queue.get()
        try:
            await ws.send(json.dumps(msg))
        except Exception as e:
            log.warning(f"send failed: {e}")
            return


async def _receiver_loop(ws, registry, out_queue, loop):
    """Read messages from hub and dispatch."""
    async for raw in ws:
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except Exception:
            log.debug(f"non-JSON frame ({len(raw)} bytes), ignoring")
            continue
        t = msg.get("t")
        sid = msg.get("sid")

        if t == "i" and sid:
            sess = registry.get(sid)
            if sess:
                try:
                    data = base64.b64decode(msg.get("d", ""))
                    sess.write(data)
                except Exception as e:
                    log.warning(f"[{sid}] input write failed: {e}")

        elif t == "r" and sid:
            sess = registry.get(sid)
            if sess:
                sess.resize(int(msg.get("rows", 30)), int(msg.get("cols", 120)))

        elif t == "start_ai":
            ai_type = msg.get("ai", "")
            cwd = msg.get("cwd", str(Path.home()))
            sid_new = msg.get("sid") or uuid.uuid4().hex[:12]
            await _handle_start(ws, registry, out_queue, loop, sid_new, ai_type, cwd, msg)

        elif t == "stop_ai" and sid:
            sess = registry.remove(sid)
            if sess:
                sess.terminate()
                await ws.send(json.dumps({"t": "stopped", "sid": sid}))

        elif t == "kill_all":
            for sess in registry.all():
                sess.terminate()
                registry.remove(sess.sid)
            await ws.send(json.dumps({"t": "killed_all"}))

        elif t == "scan":
            result = scan()
            await ws.send(json.dumps({"t": "scan_result", "scan": result.get("ai", {})}))

        elif t == "list_project_dirs":
            try:
                dirs = scan_project_dirs_windows()
            except Exception as e:
                log.warning(f"scan_project_dirs_windows failed: {e}")
                dirs = []
            await ws.send(json.dumps({
                "t": "project_dirs",
                "default": str(Path.home()),
                "dirs": dirs,
            }))

        elif t == "run_doctor":
            try:
                report = run_doctor_windows()
            except Exception as e:
                log.exception("run_doctor_windows raised")
                report = {"error": f"doctor failed: {e}"}
            await ws.send(json.dumps({"t": "doctor_result", "report": report}))

        elif t == "remote_update":
            # M1: not implemented; tell hub so dashboard doesn't hang forever.
            await ws.send(json.dumps({"t": "update_status", "status": "error",
                                       "m": "Auto-update not yet implemented in Windows M1"}))

        elif t == "remote_uninstall":
            # M1: also not implemented (no installer yet)
            await ws.send(json.dumps({"t": "uninstall_status", "status": "error",
                                       "m": "Uninstaller not yet implemented in Windows M1"}))

        elif t == "u":
            # File upload — M1 skips (no upload dir handling yet).
            await ws.send(json.dumps({"t": "err", "m": "Upload not yet implemented on Windows"}))

        # else: silently ignore unknown types (forward-compat)


async def _handle_start(ws, registry, out_queue, loop, sid, ai_type, cwd, msg):
    """Spawn a new AI session."""
    cmd, friendly = _resolve_ai_command(ai_type, cwd)
    if cmd is None:
        await ws.send(json.dumps({"t": "err", "m": f"start_ai failed: {friendly}"}))
        return
    if not os.path.isdir(cwd):
        await ws.send(json.dumps({"t": "err",
                                    "m": f"cwd does not exist: {cwd}"}))
        return
    rows = int(msg.get("rows", 30))
    cols = int(msg.get("cols", 120))
    try:
        sess = WinPtySession(sid, ai_type, friendly, cmd, cwd, rows, cols,
                             loop, out_queue)
    except Exception as e:
        log.exception(f"spawn failed for {ai_type}")
        await ws.send(json.dumps({"t": "err", "m": f"spawn failed: {e}"}))
        return
    registry.add(sess)
    await ws.send(json.dumps({"t": "started", "sid": sid, "ai": ai_type,
                                "name": friendly, "cwd": cwd}))


# ─── Pairing flow (manual M1 — full PowerShell installer comes in M2) ──
def pair_interactive(api_url=DEFAULT_API_URL):
    """Stand-in for install.ps1's pairing flow.

    Prints a pair URL, polls /api/pairing/status, writes connector.json.
    Use this once on a fresh Windows box; afterwards run without --pair."""
    import urllib.request
    import urllib.parse
    hostname = platform.node()
    body = json.dumps({"hostname": hostname}).encode()
    req = urllib.request.Request(f"{api_url}/api/pairing/request", data=body,
                                   headers={"Content-Type": "application/json"},
                                   method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read())
    except Exception as e:
        print(f"FATAL: pairing request failed: {e}", file=sys.stderr)
        sys.exit(1)
    if not resp.get("ok"):
        print(f"FATAL: pairing request rejected: {resp}", file=sys.stderr)
        sys.exit(1)
    code = resp["code"]
    pair_url = f"{api_url}/pair/{code}"
    print("")
    print("  ┌────────────────────────────────────────────────────────────────┐")
    print("  │                                                                │")
    print(f"  │  Open this link in your browser:                              │")
    print(f"  │                                                                │")
    print(f"  │    {pair_url:<60}│")
    print("  │                                                                │")
    print("  │  Sign in and confirm. This terminal is waiting.               │")
    print("  │                                                                │")
    print("  └────────────────────────────────────────────────────────────────┘")
    print("")

    token = None
    for poll in range(360):  # 1 hour
        time.sleep(10)
        try:
            with urllib.request.urlopen(f"{api_url}/api/pairing/status?code={code}", timeout=10) as r:
                pr = json.loads(r.read())
        except Exception as e:
            print(f"  poll error: {e}")
            continue
        if pr.get("status") == "confirmed":
            token = pr.get("token", "")
            break
        if pr.get("status") == "expired":
            print("Pair code expired. Re-run --pair.")
            sys.exit(1)
        sys.stdout.write(f"\r  Waiting for confirmation... ({(poll+1)*10}/3600)")
        sys.stdout.flush()
    if not token:
        print("\nTimeout. No confirmation.")
        sys.exit(1)
    print("\nPaired!")

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    cfg = {
        "hub_url": DEFAULT_HUB_URL,
        "hub_token": token,
        "name": hostname,
        "default_cwd": str(Path.home()),
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    # Best-effort permissions hardening (Windows ACLs ≠ POSIX, but icacls
    # works in M2's install.ps1; for the M1 manual path the user is admin).
    print(f"Config written to {CONFIG_PATH}")
    print(f"Now run:  python connector-win.py")


# ─── Entrypoint ────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="AITerm Windows Connector (M1)")
    p.add_argument("--pair", action="store_true",
                    help="Run the interactive pairing flow and write connector.json")
    p.add_argument("--scan", action="store_true",
                    help="Print local scan result as JSON and exit")
    p.add_argument("--version", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    _setup_logging(verbose=args.verbose)

    if args.version:
        print(CONNECTOR_VERSION)
        return

    if args.scan:
        print(json.dumps(scan(), indent=2, default=str))
        return

    if args.pair:
        pair_interactive()
        return

    config = load_config()
    log.info(f"AITerm Connector (Windows) v{CONNECTOR_VERSION} starting")
    log.info(f"Install dir: {INSTALL_DIR}")
    log.info(f"Hub URL: {config['hub_url']}")

    try:
        asyncio.run(hub_loop(config))
    except KeyboardInterrupt:
        log.info("Shutdown by user.")


if __name__ == "__main__":
    main()
