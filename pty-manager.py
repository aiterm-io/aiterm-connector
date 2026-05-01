#!/usr/bin/env python3
"""
AITerm PTY Manager - Multi-Session
====================================
Manages multiple AI terminal sessions. Survives connector restarts.
Connector connects via Unix socket and relays commands from the hub.

Protocol: newline-delimited JSON over Unix socket.
"""

import asyncio
import base64
import json
import logging
import os
import re
import shutil
import signal
import struct

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCROLLBACK_MAX = 200 * 1024  # 200KB per session
SOCKET_PATH = os.path.join(BASE_DIR, "pty.sock")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [pty-mgr] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("pty-mgr")


_ENV_ALLOWED = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD",
    "TERM", "COLORTERM",
    "LANG", "LANGUAGE", "TZ",
    "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
}


# ─── Guard Mode: dangerous-command pattern list ──────────────
# Open source by design — defense relies on human-in-the-loop, not obscurity.
# Only triggers for bash sessions where the machine has guard_enabled=True.
# Guard patterns are loaded from guard-patterns.json (single source of truth).
# Each entry is (compiled_regex, reason, severity, scope). Reload happens at
# every check call but is cheap because the JSON parse + regex compile are
# memoised — a future hot-reload signal can clear _GUARD_CACHE.
_GUARD_CACHE = None


def _hardcoded_guard_fallback():
    """Used only if guard-patterns.json is missing/malformed. Minimal set."""
    return [
        (re.compile(r"\brm\s+(-[rRf]+\s+)+/(?!\S)"), "rm -rf /", "crit", "always"),
        (re.compile(r"\bcurl\s+[^|]*\|\s*(bash|sh)\b"), "curl|bash", "warn", "always"),
        (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/"), "bash reverse shell", "crit", "always"),
    ]


def _load_guard_patterns():
    global _GUARD_CACHE
    if _GUARD_CACHE is not None:
        return _GUARD_CACHE
    try:
        import registry_loader  # type: ignore
        data = registry_loader.load_guard_patterns()
        out = []
        for entry in data.get("patterns", []):
            if not isinstance(entry, dict) or not entry.get("regex"):
                continue
            try:
                rx = re.compile(entry["regex"])
            except re.error as e:
                log.warning(f"guard-pattern compile failed for {entry.get('id')}: {e}")
                continue
            out.append((rx,
                        entry.get("reason", entry.get("id", "dangerous pattern")),
                        entry.get("severity", "warn"),
                        entry.get("scope", "always")))
        if not out:
            out = _hardcoded_guard_fallback()
        _GUARD_CACHE = out
    except Exception as e:
        log.warning(f"guard-patterns load failed, using fallback: {e}")
        _GUARD_CACHE = _hardcoded_guard_fallback()
    return _GUARD_CACHE


def guard_check(line: str, piloted: bool = False):
    """Return (True, reason) if the command line matches a dangerous pattern,
    else (False, None). When `piloted` is True, also enforce 'piloted'-scope
    patterns — the bar is stricter when AI drives AI."""
    for rx, reason, _sev, scope in _load_guard_patterns():
        if scope == "piloted" and not piloted:
            continue
        if rx.search(line):
            return True, reason
    return False, None


def _sanitized_env():
    """Whitelisted env for spawned PTYs. Blocks credential leak from
    connector-process env into user shells (AWS_*, ANTHROPIC_API_KEY,
    GITHUB_TOKEN, etc.)."""
    env = {k: v for k, v in os.environ.items()
           if k in _ENV_ALLOWED or k.startswith("LC_")}
    env.setdefault("TERM", "xterm-256color")
    env.setdefault("COLORTERM", "truecolor")
    env.setdefault("LANG", "en_US.UTF-8")
    env.setdefault("HOME", os.path.expanduser("~"))
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    return env


import session_daemon  # dtach-in-Python: per-session supervisor that holds
                       # the PTY master FD across pty-manager restarts.

class PtySession:
    """A single AI session, supervised by a session_daemon process.

    PTY-Manager talks to that supervisor via a Unix-domain socket using a
    tiny framed protocol (T_DATA / T_RESIZE / T_KILL / T_META_*). The AI
    process is a child of the supervisor, NOT of pty-manager — so pty-manager
    can die and the AI keeps running. New pty-manager instance reattaches
    via session_daemon.discover_sessions() at startup."""

    def __init__(self, sid, cmd, cwd, loop, cmd_args=None, guard_enabled=False):
        self.sid = sid
        self.cmd = cmd
        self.cmd_args = cmd_args or []
        self.cwd = cwd
        self.pid = None              # AI process PID (reported by daemon)
        self.fd = None               # socket FD to the supervisor
        self.sock = None             # the socket itself (kept for sendall)
        self.sock_path = None        # /run/aiterm/sess_<sid>.sock
        self.scrollback = bytearray()
        self._sock_rbuf = bytearray()  # frame-parsing buffer
        self.started_at = None
        self.loop = loop
        self.clients = set()
        # Guard Mode state (active only when self.ai_base == "bash")
        self.guard_enabled = bool(guard_enabled)
        self._guard_line = b""
        self._guard_pending = None
        self._guard_held = b""
        self._guard_cb = None

    @property
    def _is_bash(self):
        return os.path.basename(self.cmd or "") in ("bash", "sh", "zsh", "fish")

    def _attach_socket(self, sock_path):
        """Open + connect a non-blocking Unix socket to the supervisor and
        wire it into the asyncio loop. Used by spawn() and reattach()."""
        import socket as _socket
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.setblocking(False)
        # The supervisor takes a moment to bind the socket after fork —
        # spawn() already waited up to ~600 ms for it, but on slow systems
        # we may still need a small connect retry.
        last_err = None
        for _ in range(30):
            try:
                s.connect(sock_path)
                break
            except (BlockingIOError, OSError) as e:
                last_err = e
                # Block briefly so we don't spin
                import time as _t
                _t.sleep(0.02)
        else:
            raise RuntimeError(f"could not connect to supervisor at {sock_path}: {last_err}")
        self.sock = s
        self.fd = s.fileno()
        self.sock_path = sock_path
        self.loop.add_reader(self.fd, self._on_socket)

    def spawn(self):
        self.kill()
        import time as _time
        self.started_at = _time.time()
        env = _sanitized_env()

        argv = [self.cmd] + self.cmd_args
        # Fork supervisor + AI; daemon hands us back the AI PID and the
        # path of the supervisor's listen-socket.
        try:
            sock_path, ai_pid = session_daemon.spawn(self.sid, argv, self.cwd, env)
        except Exception as e:
            log.error(f"session_daemon.spawn failed: {e}")
            raise
        self.pid = ai_pid
        self.scrollback.clear()
        self._sock_rbuf.clear()
        self._attach_socket(sock_path)
        self.resize(30, 120)
        log.info(f"Session {self.sid}: spawned {self.cmd} in {self.cwd} via daemon (ai_pid {ai_pid})")

    def reattach(self, sock_path, meta):
        """Connect to an already-running supervisor (after pty-manager
        restart). meta is the JSON dict from sess_<sid>.sock.meta written
        at spawn time — it carries cmd, cwd, started_at, ai_pid."""
        self.cmd = (meta.get("cmd") or [self.cmd])[0] if isinstance(meta.get("cmd"), list) else (meta.get("cmd") or self.cmd)
        cmd_field = meta.get("cmd")
        if isinstance(cmd_field, list) and len(cmd_field) > 1:
            self.cmd_args = cmd_field[1:]
        self.cwd = meta.get("cwd") or self.cwd
        self.pid = meta.get("ai_pid")
        self.started_at = meta.get("started_at")
        self.scrollback.clear()
        self._sock_rbuf.clear()
        self._attach_socket(sock_path)
        log.info(f"Session {self.sid}: reattached to existing supervisor (ai_pid {self.pid})")

    def detach(self):
        """Close our socket to the supervisor without killing the AI.
        Used when pty-manager itself is shutting down — the supervisor and
        the AI keep running, ready for the next pty-manager to reattach."""
        if self.fd is not None:
            try:
                self.loop.remove_reader(self.fd)
            except Exception:
                pass
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        self.fd = None

    def kill(self, force=False):
        """Tell the supervisor to terminate the AI, then close our socket.
        Supervisor cleans up the socket file and exits.

        force=True: skip SIGTERM, send SIGKILL via T_KILL_HARD frame,
        and as belt-and-suspenders also SIGKILL the supervisor PID +
        unlink the socket file ourselves. Used for stuck Ink-based TUIs
        that catch SIGTERM and refuse to exit cleanly."""
        # Stop reading from the socket
        if self.fd is not None:
            try:
                self.loop.remove_reader(self.fd)
            except Exception:
                pass
        # Tell supervisor to terminate the AI; supervisor exits afterwards
        # and unlinks the socket itself.
        if self.sock is not None:
            try:
                frame_type = session_daemon.T_KILL_HARD if force else session_daemon.T_KILL
                self.sock.sendall(session_daemon.pack_frame(frame_type, b""))
            except (OSError, ConnectionError):
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        if force:
            # Belt-and-suspenders: directly SIGKILL the AI process AND
            # the supervisor, then nuke the socket. Covers the case
            # where the supervisor's own loop is stuck (rare) or the
            # T_KILL_HARD frame didn't make it through.
            self._force_external_kill()
        self.fd = None
        self.sock_path = None
        self.pid = None

    def _force_external_kill(self):
        """SIGKILL the AI (self.pid) and the supervisor (looked up via
        sock_path's .meta file), then unlink the supervisor socket so a
        re-spawn in the same session id doesn't trip on stale state."""
        try:
            if self.pid:
                os.kill(self.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        # Read supervisor PID from the .meta sidecar (session_daemon
        # writes it there on spawn). Best-effort.
        sup_pid = None
        try:
            if self.sock_path:
                meta = json.loads(open(self.sock_path + ".meta").read())
                sup_pid = int(meta.get("supervisor_pid") or 0) or None
        except Exception:
            pass
        if sup_pid:
            try:
                os.kill(sup_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        # Remove socket + meta so cleanup_dead_sessions doesn't get
        # confused on the next pty-manager startup.
        for suffix in ("", ".meta"):
            try:
                if self.sock_path:
                    os.unlink(self.sock_path + suffix)
            except OSError:
                pass

    def resize(self, rows, cols):
        if self.sock is None:
            return
        body = f"{int(rows)}x{int(cols)}".encode()
        try:
            self.sock.sendall(session_daemon.pack_frame(session_daemon.T_RESIZE, body))
        except (OSError, ConnectionError):
            pass

    def _send_to_pty(self, data):
        """Send raw bytes to the PTY (wraps in T_DATA frame for the
        supervisor)."""
        if self.sock is None:
            return
        try:
            self.sock.sendall(session_daemon.pack_frame(session_daemon.T_DATA, data))
        except (OSError, ConnectionError):
            pass

    def write(self, data):
        if self.sock is None:
            return
        # Fast path: guard off, or non-bash session, or nothing to scan
        if not self.guard_enabled or not self._is_bash:
            self._send_to_pty(data)
            return
        # Guard path: while a confirmation is pending, buffer everything
        if self._guard_pending is not None:
            self._guard_held += data
            return
        # Scan for line terminators (\r or \n); intercept them.
        i = 0
        n = len(data)
        while i < n:
            b = data[i:i+1]
            if b in (b"\r", b"\n"):
                # Flush bytes BEFORE the terminator to bash (so live-echo works)
                if i > 0:
                    self._send_to_pty(data[:i])
                    self._guard_line += data[:i]
                # Evaluate the accumulated line
                try:
                    line_str = self._guard_line.decode("utf-8", errors="replace").strip()
                except Exception:
                    line_str = ""
                dangerous, reason = guard_check(line_str) if line_str else (False, None)
                if dangerous:
                    # Hold the terminator + any trailing data
                    self._guard_pending = line_str
                    self._guard_held = data[i:]
                    self._guard_line = b""
                    if self._guard_cb:
                        try:
                            self._guard_cb(line_str, reason)
                        except Exception as e:
                            log.warning(f"guard callback failed: {e}")
                    return
                # Safe: write terminator, keep scanning remainder
                self._send_to_pty(b)
                self._guard_line = b""
                i += 1
                data = data[i:]
                n = len(data)
                i = 0
                continue
            elif b == b"\x03":  # Ctrl-C resets the line
                self._guard_line = b""
                self._send_to_pty(b)
                i += 1
                data = data[i:]
                n = len(data)
                i = 0
                continue
            elif b in (b"\x08", b"\x7f"):  # backspace / delete
                if self._guard_line:
                    self._guard_line = self._guard_line[:-1]
                self._send_to_pty(b)
                i += 1
                data = data[i:]
                n = len(data)
                i = 0
                continue
            else:
                self._guard_line += b
                i += 1
        # No terminator in this chunk: forward everything
        if data:
            self._send_to_pty(data)

    def guard_resolve(self, approve: bool):
        """Called when user responds to a guard_confirm dialog."""
        if self._guard_pending is None:
            return
        self._guard_pending = None
        held = self._guard_held
        self._guard_held = b""
        self._guard_line = b""
        if self.sock is None:
            return
        if approve:
            # Release the held data (terminator + whatever followed)
            self._send_to_pty(held)
        else:
            # Cancel: send Ctrl-C so bash clears its readline buffer.
            self._send_to_pty(b"\x03")

    def set_guard(self, enabled: bool):
        was = self.guard_enabled
        self.guard_enabled = bool(enabled)
        # If we're turning off while a prompt is pending, auto-approve (fail-open to avoid stuck session)
        if was and not self.guard_enabled and self._guard_pending is not None:
            self.guard_resolve(True)

    def is_alive(self):
        # The AI is a child of the session_daemon supervisor, not of
        # pty-manager — so waitpid is not applicable. Probe via /proc.
        if not self.pid:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # process exists, just not ours to signal

    def _on_socket(self):
        """asyncio reader callback. Reads bytes from the supervisor socket
        and demultiplexes into framed messages. T_DATA frames are forwarded
        to scrollback + browser clients exactly as the old pty-FD reader
        did. Other frame types (T_META_RESP) are absorbed silently."""
        if self.sock is None:
            return
        try:
            chunk = self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except (OSError, ConnectionError):
            self._handle_supervisor_gone()
            return
        if not chunk:
            self._handle_supervisor_gone()
            return
        self._sock_rbuf.extend(chunk)
        # Drain complete frames.
        while len(self._sock_rbuf) >= 5:
            length = struct.unpack(">I", self._sock_rbuf[1:5])[0]
            if length > 16 * 1024 * 1024:
                # Malformed framing — drop everything to resync.
                log.warning(f"sess {self.sid}: malformed frame length {length}, resetting buffer")
                self._sock_rbuf.clear()
                break
            if len(self._sock_rbuf) < 5 + length:
                break
            ftype = self._sock_rbuf[0]
            body = bytes(self._sock_rbuf[5:5 + length])
            del self._sock_rbuf[:5 + length]
            if ftype == session_daemon.T_DATA:
                self.scrollback.extend(body)
                if len(self.scrollback) > SCROLLBACK_MAX:
                    self.scrollback = self.scrollback[-SCROLLBACK_MAX:]
                asyncio.ensure_future(self._broadcast(body))
            # T_META_RESP and others: ignored here; reattach() handles those.

    def _handle_supervisor_gone(self):
        """Supervisor socket closed → AI exited. Clean up reader, mark dead."""
        try:
            self.loop.remove_reader(self.fd)
        except Exception:
            pass
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.fd = None
        self.pid = None

    async def _broadcast(self, data):
        msg = json.dumps({"t": "o", "sid": self.sid, "d": base64.b64encode(data).decode()}) + "\n"
        raw = msg.encode()
        dead = set()
        # Snapshot the set: each `await w.drain()` yields control, and a
        # client connecting or disconnecting in between would mutate
        # self.clients mid-iteration → RuntimeError("Set changed size
        # during iteration") and the whole pty-manager crashes. Iterate
        # over a list copy instead.
        for w in list(self.clients):
            try:
                w.write(raw)
                await w.drain()
            except Exception:
                dead.add(w)
        self.clients -= dead

    def to_dict(self):
        return {"sid": self.sid, "cmd": self.cmd, "cwd": self.cwd, "pid": self.pid or 0, "alive": self.is_alive(),
                "started_at": self.started_at or 0}


# ── Session Manager ──────────────────────────────────────────
sessions = {}  # sid → PtySession
_connector_writers = set()      # all connectors currently attached
_last_collision_state = {}      # sid → ext_pid (last reported) — used to
                                # dedupe and emit "cleared" when it goes away

# Known AI binaries and where to find them
# AI metadata is now sourced from /opt/aiterm/ai-registry.json (signed,
# distributed via the same Ed25519-manifest pipeline as the connector
# itself). The legacy AI_COMMANDS / AI_DEFAULT_ARGS / EXTRA_PATHS dicts
# are derived at startup so existing code paths don't change shape — they
# just get repopulated whenever the registry is updated. See
# registry_loader.py for the schema and fallback behaviour.
try:
    import registry_loader  # type: ignore
    AI_COMMANDS = registry_loader.derive_ai_commands()
    AI_DEFAULT_ARGS = registry_loader.derive_default_args()
except Exception as _e:
    log.warning(f"registry_loader unavailable; using hardcoded fallback: {_e}")
    AI_COMMANDS = {"claude": "claude", "ollama": "ollama", "bash": "bash"}
    AI_DEFAULT_ARGS = {}


def _user_bin_paths(bin_name):
    paths = [
        os.path.expanduser(f"~/.local/bin/{bin_name}"),
        f"/root/.local/bin/{bin_name}",
        f"/usr/local/bin/{bin_name}",
        f"/usr/bin/{bin_name}",
    ]
    # npm global installs (gemini, qwen, codex often land here)
    for npm_prefix in ("/usr/local/lib/node_modules/.bin", "/opt/homebrew/bin"):
        paths.append(f"{npm_prefix}/{bin_name}")
    return paths

# Search paths to consult before falling back to PATH lookup. Comes from
# the registry's `scan.extra_paths` per AI; we additionally seed common
# user-bin locations so the registry only needs to override unusual cases.
def _build_extra_paths():
    out = {}
    try:
        registry_extras = registry_loader.derive_extra_paths()
    except Exception:
        registry_extras = {}
    # Default search set — applied to every AI even if the registry doesn't
    # mention it, so a freshly added AI is immediately findable in user bins.
    for ai_id, binary in AI_COMMANDS.items():
        if ai_id == "bash":
            continue
        out[ai_id] = _user_bin_paths(binary)
        # Merge in registry-specific paths, deduping while keeping order.
        for p in registry_extras.get(ai_id, []):
            if p not in out[ai_id]:
                out[ai_id].append(p)
    return out

EXTRA_PATHS = _build_extra_paths()


def _process_context(pid):
    """Best-effort metadata about a PID for the conflict UI: how long it has
    been running, who its parent looks like, and whether we recognise it as
    one of our own sessions. Used only to make the dashboard's 'something
    is already there' modal informative — never for security decisions."""
    out = {"pid": pid, "started_at": None, "parent_pid": None,
           "parent_cmd": "", "uid": None}
    try:
        st = os.stat(f"/proc/{pid}")
        out["uid"] = st.st_uid
        out["started_at"] = int(st.st_ctime)
    except (FileNotFoundError, PermissionError):
        return out
    try:
        with open(f"/proc/{pid}/status") as f:
            for ln in f:
                if ln.startswith("PPid:"):
                    out["parent_pid"] = int(ln.split()[1])
                    break
    except Exception:
        pass
    if out["parent_pid"]:
        try:
            with open(f"/proc/{out['parent_pid']}/cmdline", "rb") as f:
                out["parent_cmd"] = f.read().decode(errors="replace").replace("\x00", " ").strip()[:200]
        except Exception:
            pass
    return out


def find_running_process(binary_name, target_cwd):
    """Check /proc for a running INTERACTIVE process matching binary_name in target_cwd.
    Excludes daemon/server processes (e.g. 'ollama serve')."""
    EXCLUDE_PATTERNS = ["serve", "server", "daemon", "-d", "--daemon"]
    target = os.path.realpath(target_cwd)
    my_pid = os.getpid()
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit() or int(pid_dir) == my_pid:
                continue
            try:
                proc_cwd = os.path.realpath(f"/proc/{pid_dir}/cwd")
                if proc_cwd != target:
                    continue
                cmdline = open(f"/proc/{pid_dir}/cmdline", "rb").read().decode(errors="replace")
                if binary_name in cmdline:
                    # Skip server/daemon processes
                    if any(pat in cmdline for pat in EXCLUDE_PATTERNS):
                        continue
                    return int(pid_dir)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
    except Exception:
        pass
    return None


def find_binary(ai_type):
    """Find the binary for an AI type."""
    cmd = AI_COMMANDS.get(ai_type, ai_type)
    binary = shutil.which(cmd)
    if not binary:
        for p in EXTRA_PATHS.get(ai_type, []):
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        # Check home dirs
        if ai_type == "claude":
            try:
                for entry in os.scandir("/home"):
                    if entry.is_dir():
                        p = os.path.join(entry.path, ".local/bin/claude")
                        if os.path.isfile(p) and os.access(p, os.X_OK):
                            return p
            except (PermissionError, OSError):
                pass
    return binary


async def handle_client(reader, writer):
    """Handle a connector connection."""
    log.info("Connector attached")

    # Track this writer in the global set so non-session-specific
    # broadcasts (external_collision, etc.) can reach every connector.
    _connector_writers.add(writer)

    # Register this writer with all existing sessions (for output broadcast)
    for sess in sessions.values():
        sess.clients.add(writer)

    # Send current session list
    session_list = [s.to_dict() for s in sessions.values()]
    try:
        writer.write((json.dumps({"t": "sessions", "sessions": session_list}) + "\n").encode())
        await writer.drain()
    except Exception:
        pass

    # Send scrollback for all active sessions. Marked with replay=true so the
    # hub REPLACES its scrollback (not appends) and does NOT rebroadcast to
    # already-connected browsers — they already have this content.
    # Iterate over list snapshot: each `await writer.drain()` yields, and a
    # session start/stop in between would mutate the dict mid-iteration.
    for sess in list(sessions.values()):
        if sess.scrollback:
            try:
                msg = json.dumps({"t": "o", "sid": sess.sid, "replay": True,
                                  "d": base64.b64encode(bytes(sess.scrollback)).decode()}) + "\n"
                writer.write(msg.encode())
                await writer.drain()
            except Exception:
                pass

    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            t = msg.get("t")
            sid = msg.get("sid", "")

            if t == "start":
                ai_type = msg.get("ai", "")
                raw_cwd = msg.get("cwd", "")

                # Parse force flag: cwd="force:/path"
                force = raw_cwd.startswith("force:")
                if force:
                    raw_cwd = raw_cwd[6:]
                cwd = raw_cwd or os.path.expanduser("~")
                if not os.path.isdir(cwd):
                    cwd = os.path.expanduser("~")
                cwd = os.path.realpath(cwd)

                # Support model-specific AI types like "ollama:llama3"
                ai_base = ai_type.split(":")[0]
                ai_model = ai_type.split(":")[1] if ":" in ai_type else ""

                binary = find_binary(ai_base)
                if not binary:
                    resp = {"t": "err", "sid": sid, "m": f"{ai_base} not found"}
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    continue

                # Check own sessions: same AI + same directory
                dupe = False
                for existing in sessions.values():
                    if os.path.realpath(existing.cwd) == cwd and os.path.basename(existing.cmd) == os.path.basename(binary):
                        dupe = True
                        break
                if dupe and not force:
                    resp = {"t": "err", "sid": sid, "m": f"{os.path.basename(binary)} already running in {cwd}"}
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    continue

                # Check for external process in that CWD
                # Skip for Ollama — ollama run is a client, multiple are fine
                SKIP_CONFLICT_CHECK = ("ollama",)
                bin_name = os.path.basename(binary)
                if bin_name not in SKIP_CONFLICT_CHECK:
                    ext_pid = find_running_process(bin_name, cwd)
                    if ext_pid and not force:
                        ai_name = "Claude Code" if ai_base == "claude" else ai_base.title()
                        ctx = _process_context(ext_pid)
                        is_ours = ext_pid in {s.pid for s in sessions.values() if s.pid}
                        resp = {"t": "process_conflict", "sid": sid, "ai": ai_type,
                                "pid": ext_pid, "cwd": cwd,
                                "m": f"{ai_name} already running in {cwd} (PID {ext_pid})",
                                "ctx": {**ctx, "is_ours": is_ours, "ai_name": ai_name}}
                        writer.write((json.dumps(resp) + "\n").encode())
                        await writer.drain()
                        continue
                    if ext_pid and force:
                        own_pids = {s.pid for s in sessions.values() if s.pid}
                        # Owned-by-this-PTY-Manager: easy case, kill it.
                        if ext_pid in own_pids:
                            log.info(f"Force-killing own session PID {ext_pid} in {cwd}")
                            try:
                                os.kill(ext_pid, signal.SIGTERM)
                                # Give it 500 ms to exit cleanly, then SIGKILL.
                                for _ in range(10):
                                    await asyncio.sleep(0.05)
                                    try:
                                        os.kill(ext_pid, 0)  # exists?
                                    except ProcessLookupError:
                                        break
                                else:
                                    os.kill(ext_pid, signal.SIGKILL)
                            except (ProcessLookupError, PermissionError):
                                pass
                        else:
                            # Not in our sessions dict → orphan from a previous
                            # PTY-Manager OR a manually-started AI in the same
                            # cwd. With explicit force, we kill it if:
                            #   * it's owned by the same UID as PTY-Manager
                            #     (no privilege escalation; we kill OUR user's
                            #     processes only), AND
                            #   * find_running_process already verified it's a
                            #     known AI binary in the target cwd (so we're
                            #     not zapping random system processes).
                            # The user explicitly chose "force" — that's their
                            # informed consent to clean up THIS process.
                            ok_to_kill = False
                            try:
                                st = os.stat(f"/proc/{ext_pid}")
                                if st.st_uid == os.getuid():
                                    ok_to_kill = True
                            except (FileNotFoundError, PermissionError):
                                pass
                            if ok_to_kill:
                                log.warning(f"Force-killing same-UID AI PID {ext_pid} in {cwd} (user requested)")
                                try:
                                    os.kill(ext_pid, signal.SIGTERM)
                                    for _ in range(10):
                                        await asyncio.sleep(0.05)
                                        try:
                                            os.kill(ext_pid, 0)
                                        except ProcessLookupError:
                                            break
                                    else:
                                        os.kill(ext_pid, signal.SIGKILL)
                                except (ProcessLookupError, PermissionError) as e:
                                    log.warning(f"force kill failed: {e}")
                                # Successful kill — fall through and spawn the new
                                # session below. Do NOT write resp / continue here:
                                # `resp` would still hold the previous iteration's
                                # value and would surface as a duplicate
                                # process_conflict to the dashboard.
                            else:
                                log.warning(f"Refusing to kill PID {ext_pid} — different UID")
                                resp = {"t": "process_conflict", "sid": sid, "ai": ai_type,
                                        "pid": ext_pid, "cwd": cwd,
                                        "m": f"External process (PID {ext_pid}) belongs to another user. Run: kill {ext_pid}"}
                                writer.write((json.dumps(resp) + "\n").encode())
                                await writer.drain()
                                continue

                # Build command: for Ollama use "ollama run <model>"
                if ai_base == "ollama" and ai_model:
                    cmd = binary
                    cmd_args = ["run", ai_model]
                elif ai_base == "ollama" and not ai_model:
                    resp = {"t": "err", "sid": sid, "m": "Ollama: no model specified. Rescan to see available models."}
                    writer.write((json.dumps(resp) + "\n").encode())
                    await writer.drain()
                    continue
                else:
                    cmd = binary
                    cmd_args = list(AI_DEFAULT_ARGS.get(ai_base, []))

                guard_enabled = bool(msg.get("guard", False))
                sess = PtySession(sid, cmd, cwd, asyncio.get_event_loop(), cmd_args=cmd_args, guard_enabled=guard_enabled)
                sess.clients.add(writer)

                # Wire guard callback to push confirmation requests upstream.
                # Explicit parameters avoid closure-over-loop-variable issues.
                def _make_guard_cb(bound_sid, bound_sess):
                    def _cb(cmd_line, reason):
                        payload = json.dumps({"t": "guard_confirm", "sid": bound_sid, "cmd": cmd_line[:400], "reason": reason}) + "\n"
                        for w in list(bound_sess.clients):
                            try:
                                w.write(payload.encode())
                            except Exception:
                                pass
                    return _cb
                sess._guard_cb = _make_guard_cb(sid, sess)

                sess.spawn()
                sessions[sid] = sess

                FRIENDLY_NAMES = {
                    "claude": "Claude Code",
                    "codex": "Codex",
                    "gemini": "Gemini",
                    "goose": "Goose",
                    "qwen": "Qwen",
                    "aider": "Aider",
                    "llm": "llm",
                    "sgpt": "ShellGPT",
                    "llamacpp": "llama.cpp",
                    "localai": "LocalAI",
                    "gpt4all": "GPT4All",
                    "bash": "Bash",
                }
                ai_name = FRIENDLY_NAMES.get(ai_base, ai_model or ai_base.title())
                if ai_base == "ollama" and ai_model:
                    ai_name = "Ollama: " + ai_model
                import time as _time
                resp = {"t": "started", "sid": sid, "ai": ai_type, "name": ai_name, "cwd": cwd, "started_at": _time.time()}
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()
                log.info(f"Session {sid} started: {ai_type} in {cwd}")

            elif t == "stop":
                force = bool(msg.get("force", False))
                sess = sessions.pop(sid, None)
                if sess:
                    sess.kill(force=force)
                    log.info(f"Session {sid} stopped" + (" (forced)" if force else ""))
                resp = {"t": "stopped", "sid": sid}
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()

            elif t == "kill_all":
                # Emergency stop — kill every session right now. Used by the
                # per-user "panic" button. Reports each kill so the dashboard
                # updates its tab list. SIGTERM first, kernel will reap.
                killed_sids = list(sessions.keys())
                log.warning(f"KILL_ALL received — terminating {len(killed_sids)} session(s)")
                for sid_kill in killed_sids:
                    sess = sessions.pop(sid_kill, None)
                    if sess:
                        try:
                            sess.kill()
                        except Exception as e:
                            log.warning(f"kill({sid_kill}) failed: {e}")
                        try:
                            writer.write((json.dumps({"t": "stopped", "sid": sid_kill}) + "\n").encode())
                        except Exception:
                            pass
                try:
                    await writer.drain()
                except Exception:
                    pass

            elif t == "input":
                sess = sessions.get(sid)
                if sess:
                    sess.write(base64.b64decode(msg.get("d", "")))

            elif t == "guard_response":
                sess = sessions.get(sid)
                if sess:
                    sess.guard_resolve(bool(msg.get("approve", False)))

            elif t == "set_guard":
                # Live toggle for an existing session
                sess = sessions.get(sid)
                if sess:
                    sess.set_guard(bool(msg.get("enabled", False)))

            elif t == "resize":
                sess = sessions.get(sid)
                if sess:
                    sess.resize(msg.get("rows", 30), msg.get("cols", 120))

            elif t == "list":
                session_list = [s.to_dict() for s in sessions.values()]
                writer.write((json.dumps({"t": "sessions", "sessions": session_list}) + "\n").encode())
                await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        _connector_writers.discard(writer)
        # Remove this writer from all sessions (but keep sessions alive!)
        for sess in sessions.values():
            sess.clients.discard(writer)
        try:
            writer.close()
        except Exception:
            pass
        log.info(f"Connector detached ({sum(len(s.clients) for s in sessions.values())} clients remaining)")


async def _broadcast_to_connectors(msg_dict):
    """Send a JSON line to every attached connector. Used for non-
    session-specific events (e.g. external-process collision warnings)."""
    line = (json.dumps(msg_dict) + "\n").encode()
    dead = set()
    for w in list(_connector_writers):
        try:
            w.write(line)
            await w.drain()
        except Exception:
            dead.add(w)
    _connector_writers.difference_update(dead)


async def _watch_external_collisions():
    """Every 30 s, look for external Claude/AI processes running in the
    SAME cwd as one of our supervised sessions. Emit external_collision
    when found, external_collision_cleared when previously-seen ones
    disappear. The dashboard renders an inline warning so the user
    knows two instances might be touching the same files (CLAUDE.md,
    .claude/settings.json, git state, …).

    Direction covered here is the inverse of process_conflict: that
    one fires when *we* try to spawn into an occupied dir. This one
    fires when somebody opens a second AI from outside (SSH, PuTTY)
    while a dashboard session is already running."""
    while True:
        try:
            for sid, sess in list(sessions.items()):
                cwd = (sess.cwd or "").strip()
                cmd = (sess.cmd or "").strip()
                if not cwd or not cmd or not os.path.isdir(cwd):
                    continue
                bin_name = os.path.basename(cmd)
                if bin_name in ("ollama",):  # daemon-like, skip
                    continue
                ext = find_running_process(bin_name, cwd)
                # Reject our own ai_pid (the supervisor's child).
                if ext == sess.pid:
                    ext = None
                last = _last_collision_state.get(sid)
                if ext and ext != last:
                    _last_collision_state[sid] = ext
                    cmdline = ""
                    try:
                        with open(f"/proc/{ext}/cmdline", "rb") as f:
                            cmdline = f.read().decode("utf-8", "replace").replace("\x00", " ").strip()[:120]
                    except Exception:
                        pass
                    await _broadcast_to_connectors({
                        "t": "external_collision",
                        "sid": sid, "cwd": cwd, "ext_pid": ext,
                        "cmdline": cmdline, "ai": bin_name,
                    })
                    log.info(f"external collision: sid={sid} cwd={cwd} ext_pid={ext}")
                elif not ext and last:
                    _last_collision_state.pop(sid, None)
                    await _broadcast_to_connectors({
                        "t": "external_collision_cleared", "sid": sid,
                    })
            # Drop entries for sessions that no longer exist.
            for stale_sid in [s for s in _last_collision_state if s not in sessions]:
                _last_collision_state.pop(stale_sid, None)
        except Exception as e:
            log.warning(f"external_collision watcher error: {e}")
        await asyncio.sleep(30)


def _reload_registries():
    """Hot-reload all registry-derived state without killing sessions.
    Called on SIGHUP and from the inotify-style mtime poller. Existing
    PtySession objects keep running — only the lookup tables that decide
    *what new sessions can do* change."""
    global AI_COMMANDS, AI_DEFAULT_ARGS, EXTRA_PATHS, _GUARD_CACHE
    try:
        import importlib
        import registry_loader  # type: ignore
        # Re-import is unnecessary (registry_loader has no module-level cache),
        # but we do it for symmetry: if the loader file itself changed (e.g.
        # new helper function), this picks it up.
        importlib.reload(registry_loader)
        AI_COMMANDS = registry_loader.derive_ai_commands()
        AI_DEFAULT_ARGS = registry_loader.derive_default_args()
        EXTRA_PATHS = _build_extra_paths()
        _GUARD_CACHE = None  # forces _load_guard_patterns() to re-read JSON
        log.warning(f"registries reloaded: {len(AI_COMMANDS)} AIs, "
                    f"{len(_load_guard_patterns())} guard patterns")
    except Exception as e:
        log.error(f"registry reload failed: {e}")


async def _watch_registries(loop):
    """Poll registry-file mtimes every 5s. On change, fire the same reload
    path SIGHUP would. No external dep — stdlib only."""
    files = [
        "/opt/aiterm/ai-registry.json",
        "/opt/aiterm/guard-patterns.json",
        "/opt/aiterm/doctor-checks.json",
    ]
    last = {}
    # Seed initial state so the first iteration doesn't fire spuriously.
    for f in files:
        try:
            last[f] = os.path.getmtime(f)
        except FileNotFoundError:
            last[f] = 0
    while True:
        try:
            await asyncio.sleep(5)
            changed = []
            for f in files:
                try:
                    m = os.path.getmtime(f)
                except FileNotFoundError:
                    m = 0
                if m and last.get(f) != m:
                    changed.append(f)
                    last[f] = m
            if changed:
                names = ", ".join(os.path.basename(c) for c in changed)
                log.info(f"registry mtime changed ({names}) — hot-reload")
                _reload_registries()
        except asyncio.CancelledError:
            return
        except Exception as e:
            log.warning(f"registry watcher error: {e}")
            await asyncio.sleep(10)


def _reattach_existing_sessions(loop):
    """Scan /run/aiterm/ for supervisor sockets surviving a previous
    pty-manager run. For each live one, recreate a PtySession entry and
    connect — the AI process keeps running throughout."""
    try:
        found = session_daemon.discover_sessions()
    except Exception as e:
        log.warning(f"reattach scan failed: {e}")
        return 0
    n = 0
    for s in found:
        if not s["ai_alive"]:
            continue
        meta = s["meta"] or {}
        sid = s["sid"]
        if sid in sessions:
            continue
        cmd_field = meta.get("cmd") or []
        if isinstance(cmd_field, list) and cmd_field:
            cmd = cmd_field[0]
            cmd_args = cmd_field[1:]
        else:
            cmd = "bash"
            cmd_args = []
        cwd = meta.get("cwd") or os.path.expanduser("~")
        sess = PtySession(sid, cmd, cwd, loop, cmd_args=cmd_args)
        try:
            sess.reattach(s["sock_path"], meta)
            sessions[sid] = sess
            n += 1
            log.info(f"reattached session {sid} (ai_pid={meta.get('ai_pid')}, cwd={cwd})")
        except Exception as e:
            log.warning(f"reattach {sid} failed: {e}")
    # Drop stale socket files where the supervisor crashed without cleaning up.
    try:
        cleaned = session_daemon.cleanup_dead_sessions()
        if cleaned:
            log.info(f"cleaned {cleaned} stale session socket(s)")
    except Exception:
        pass
    return n


async def main():
    # Clean up old socket
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o600)

    stop = asyncio.Future()
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: stop.set_result(None) if not stop.done() else None)
    # SIGHUP = hot-reload registries without killing sessions. Used by the
    # update flow ('aiterm update' sends SIGHUP after a registry-only change)
    # and available for manual ops: `kill -HUP $(pgrep -f pty-manager)`.
    loop.add_signal_handler(signal.SIGHUP, _reload_registries)

    # Watcher fires the same reload path automatically when the JSON file
    # mtime moves, so a manual edit of a registry hot-reloads within ~5 s
    # even without an explicit signal.
    watcher_task = asyncio.create_task(_watch_registries(loop))
    collision_task = asyncio.create_task(_watch_external_collisions())

    # Reattach supervisor processes from a previous pty-manager run. Their
    # AI children kept running while we were down; we just plug back in.
    reattached = _reattach_existing_sessions(loop)
    if reattached:
        log.info(f"PTY Manager ready on {SOCKET_PATH} — reattached {reattached} live session(s)")
    else:
        log.info(f"PTY Manager ready on {SOCKET_PATH} (multi-session, hot-reload armed)")
    await stop

    # Graceful shutdown: DETACH all sessions instead of killing them.
    # The supervisor processes keep running with the AI children attached;
    # the next pty-manager instance will reattach. Survives its own updates.
    watcher_task.cancel()
    collision_task.cancel()
    for sess in sessions.values():
        sess.detach()
    server.close()
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    log.info("Shutdown — sessions detached, supervisors keep running")


if __name__ == "__main__":
    asyncio.run(main())
