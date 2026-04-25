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
import fcntl
import json
import logging
import os
import pty
import re
import shutil
import signal
import struct
import sys
import termios

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
_GUARD_PATTERNS = [
    # Destructive filesystem
    (re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|-[rR]\b.*\s-f\b|-f\b.*\s-[rR]\b)"), "recursive forced delete"),
    (re.compile(r"\brm\s+.*\s/\s*(?:$|;|&)"), "rm targeting root"),
    (re.compile(r"\bfind\s+.+-delete\b"), "find with -delete"),
    (re.compile(r"\bdd\s+.*\bof=/dev/(?:sd|nvme|disk|hd|mmcblk|vda|xvd)"), "dd to block device"),
    (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b"), "filesystem format"),
    (re.compile(r"\bshred\s+-[a-z]*(?:z|u)"), "shred with delete"),
    # Pipe-to-interpreter (classic curl|bash)
    (re.compile(r"\b(?:curl|wget|fetch)\s[^;|&]*\|\s*(?:sh|bash|zsh|fish|ksh|python3?|perl|ruby|node)\b"), "pipe remote content to interpreter"),
    # System-level
    (re.compile(r"\b(?:shutdown|halt|poweroff|reboot|init\s+0|init\s+6)\b"), "system shutdown/reboot"),
    (re.compile(r"\b(?:systemctl|service)\s+(?:stop|disable|mask)\b"), "stop or disable service"),
    # Network / firewall destructive
    (re.compile(r"\biptables\s+-F\b"), "flush iptables"),
    (re.compile(r"\bufw\s+disable\b"), "disable ufw firewall"),
    (re.compile(r"\bnftables\s+flush\b"), "flush nftables"),
    # Chmod/chown on root or wide wildcards
    (re.compile(r"\bchmod\s+(?:-R\s+)?(?:777|a\+w)\s+(?:/|/\*|/\s|/$)"), "chmod wide-open at root"),
    (re.compile(r"\bchown\s+(?:-R\s+)?\S+\s+/(?:$|\s)"), "chown at root"),
    # Redirect to block device
    (re.compile(r">\s*/dev/(?:sda|sdb|nvme|mmcblk|xvd|vda|disk\d)"), "write to block device"),
    # Eval-like
    (re.compile(r"\beval\s+[\"'`$]"), "eval with dynamic input"),
    # Fork bomb
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}"), "fork bomb"),
    # Overwriting authorized_keys
    (re.compile(r">\s*~?/?\.ssh/authorized_keys\b"), "overwrite SSH authorized_keys"),
    (re.compile(r">>\s*~?/?\.ssh/authorized_keys\b"), "append to SSH authorized_keys"),
]


def guard_check(line: str):
    """Return (True, reason) if the command line matches a dangerous pattern, else (False, None)."""
    for rx, reason in _GUARD_PATTERNS:
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


class PtySession:
    """A single PTY process (AI session)."""

    def __init__(self, sid, cmd, cwd, loop, cmd_args=None, guard_enabled=False):
        self.sid = sid
        self.cmd = cmd
        self.cmd_args = cmd_args or []
        self.cwd = cwd
        self.pid = None
        self.fd = None
        self.scrollback = bytearray()
        self.started_at = None  # set on spawn
        self.loop = loop
        self.clients = set()
        # Guard Mode state (active only when self.ai_base == "bash")
        self.guard_enabled = bool(guard_enabled)
        self._guard_line = b""            # accumulator for the current input line
        self._guard_pending = None        # pending command string while awaiting user confirmation
        self._guard_held = b""            # data held back (terminator + any trailing bytes)
        self._guard_cb = None             # callable(line, reason) invoked on pattern match

    @property
    def _is_bash(self):
        return os.path.basename(self.cmd or "") in ("bash", "sh", "zsh", "fish")

    def spawn(self):
        self.kill()
        import time as _time
        self.started_at = _time.time()
        env = _sanitized_env()

        argv = [self.cmd] + self.cmd_args
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(self.cwd)
            except Exception:
                os.chdir(os.path.expanduser("~"))
            os.execvpe(self.cmd, argv, env)
            sys.exit(1)

        self.pid, self.fd = pid, fd
        self.scrollback.clear()
        self.resize(30, 120)
        self.loop.add_reader(fd, self._on_output)
        log.info(f"Session {self.sid}: spawned {self.cmd} in {self.cwd} (pid {pid})")

    def kill(self):
        if self.fd is not None:
            try:
                self.loop.remove_reader(self.fd)
            except Exception:
                pass
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGTERM)
                os.waitpid(self.pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
            self.pid = None
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def resize(self, rows, cols):
        if self.fd is not None:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            if self.pid:
                try:
                    os.kill(self.pid, signal.SIGWINCH)
                except ProcessLookupError:
                    pass

    def write(self, data):
        if self.fd is None:
            return
        # Fast path: guard off, or non-bash session, or nothing to scan
        if not self.guard_enabled or not self._is_bash:
            try:
                os.write(self.fd, data)
            except OSError:
                pass
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
                    try:
                        os.write(self.fd, data[:i])
                    except OSError:
                        return
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
                    # Reset line buffer; next user input (while pending) goes to _guard_held
                    self._guard_line = b""
                    if self._guard_cb:
                        try:
                            self._guard_cb(line_str, reason)
                        except Exception as e:
                            log.warning(f"guard callback failed: {e}")
                    return
                # Safe: write terminator, keep scanning remainder
                try:
                    os.write(self.fd, b)
                except OSError:
                    return
                self._guard_line = b""
                i += 1
                data = data[i:]
                n = len(data)
                i = 0
                continue
            elif b == b"\x03":  # Ctrl-C resets the line
                self._guard_line = b""
                try:
                    os.write(self.fd, b)
                except OSError:
                    return
                i += 1
                data = data[i:]
                n = len(data)
                i = 0
                continue
            elif b in (b"\x08", b"\x7f"):  # backspace / delete
                if self._guard_line:
                    self._guard_line = self._guard_line[:-1]
                try:
                    os.write(self.fd, b)
                except OSError:
                    return
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
            try:
                os.write(self.fd, data)
            except OSError:
                pass

    def guard_resolve(self, approve: bool):
        """Called when user responds to a guard_confirm dialog."""
        if self._guard_pending is None:
            return
        self._guard_pending = None
        held = self._guard_held
        self._guard_held = b""
        self._guard_line = b""
        if self.fd is None:
            return
        try:
            if approve:
                # Release the held data (terminator + whatever followed)
                os.write(self.fd, held)
            else:
                # Cancel: send Ctrl-C so bash clears its readline buffer and shows a fresh prompt.
                # Drop the held data.
                os.write(self.fd, b"\x03")
        except OSError:
            pass

    def set_guard(self, enabled: bool):
        was = self.guard_enabled
        self.guard_enabled = bool(enabled)
        # If we're turning off while a prompt is pending, auto-approve (fail-open to avoid stuck session)
        if was and not self.guard_enabled and self._guard_pending is not None:
            self.guard_resolve(True)

    def is_alive(self):
        if not self.pid:
            return False
        try:
            return os.waitpid(self.pid, os.WNOHANG)[0] == 0
        except ChildProcessError:
            return False

    def _on_output(self):
        try:
            data = os.read(self.fd, 65536)
            if not data:
                return
            self.scrollback.extend(data)
            if len(self.scrollback) > SCROLLBACK_MAX:
                self.scrollback = self.scrollback[-SCROLLBACK_MAX:]
            asyncio.ensure_future(self._broadcast(data))
        except OSError:
            try:
                self.loop.remove_reader(self.fd)
            except Exception:
                pass

    async def _broadcast(self, data):
        msg = json.dumps({"t": "o", "sid": self.sid, "d": base64.b64encode(data).decode()}) + "\n"
        raw = msg.encode()
        dead = set()
        for w in self.clients:
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

# Known AI binaries and where to find them
AI_COMMANDS = {
    "claude": "claude",
    "ollama": "ollama",
    "llamacpp": "llama-cli",
    "localai": "local-ai",
    "gpt4all": "gpt4all",
    "bash": "bash",
    "codex": "codex",
    "gemini": "gemini",
    "goose": "goose",
    "qwen": "qwen",
    "aider": "aider",
    "llm": "llm",
    "sgpt": "sgpt",
}

# Default args that switch a CLI into interactive/REPL mode.
AI_DEFAULT_ARGS = {
    "goose": ["session"],
    "llm": ["chat"],
    "sgpt": ["--repl", "temp"],
}

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

EXTRA_PATHS = {
    "claude": _user_bin_paths("claude"),
    "codex": _user_bin_paths("codex"),
    "gemini": _user_bin_paths("gemini"),
    "goose": _user_bin_paths("goose"),
    "qwen": _user_bin_paths("qwen"),
    "aider": _user_bin_paths("aider") + [os.path.expanduser("~/.local/pipx/venvs/aider-chat/bin/aider")],
    "llm": _user_bin_paths("llm"),
    "sgpt": _user_bin_paths("sgpt"),
}


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
    for sess in sessions.values():
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
                        resp = {"t": "process_conflict", "sid": sid, "ai": ai_type,
                                "pid": ext_pid, "cwd": cwd,
                                "m": f"{ai_name} already running in {cwd} (PID {ext_pid})"}
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
                sess = sessions.pop(sid, None)
                if sess:
                    sess.kill()
                    log.info(f"Session {sid} stopped")
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
        # Remove this writer from all sessions (but keep sessions alive!)
        for sess in sessions.values():
            sess.clients.discard(writer)
        try:
            writer.close()
        except Exception:
            pass
        log.info(f"Connector detached ({sum(len(s.clients) for s in sessions.values())} clients remaining)")


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

    log.info(f"PTY Manager ready on {SOCKET_PATH} (multi-session)")
    await stop

    # Cleanup
    for sess in sessions.values():
        sess.kill()
    server.close()
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    log.info("Shutdown")


if __name__ == "__main__":
    asyncio.run(main())
