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

    def __init__(self, sid, cmd, cwd, loop, cmd_args=None):
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
        if self.fd is not None:
            try:
                os.write(self.fd, data)
            except OSError:
                pass

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
}

EXTRA_PATHS = {
    "claude": [
        os.path.expanduser("~/.local/bin/claude"),
        "/root/.local/bin/claude",
        "/usr/local/bin/claude",
        "/usr/bin/claude",
    ],
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

    # Send scrollback for all active sessions
    for sess in sessions.values():
        if sess.scrollback:
            try:
                msg = json.dumps({"t": "o", "sid": sess.sid, "d": base64.b64encode(bytes(sess.scrollback)).decode()}) + "\n"
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
                        if ext_pid in own_pids:
                            log.info(f"Force-killing own session PID {ext_pid} in {cwd}")
                            try:
                                os.kill(ext_pid, signal.SIGTERM)
                            except (ProcessLookupError, PermissionError):
                                pass
                        else:
                            log.warning(f"Cannot kill external PID {ext_pid}")
                            resp = {"t": "process_conflict", "sid": sid, "ai": ai_type,
                                    "pid": ext_pid, "cwd": cwd,
                                    "m": f"External process (PID {ext_pid}) is running. Run: kill {ext_pid}"}
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
                    cmd_args = []

                sess = PtySession(sid, cmd, cwd, asyncio.get_event_loop(), cmd_args=cmd_args)
                sess.clients.add(writer)
                sess.spawn()
                sessions[sid] = sess

                ai_name = ai_model or ai_base.title()
                if ai_base == "claude":
                    ai_name = "Claude Code"
                elif ai_base == "ollama" and ai_model:
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

            elif t == "input":
                sess = sessions.get(sid)
                if sess:
                    sess.write(base64.b64decode(msg.get("d", "")))

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
