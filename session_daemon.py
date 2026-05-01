"""Per-session supervisor daemon — keeps a PTY alive across pty-manager restarts.

Pure-stdlib ("dtach in Python"). For each AI session pty-manager wants to
spawn, this module forks a daemonised supervisor process that:
  - opens a PTY pair
  - forks the actual AI process (claude / ollama / bash / …) as the slave
  - holds the master FD for the lifetime of the AI process
  - listens on a Unix-domain socket /run/aiterm/sess_<sid>.sock
  - pumps bytes between the master FD and any number of connected clients

When pty-manager (or the connector, or the hub) restarts, the supervisor
keeps running.  Pty-manager comes back, scans /run/aiterm/, reconnects to
each socket, and resumes I/O — the user's claude session is uninterrupted.

Wire format on the socket: a tiny binary framing.

  Type 0x01  raw I/O        — body is bytes to write to / from PTY
  Type 0x02  resize          — body is "ROWSxCOLS" UTF-8 (max 16 bytes)
  Type 0x03  meta request    — request a JSON description of the session
  Type 0x04  meta response   — JSON body
  Type 0x05  kill            — supervisor SIGTERMs the AI then exits

Frame layout: |type:1B|length:4B big-endian|body:length B|

The TYPE-prefixed framing keeps control messages out of band so an attacker
who somehow injected bytes into a session can never escape into a control
message (they'd need to control the framing layer of the socket itself,
which is local-Unix-domain only and 0600).
"""
import errno
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
import termios
import time

SOCK_DIR = "/run/aiterm"
SOCK_MODE = 0o600
DIR_MODE = 0o700

# Frame types — keep in sync with PtySession client below.
T_DATA = 0x01
T_RESIZE = 0x02
T_META_REQ = 0x03
T_META_RESP = 0x04
T_KILL = 0x05         # SIGTERM — gives the AI a chance to clean up
T_KILL_HARD = 0x06    # SIGKILL — for stuck TUIs that ignore SIGTERM


def _ensure_sock_dir():
    """Create the socket directory if missing. Falls back to /tmp/aiterm-<uid>
    when /run is not writable (rare on systemd boxes, common on minimal
    containers)."""
    candidates = [SOCK_DIR, f"/tmp/aiterm-{os.getuid()}"]
    for d in candidates:
        try:
            os.makedirs(d, mode=DIR_MODE, exist_ok=True)
            os.chmod(d, DIR_MODE)
            return d
        except (PermissionError, OSError):
            continue
    raise RuntimeError("no writable socket dir for AITerm sessions")


def sock_path_for(sid):
    return os.path.join(_ensure_sock_dir(), f"sess_{sid}.sock")


def meta_path_for(sid):
    return sock_path_for(sid) + ".meta"


# ── Frame helpers ────────────────────────────────────────────────

def pack_frame(ftype, body):
    if isinstance(body, str):
        body = body.encode()
    return bytes([ftype]) + struct.pack(">I", len(body)) + body


def read_frame(fd_or_sock):
    """Read one frame from a file descriptor or socket. Returns (type, body)
    or (None, None) on EOF / error."""
    if hasattr(fd_or_sock, "recv"):
        recv = fd_or_sock.recv
    else:
        recv = lambda n: os.read(fd_or_sock, n)
    try:
        head = b""
        while len(head) < 5:
            chunk = recv(5 - len(head))
            if not chunk:
                return None, None
            head += chunk
        ftype = head[0]
        length = struct.unpack(">I", head[1:5])[0]
        if length > 16 * 1024 * 1024:  # 16 MB sanity cap
            return None, None
        body = b""
        while len(body) < length:
            chunk = recv(length - len(body))
            if not chunk:
                return None, None
            body += chunk
        return ftype, body
    except (OSError, ConnectionError):
        return None, None


def send_frame(sock, ftype, body):
    try:
        sock.sendall(pack_frame(ftype, body))
        return True
    except (OSError, ConnectionError, BrokenPipeError):
        return False


# ── The supervisor process ───────────────────────────────────────

def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


def _supervisor_main(sid, cmd, cwd, env, master_fd, slave_fd, ai_pid, sock_path):
    """The supervisor runs here. We hold master_fd for the lifetime of ai_pid.
    Slave_fd was already given to the AI process — we close our copy."""
    try:
        os.close(slave_fd)
    except OSError:
        pass

    # Clean up any previous socket file (stale from crash).
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    # Set up the listening socket. 0600 perms — only the same user can read/write.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    os.chmod(sock_path, SOCK_MODE)
    server.listen(8)
    server.setblocking(False)

    # Make master FD non-blocking so the poll loop can drain reads cleanly.
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    # Drop a sidecar metadata file pty-manager can read on reattach without
    # connecting — useful for fast inventory at startup.
    meta = {
        "sid": sid, "cmd": cmd, "cwd": cwd,
        "started_at": int(time.time()),
        "ai_pid": ai_pid, "supervisor_pid": os.getpid(),
    }
    try:
        with open(meta_path_for(sid), "w") as f:
            json.dump(meta, f)
        os.chmod(meta_path_for(sid), 0o600)
    except OSError:
        pass

    # Per-client read buffers (frames may arrive in pieces).
    clients = {}  # fd -> {"sock": socket, "rbuf": bytearray}

    # Bounded scrollback so a long-running session has something for the next
    # client to bootstrap with — first 64 KB and last 64 KB of output. Real
    # scrollback lives at the hub; this is just the "wake-up" replay.
    scrollback_head = bytearray()
    scrollback_tail = bytearray()
    HEAD_CAP = 64 * 1024
    TAIL_CAP = 64 * 1024

    def buffer_output(data):
        if len(scrollback_head) < HEAD_CAP:
            need = HEAD_CAP - len(scrollback_head)
            scrollback_head.extend(data[:need])
        scrollback_tail.extend(data)
        if len(scrollback_tail) > TAIL_CAP:
            del scrollback_tail[: len(scrollback_tail) - TAIL_CAP]

    poll = select.poll()
    poll.register(master_fd, select.POLLIN | select.POLLERR | select.POLLHUP)
    poll.register(server.fileno(), select.POLLIN)

    def broadcast(data):
        """Send frame to every connected client; drop slow ones silently."""
        frame = pack_frame(T_DATA, data)
        for fd, c in list(clients.items()):
            try:
                c["sock"].sendall(frame)
            except (BrokenPipeError, ConnectionResetError, OSError, BlockingIOError):
                _drop_client(fd)

    def _drop_client(fd):
        c = clients.pop(fd, None)
        if not c:
            return
        try:
            poll.unregister(fd)
        except (KeyError, ValueError):
            pass
        try:
            c["sock"].close()
        except OSError:
            pass

    def _process_client_frame(c, ftype, body):
        if ftype == T_DATA:
            try:
                os.write(master_fd, body)
            except OSError:
                pass
        elif ftype == T_RESIZE:
            try:
                rows_s, _, cols_s = body.decode("ascii", "replace").partition("x")
                rows, cols = int(rows_s), int(cols_s)
                _set_winsize(master_fd, rows, cols)
            except (UnicodeDecodeError, ValueError):
                pass
        elif ftype == T_META_REQ:
            payload = json.dumps({
                "sid": sid, "cmd": cmd, "cwd": cwd,
                "started_at": meta["started_at"],
                "ai_pid": ai_pid,
                "head_b64": __import__("base64").b64encode(bytes(scrollback_head)).decode(),
                "tail_b64": __import__("base64").b64encode(bytes(scrollback_tail)).decode(),
            }).encode()
            send_frame(c["sock"], T_META_RESP, payload)
        elif ftype == T_KILL:
            try:
                os.kill(ai_pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            # Loop will exit via waitpid below.
        elif ftype == T_KILL_HARD:
            # Stuck-TUI bypass: skip SIGTERM and go straight to SIGKILL.
            # Used by the dashboard's "Force close" path when normal
            # stop_ai didn't drop the session within the timeout.
            try:
                os.kill(ai_pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    while True:
        # Reap AI process if it exited.
        try:
            pid, _ = os.waitpid(ai_pid, os.WNOHANG)
            if pid == ai_pid:
                break
        except ChildProcessError:
            break

        events = poll.poll(1000)
        for fd, ev in events:
            if fd == server.fileno():
                try:
                    cli, _ = server.accept()
                    cli.setblocking(False)
                    clients[cli.fileno()] = {"sock": cli, "rbuf": bytearray()}
                    poll.register(cli.fileno(),
                                  select.POLLIN | select.POLLHUP | select.POLLERR)
                    # Bootstrap newcomer with the scrollback head+tail.
                    if scrollback_head or scrollback_tail:
                        elide = "\r\n[... live session - output continues below ...]\r\n".encode()
                        send_frame(cli, T_DATA,
                                   bytes(scrollback_head) +
                                   (elide if len(scrollback_head) >= HEAD_CAP else b"") +
                                   bytes(scrollback_tail))
                except (BlockingIOError, OSError):
                    pass
            elif fd == master_fd:
                if ev & (select.POLLERR | select.POLLHUP):
                    # Master closed — usually means AI exited
                    try:
                        os.read(master_fd, 65536)  # drain
                    except OSError:
                        pass
                    break
                try:
                    data = os.read(master_fd, 65536)
                    if not data:
                        break
                    broadcast(data)
                    buffer_output(data)
                except BlockingIOError:
                    pass
                except OSError:
                    break
            else:
                if ev & (select.POLLHUP | select.POLLERR):
                    _drop_client(fd)
                    continue
                c = clients.get(fd)
                if not c:
                    continue
                try:
                    chunk = c["sock"].recv(65536)
                except (BlockingIOError, ConnectionResetError, OSError):
                    _drop_client(fd)
                    continue
                if not chunk:
                    _drop_client(fd)
                    continue
                c["rbuf"].extend(chunk)
                # Drain complete frames from rbuf.
                while len(c["rbuf"]) >= 5:
                    length = struct.unpack(">I", c["rbuf"][1:5])[0]
                    if length > 16 * 1024 * 1024:
                        _drop_client(fd)
                        break
                    if len(c["rbuf"]) < 5 + length:
                        break
                    ftype = c["rbuf"][0]
                    body = bytes(c["rbuf"][5:5 + length])
                    del c["rbuf"][:5 + length]
                    _process_client_frame(c, ftype, body)
        else:
            continue
        break  # outer while: master broke

    # ── Cleanup ──
    # Make sure AI is gone.
    try:
        os.kill(ai_pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.05)
            try:
                os.kill(ai_pid, 0)
            except ProcessLookupError:
                break
        else:
            os.kill(ai_pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        os.waitpid(ai_pid, 0)
    except ChildProcessError:
        pass

    # Notify clients of EOF and close.
    for fd in list(clients):
        c = clients[fd]
        try:
            send_frame(c["sock"], T_DATA, b"\r\n[session ended]\r\n")
            c["sock"].close()
        except OSError:
            pass

    try:
        server.close()
    except OSError:
        pass
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass
    try:
        os.unlink(meta_path_for(sid))
    except FileNotFoundError:
        pass


def spawn(sid, argv, cwd, env):
    """Spawn a daemonised supervisor for one AI session. Returns
    (sock_path, ai_pid). The supervisor is fully detached — pty-manager can
    die without affecting it."""
    if not isinstance(argv, list):
        argv = [argv]
    sock_path = sock_path_for(sid)

    # Pipe for parent ← daemon to send ai_pid back.
    rfd, wfd = os.pipe()

    pid1 = os.fork()
    if pid1 != 0:
        # Original (pty-manager) — wait for first fork to exit
        os.close(wfd)
        try:
            os.waitpid(pid1, 0)
        except ChildProcessError:
            pass
        # Read ai_pid from the daemon
        try:
            data = os.read(rfd, 32)
        except OSError:
            data = b""
        os.close(rfd)
        try:
            ai_pid = int(data.decode().strip())
        except (ValueError, AttributeError):
            ai_pid = 0
        # Wait briefly for socket to exist before returning
        for _ in range(30):
            if os.path.exists(sock_path):
                break
            time.sleep(0.02)
        return sock_path, ai_pid

    # First child: setsid, fork again, exit middle
    os.close(rfd)
    os.setsid()
    pid2 = os.fork()
    if pid2 != 0:
        os._exit(0)

    # Grandchild — the supervisor daemon.
    # Open PTY pair
    master_fd, slave_fd = os.openpty()
    # Default sane size
    _set_winsize(master_fd, 24, 80)

    ai_pid = os.fork()
    if ai_pid == 0:
        # AI process: become the slave
        try:
            os.close(master_fd)
        except OSError:
            pass
        os.setsid()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        except OSError:
            pass
        os.dup2(slave_fd, 0)
        os.dup2(slave_fd, 1)
        os.dup2(slave_fd, 2)
        if slave_fd > 2:
            os.close(slave_fd)
        try:
            os.chdir(cwd)
        except OSError:
            pass
        try:
            os.execvpe(argv[0], argv, env)
        except OSError as e:
            sys.stderr.write(f"[session_daemon] exec failed: {e}\n")
            os._exit(127)

    # Send AI pid back to pty-manager
    try:
        os.write(wfd, str(ai_pid).encode() + b"\n")
    except OSError:
        pass
    os.close(wfd)

    # Detach stdio so logs don't pollute systemd journals
    nullfd = os.open(os.devnull, os.O_RDWR)
    for std in (0, 1, 2):
        try:
            os.dup2(nullfd, std)
        except OSError:
            pass
    if nullfd > 2:
        os.close(nullfd)

    # Set process title-ish via argv[0] hack (best effort, optional)
    try:
        sys.argv[0] = f"aiterm-sess-{sid}"
    except Exception:
        pass

    # Run the supervisor loop
    try:
        _supervisor_main(sid, argv, cwd, env, master_fd, slave_fd, ai_pid, sock_path)
    except Exception:
        pass
    os._exit(0)


# ── Discovery: list existing supervised sessions ──────────────────

def discover_sessions():
    """Scan SOCK_DIR for live aiterm session sockets. Returns list of dicts:
    {sid, sock_path, meta_path, meta (if readable), ai_alive (bool)}."""
    out = []
    try:
        sock_dir = _ensure_sock_dir()
    except RuntimeError:
        return out
    try:
        names = os.listdir(sock_dir)
    except OSError:
        return out
    for name in names:
        if not (name.startswith("sess_") and name.endswith(".sock")):
            continue
        sid = name[len("sess_"):-len(".sock")]
        sock_path = os.path.join(sock_dir, name)
        meta_path = sock_path + ".meta"
        meta = None
        try:
            with open(meta_path) as f:
                meta = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass
        ai_alive = False
        ai_pid = (meta or {}).get("ai_pid")
        if ai_pid:
            try:
                os.kill(ai_pid, 0)
                ai_alive = True
            except (ProcessLookupError, PermissionError):
                ai_alive = False
        out.append({
            "sid": sid,
            "sock_path": sock_path,
            "meta_path": meta_path,
            "meta": meta,
            "ai_alive": ai_alive,
        })
    return out


def cleanup_dead_sessions():
    """Remove sockets whose supervisor / AI is gone. Returns count cleaned."""
    n = 0
    for s in discover_sessions():
        if s["ai_alive"]:
            continue
        # Either supervisor crashed or AI died and supervisor cleanup didn't
        # finish. Either way, the socket is dead — try a probe connect; if
        # that fails, unlink.
        try:
            cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cli.settimeout(0.2)
            cli.connect(s["sock_path"])
            cli.close()
            # Connection succeeded → supervisor is up; trust that for now.
            continue
        except OSError:
            pass
        for p in (s["sock_path"], s["meta_path"]):
            try:
                os.unlink(p)
                n += 1
            except FileNotFoundError:
                pass
    return n
