#!/bin/bash
set -e

HUB_URL="wss://www.aiterm.io/connector"
API_URL="https://www.aiterm.io"

RED="\033[0;31m"; GREEN="\033[0;32m"; CYAN="\033[0;36m"; DIM="\033[2m"; BOLD="\033[1m"; YELLOW="\033[0;33m"; NC="\033[0m"
info()  { echo -e "${CYAN}  ▸${NC} $1"; }
ok()    { echo -e "${GREEN}  ✓${NC} $1"; }
fail()  { echo -e "${RED}  ✗${NC} $1"; exit 1; }

# ── CLI flags ─────────────────────────────────────────────────
# --pair / --repair : force a new pairing even if an existing installation is
#                     detected. Useful when the machine is no longer recognised
#                     by the hub or should be re-linked to a different account.
FORCE_PAIR=0
for arg in "$@"; do
    case "$arg" in
        --pair|--repair|--reinstall) FORCE_PAIR=1 ;;
    esac
done

ensure_path() {
    # Add ~/.local/bin to PATH if not already there (user mode)
    local BDIR="$1"
    case ":$PATH:" in
        *":$BDIR:"*) return ;;
    esac
    # Detect shell config
    local SHELL_RC=""
    if [ -f "$HOME/.bashrc" ]; then SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.profile" ]; then SHELL_RC="$HOME/.profile"
    fi
    if [ -n "$SHELL_RC" ]; then
        if ! grep -q "$BDIR" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "export PATH=\"$BDIR:\$PATH\"" >> "$SHELL_RC"
            ok "Added $BDIR to PATH in $(basename $SHELL_RC)"
        fi
    fi
    export PATH="$BDIR:$PATH"
}

# ── Detect install mode ──
setup_user_mode() {
    TARGET_USER="$1"
    TARGET_HOME=$(eval echo "~$TARGET_USER")
    MODE="user"
    INSTALL_DIR="$TARGET_HOME/.local/share/aiterm"
    BIN_DIR="$TARGET_HOME/.local/bin"
    RUN_AS="$TARGET_USER"
    if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
        SVC_CMD="sudo -u $TARGET_USER XDG_RUNTIME_DIR=/run/user/$(id -u $TARGET_USER) systemctl --user"
    else
        SVC_CMD="systemctl --user"
    fi
    mkdir -p "$BIN_DIR" "$INSTALL_DIR"
    if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then chown -R "$TARGET_USER:" "$INSTALL_DIR" "$BIN_DIR" 2>/dev/null; fi
}

# Write systemd unit files (idempotent). Sets PTY_UNIT_CHANGED / CONN_UNIT_CHANGED / SVC_DIR.
write_units() {
    PTY_UNIT_CHANGED=0; CONN_UNIT_CHANGED=0
    if [ "$MODE" = "system" ]; then
        SVC_DIR="/etc/systemd/system"
    else
        TARGET_USER="${RUN_AS:-$(whoami)}"
        TARGET_HOME=$(eval echo "~$TARGET_USER")
        SVC_DIR="$TARGET_HOME/.config/systemd/user"
        mkdir -p "$SVC_DIR"
        if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then chown -R "$TARGET_USER:" "$SVC_DIR"; fi
    fi

    local PTY_OLD CONN_OLD PTY_NEW CONN_NEW
    PTY_OLD=$(md5sum "$SVC_DIR/aiterm-pty.service" 2>/dev/null | awk '{print $1}')
    CONN_OLD=$(md5sum "$SVC_DIR/aiterm-connector.service" 2>/dev/null | awk '{print $1}')

    # ProtectKernelLogs needs systemd >= 244 (Rocky 8 ships 239, would emit
    # "Unknown lvalue" warnings to the journal). Detect once and gate the
    # directive — service stays hardened on modern systemd, silent on old.
    local SYSTEMD_VER PROTECT_KERNEL_LOGS=""
    SYSTEMD_VER=$(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')
    if [ -n "$SYSTEMD_VER" ] && [ "$SYSTEMD_VER" -ge 244 ] 2>/dev/null; then
        PROTECT_KERNEL_LOGS="${PROTECT_KERNEL_LOGS}"
    fi

    if [ "$MODE" = "system" ]; then
        cat > "$SVC_DIR/aiterm-pty.service" << SVCEOF
[Unit]
Description=AITerm PTY Manager
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/pty-manager.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=3
# KillMode=process — only signal pty-manager itself on stop/restart.
# Per-session supervisors (session_daemon) double-fork out of the cgroup
# but mind: with the systemd default (control-group) those orphaned
# children would still receive SIGTERM. process mode keeps them alive
# so AI sessions survive a pty-manager restart.
KillMode=process
SendSIGKILL=yes
TimeoutStopSec=10
# Hardening (minimal: must spawn user shells with full fs access & setuid/sudo)
ProtectKernelTunables=yes
ProtectKernelModules=yes
${PROTECT_KERNEL_LOGS}
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
[Install]
WantedBy=multi-user.target
SVCEOF

        cat > "$SVC_DIR/aiterm-connector.service" << SVCEOF
[Unit]
Description=AITerm Connector
After=network.target aiterm-pty.service
Wants=aiterm-pty.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/connector.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=3
# Hardening (connector is network-exposed, does not spawn user shells)
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
${PROTECT_KERNEL_LOGS}
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
[Install]
WantedBy=multi-user.target
SVCEOF
    else
        cat > "$SVC_DIR/aiterm-pty.service" << SVCEOF
[Unit]
Description=AITerm PTY Manager
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/pty-manager.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=3
# KillMode=process — keep per-session supervisors alive when pty-manager
# itself restarts. See system-mode unit above for the full reasoning.
KillMode=process
SendSIGKILL=yes
TimeoutStopSec=10
# Hardening (minimal: must spawn user shells)
ProtectKernelTunables=yes
ProtectKernelModules=yes
${PROTECT_KERNEL_LOGS}
ProtectControlGroups=yes
LockPersonality=yes
RestrictRealtime=yes
[Install]
WantedBy=default.target
SVCEOF

        cat > "$SVC_DIR/aiterm-connector.service" << SVCEOF
[Unit]
Description=AITerm Connector
After=aiterm-pty.service
Wants=aiterm-pty.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/connector.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=3
# Hardening (connector is network-exposed)
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
${PROTECT_KERNEL_LOGS}
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictNamespaces=yes
RestrictRealtime=yes
[Install]
WantedBy=default.target
SVCEOF
        if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then chown "$TARGET_USER:" "$SVC_DIR"/aiterm-*.service; fi
    fi

    PTY_NEW=$(md5sum "$SVC_DIR/aiterm-pty.service" 2>/dev/null | awk '{print $1}')
    CONN_NEW=$(md5sum "$SVC_DIR/aiterm-connector.service" 2>/dev/null | awk '{print $1}')
    [ "$PTY_OLD" != "$PTY_NEW" ] && PTY_UNIT_CHANGED=1
    [ "$CONN_OLD" != "$CONN_NEW" ] && CONN_UNIT_CHANGED=1
    # Force success exit. Otherwise — if both unit files are byte-identical
    # to the previous install — the trailing `[ ] && ...` returns 1 and the
    # function inherits that as its exit code, which trips `set -e` at the
    # call site even though nothing actually went wrong. Bash's "&& list"
    # exemption only applies inside the function body, not to its return.
    return 0
}

# Signed-download helper. Verifies Ed25519-signed manifest + per-file SHA-256
# against an embedded public key. Prevents a compromised CDN/TLS endpoint from
# shipping malicious code during first install OR update.
# Requires python3 + cryptography (must be installed BEFORE calling this).
signed_download() {
    python3 - "$API_URL" "$INSTALL_DIR" "$BIN_DIR" << 'PYEOF'
import hashlib, json, os, ssl, sys, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST_PUBKEY_HEX = "bc5e9a344e32ec65e490d725f911b8f94c5e8b17812a617da776e8ac837f2aca"
api_url, install_dir, bin_dir = sys.argv[1:4]

FILES = [
    ("connector.py",         f"{install_dir}/connector.py"),
    ("pty-manager.py",       f"{install_dir}/pty-manager.py"),
    ("session_daemon.py",    f"{install_dir}/session_daemon.py"),
    ("doctor.py",            f"{install_dir}/doctor.py"),
    ("registry_loader.py",   f"{install_dir}/registry_loader.py"),
    ("aiterm",               f"{bin_dir}/aiterm"),
    # Signed registries — single-source-of-truth metadata for AIs / guard
    # patterns / extra doctor checks. Adding a new AI is a JSON edit on
    # the hub; customer connectors pick it up at the next aiterm update.
    ("ai-registry.json",     f"{install_dir}/ai-registry.json"),
    ("guard-patterns.json",  f"{install_dir}/guard-patterns.json"),
    ("doctor-checks.json",   f"{install_dir}/doctor-checks.json"),
]

ctx = ssl.create_default_context()
def fetch(path):
    with urllib.request.urlopen(f"{api_url}/dl/{path}", context=ctx, timeout=20) as r:
        return r.read()

try:
    manifest_bytes = fetch("manifest.json")
    sig_hex = fetch("manifest.sig").decode().strip()
except Exception as e:
    print(f"FETCH FAIL: {e}", file=sys.stderr); sys.exit(1)

try:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(MANIFEST_PUBKEY_HEX))
    pub.verify(bytes.fromhex(sig_hex), manifest_bytes)
except Exception:
    print("MANIFEST SIGNATURE INVALID - install aborted", file=sys.stderr); sys.exit(2)

try:
    manifest = json.loads(manifest_bytes)
except Exception as e:
    print(f"MANIFEST MALFORMED: {e}", file=sys.stderr); sys.exit(3)

for fname, target in FILES:
    expected = manifest.get(fname)
    if not expected:
        print(f"{fname}: not listed in signed manifest", file=sys.stderr); sys.exit(4)
    try:
        data = fetch(fname)
    except Exception as e:
        print(f"{fname}: download failed: {e}", file=sys.stderr); sys.exit(5)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        print(f"{fname}: HASH MISMATCH (expected {expected[:16]}, got {actual[:16]})", file=sys.stderr); sys.exit(6)
    os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
    with open(target, "wb") as f:
        f.write(data)
    os.chmod(target, 0o755)
    print(f"    {fname}: verified ({len(data)} bytes)")
PYEOF
    local rc=$?
    if [ $rc -ne 0 ]; then
        fail "Signature/hash verification failed (rc=$rc) - no files were installed"
    fi
}

ensure_python_deps() {
    # Required BEFORE signed_download can run.
    command -v python3 >/dev/null 2>&1 || {
        if [ "$MODE" = "system" ]; then
            (apt-get update -qq 2>/dev/null && apt-get install -y -qq python3 2>/dev/null) \
                || dnf install -y python3 2>/dev/null \
                || fail "python3 not available — install via your package manager"
        else
            fail "python3 required; install it first (e.g. sudo apt install python3)"
        fi
    }

    # What's missing right now?
    local need_ws need_crypto pkg_mgr=""
    python3 -c "import websockets" 2>/dev/null && need_ws=0 || need_ws=1
    python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null \
        && need_crypto=0 || need_crypto=1
    [ "$need_ws" = 0 ] && [ "$need_crypto" = 0 ] && return 0

    if command -v apt-get >/dev/null 2>&1; then pkg_mgr=apt
    elif command -v dnf >/dev/null 2>&1; then pkg_mgr=dnf
    elif command -v zypper >/dev/null 2>&1; then pkg_mgr=zypper
    elif command -v pacman >/dev/null 2>&1; then pkg_mgr=pacman
    elif command -v apk >/dev/null 2>&1; then pkg_mgr=apk
    fi

    # Step 1: distro packages first — clean install everywhere we can,
    # no PEP-668 friction, no pip dependency. Each distro family uses
    # slightly different package names:
    #   apt/dnf/zypper:  python3-websockets, python3-cryptography
    #   pacman:          python-websockets, python-cryptography  (Arch's python IS python3)
    #   apk:             py3-websockets, py3-cryptography        (Alpine convention)
    if [ -n "$pkg_mgr" ]; then
        local ws_pkg crypto_pkg pkgs=""
        case "$pkg_mgr" in
            apt|dnf|zypper) ws_pkg=python3-websockets; crypto_pkg=python3-cryptography ;;
            pacman)         ws_pkg=python-websockets;  crypto_pkg=python-cryptography  ;;
            apk)            ws_pkg=py3-websockets;     crypto_pkg=py3-cryptography     ;;
        esac
        [ "$need_ws" = 1 ]     && pkgs="$pkgs $ws_pkg"
        [ "$need_crypto" = 1 ] && pkgs="$pkgs $crypto_pkg"
        if [ -n "$pkgs" ]; then
            case "$pkg_mgr" in
                apt)
                    apt-get update -qq 2>/dev/null || true
                    # shellcheck disable=SC2086
                    apt-get install -y -qq $pkgs 2>/dev/null || true ;;
                dnf)
                    # shellcheck disable=SC2086
                    dnf install -y $pkgs 2>/dev/null || true ;;
                zypper)
                    # shellcheck disable=SC2086
                    zypper --non-interactive install -y $pkgs 2>/dev/null || true ;;
                pacman)
                    # -Sy refreshes the package db (Arch needs this on fresh boxes
                    # or rolling repos go stale fast). --noconfirm avoids prompts.
                    pacman -Sy --noconfirm --needed --quiet 2>/dev/null || true
                    # shellcheck disable=SC2086
                    pacman -S --noconfirm --needed --quiet $pkgs 2>/dev/null || true ;;
                apk)
                    # --no-cache: don't store the index, keep the image lean.
                    # Standard Alpine container/box idiom.
                    # shellcheck disable=SC2086
                    apk add --no-cache $pkgs 2>/dev/null || true ;;
            esac
        fi
        python3 -c "import websockets" 2>/dev/null && need_ws=0
        python3 -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey" 2>/dev/null \
            && need_crypto=0
    fi
    [ "$need_ws" = 0 ] && [ "$need_crypto" = 0 ] && return 0

    # Step 2: pip fallback. Ensure pip exists first — Debian doesn't ship it
    # by default, which is exactly how customers hit "websockets install failed"
    # with zero info: all three pip attempts ran against a missing pip module.
    if ! python3 -m pip --version >/dev/null 2>&1; then
        case "$pkg_mgr" in
            apt)    apt-get install -y -qq python3-pip 2>/dev/null || true ;;
            dnf)    dnf install -y python3-pip 2>/dev/null || true ;;
            zypper) zypper --non-interactive install -y python3-pip 2>/dev/null || true ;;
            pacman) pacman -S --noconfirm --needed --quiet python-pip 2>/dev/null || true ;;
            apk)    apk add --no-cache py3-pip 2>/dev/null || true ;;
        esac
    fi
    python3 -m pip --version >/dev/null 2>&1 \
        || fail "pip is not available. Install via your package manager: apt/dnf/zypper install python3-pip, pacman -S python-pip, or apk add py3-pip."

    # --break-system-packages only exists on pip >= 23.0 (PEP 668 era). Older
    # pip doesn't enforce PEP 668 anyway, so we skip the flag for it — using
    # the flag with an older pip aborts with "no such option" (seen on
    # OpenSUSE Leap, RHEL 8, older Debian).
    local pip_bsp=""
    if python3 -m pip install --help 2>&1 | grep -q -- "--break-system-packages"; then
        pip_bsp="--break-system-packages"
    fi

    # Step 3: pip install. Show real stderr on failure so the customer sees why.
    local pip_err="/tmp/aiterm-pip-err.$$"
    trap 'rm -f "$pip_err"' RETURN
    if [ "$need_ws" = 1 ]; then
        # shellcheck disable=SC2086
        if ! python3 -m pip install --quiet $pip_bsp websockets 2>"$pip_err"; then
            echo "" >&2
            echo "  pip install websockets failed. Output:" >&2
            sed 's/^/    /' "$pip_err" >&2
            fail "websockets install failed (see error above)"
        fi
    fi
    if [ "$need_crypto" = 1 ]; then
        # shellcheck disable=SC2086
        if ! python3 -m pip install --quiet $pip_bsp cryptography 2>"$pip_err"; then
            echo "" >&2
            echo "  pip install cryptography failed. Output:" >&2
            sed 's/^/    /' "$pip_err" >&2
            fail "cryptography install failed (see error above)"
        fi
    fi
}

# Check for existing installations first
EXISTING_SYSTEM=0; EXISTING_USER=0
[ -f "/opt/aiterm/connector.json" ] && EXISTING_SYSTEM=1
[ -f "$HOME/.local/share/aiterm/connector.json" ] && EXISTING_USER=1

if [ "$EXISTING_SYSTEM" -eq 1 ] || [ "$EXISTING_USER" -eq 1 ]; then
    # Update mode — pick the install path that matches the CURRENT user.
    # Both can coexist on the same box (root has /opt/aiterm, non-root user
    # has their own ~/.local/share/aiterm). Picking system unconditionally
    # makes a non-root invocation crash with "Permission denied" on the
    # first cp to /opt/aiterm/.
    if [ "$(id -u)" -eq 0 ] && [ "$EXISTING_SYSTEM" -eq 1 ]; then
        # Root + system-wide install present -> update system
        MODE="system"; INSTALL_DIR="/opt/aiterm"; BIN_DIR="/usr/local/bin"; SVC_CMD="systemctl"
    elif [ "$EXISTING_USER" -eq 1 ]; then
        # User install present (and either we're non-root, or we're root
        # without a system install) -> update the per-user install
        setup_user_mode "$(whoami)"
    else
        # Only system install exists, but we're non-root. Can't touch
        # /opt/aiterm/ from here.
        fail "A system-wide install exists at /opt/aiterm/ but you don't have write access to it. Re-run as root with sudo, or have your admin do the update."
    fi
elif [ "$(id -u)" -eq 0 ]; then
    # Root: ask for mode
    echo ""
    echo -e "${BOLD}  Installation mode:${NC}"
    echo ""
    echo -e "  ${CYAN}1${NC}  System-wide  ${DIM}(/opt/aiterm, starts at boot)${NC}"
    echo -e "  ${CYAN}2${NC}  Per user     ${DIM}(~/.local/share/aiterm)${NC}"
    echo ""
    echo -ne "  Choice [1]: "
    read -r CHOICE < /dev/tty 2>/dev/null || CHOICE="1"
    CHOICE="${CHOICE:-1}"

    if [ "$CHOICE" = "2" ]; then
        echo -ne "  ${CYAN}Username${NC} [$(logname 2>/dev/null || echo $SUDO_USER)]: "
        read -r TARGET < /dev/tty 2>/dev/null || TARGET=""
        TARGET="${TARGET:-$(logname 2>/dev/null || echo ${SUDO_USER:-root})}"
        id "$TARGET" &>/dev/null || fail "User '$TARGET' does not exist"
        setup_user_mode "$TARGET"
    else
        MODE="system"
        INSTALL_DIR="/opt/aiterm"
        BIN_DIR="/usr/local/bin"
        SVC_CMD="systemctl"
    fi
else
    # Non-root: user mode
    setup_user_mode "$(whoami)"
fi

# ── Detect existing installation ──
# Extract hub_token from connector.json (if any) to decide update vs pair.
HAS_PAIRING=0
if [ -f "$INSTALL_DIR/connector.json" ]; then
    EXISTING_TOKEN=$(python3 -c "import json,sys
try:
    print(json.load(open('$INSTALL_DIR/connector.json')).get('hub_token',''))
except Exception:
    print('')" 2>/dev/null)
    if [ -n "$EXISTING_TOKEN" ]; then
        HAS_PAIRING=1
    fi
fi

# Update mode ONLY if: existing install + valid pairing + user didn't ask to re-pair
if [ -f "$INSTALL_DIR/connector.json" ] && [ -f "$INSTALL_DIR/connector.py" ] && [ "$HAS_PAIRING" -eq 1 ] && [ "$FORCE_PAIR" -eq 0 ]; then
    echo ""
    echo -e "${BOLD}  ┌──────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │       AITerm Connector Update         │${NC}"
    echo -e "${BOLD}  └──────────────────────────────────────┘${NC}"
    echo ""

    info "Existing installation found ($INSTALL_DIR)"

    # Hash files before download for conditional-restart logic.
    # Three change classes, ordered by impact:
    #   PTY_CHANGED   pty-manager.py or registry_loader.py changed
    #                 → full restart, kills active sessions
    #   CONN_CHANGED  connector.py changed
    #                 → connector restart, sessions survive (pty-mgr is independent)
    #   REG_CHANGED   only the JSON registries changed
    #                 → no restart needed; pty-manager hot-reloads via inotify-mtime
    #                   poll within 5 s. We send SIGHUP for instant reload.
    PTY_OLD=$(md5sum "$INSTALL_DIR/pty-manager.py" 2>/dev/null | awk '{print $1}')
    RL_OLD=$(md5sum "$INSTALL_DIR/registry_loader.py" 2>/dev/null | awk '{print $1}')
    CONN_OLD=$(md5sum "$INSTALL_DIR/connector.py" 2>/dev/null | awk '{print $1}')
    AIREG_OLD=$(md5sum "$INSTALL_DIR/ai-registry.json" 2>/dev/null | awk '{print $1}')
    GP_OLD=$(md5sum "$INSTALL_DIR/guard-patterns.json" 2>/dev/null | awk '{print $1}')
    DC_OLD=$(md5sum "$INSTALL_DIR/doctor-checks.json" 2>/dev/null | awk '{print $1}')

    ensure_python_deps
    info "Downloading + verifying signed manifest..."
    signed_download
    ok "Files updated (Ed25519 signature + SHA-256 verified)"
    [ "$BIN_DIR" != "/usr/local/bin" ] && ensure_path "$BIN_DIR"

    PTY_NEW=$(md5sum "$INSTALL_DIR/pty-manager.py" 2>/dev/null | awk '{print $1}')
    RL_NEW=$(md5sum "$INSTALL_DIR/registry_loader.py" 2>/dev/null | awk '{print $1}')
    CONN_NEW=$(md5sum "$INSTALL_DIR/connector.py" 2>/dev/null | awk '{print $1}')
    AIREG_NEW=$(md5sum "$INSTALL_DIR/ai-registry.json" 2>/dev/null | awk '{print $1}')
    GP_NEW=$(md5sum "$INSTALL_DIR/guard-patterns.json" 2>/dev/null | awk '{print $1}')
    DC_NEW=$(md5sum "$INSTALL_DIR/doctor-checks.json" 2>/dev/null | awk '{print $1}')

    PTY_CHANGED=0; CONN_CHANGED=0; REG_CHANGED=0
    [ "$PTY_OLD"  != "$PTY_NEW" ]  && PTY_CHANGED=1
    [ "$RL_OLD"   != "$RL_NEW" ]   && PTY_CHANGED=1   # loader change → reimport unsafe → full restart
    [ "$CONN_OLD" != "$CONN_NEW" ] && CONN_CHANGED=1
    [ "$AIREG_OLD" != "$AIREG_NEW" ] && REG_CHANGED=1
    [ "$GP_OLD"    != "$GP_NEW" ]    && REG_CHANGED=1
    [ "$DC_OLD"    != "$DC_NEW" ]    && REG_CHANGED=1

    # Permissions hardening: config must not be world-readable (F-01 fix for old installs)
    if [ -f "$INSTALL_DIR/connector.json" ]; then
        CUR_MODE=$(stat -c "%a" "$INSTALL_DIR/connector.json" 2>/dev/null)
        if [ "$CUR_MODE" != "600" ]; then
            chmod 600 "$INSTALL_DIR/connector.json" && ok "connector.json permissions fixed (was $CUR_MODE, now 600)"
        fi
    fi

    # Systemd units (rewrites if outdated — picks up hardening + path changes)
    if command -v systemctl &>/dev/null && [ -d /etc/systemd/system ] || [ -d "$HOME/.config/systemd/user" ]; then
        write_units
        if [ "$PTY_UNIT_CHANGED" = "1" ] || [ "$CONN_UNIT_CHANGED" = "1" ]; then
            $SVC_CMD daemon-reload 2>/dev/null
            ok "Systemd unit files updated"
            [ "$PTY_UNIT_CHANGED" = "1" ] && PTY_CHANGED=1
            [ "$CONN_UNIT_CHANGED" = "1" ] && CONN_CHANGED=1
        fi
    fi

    # Legacy cleanup warning (F-10)
    if [ -d /opt/claude-web ]; then
        echo ""
        echo -e "  ${YELLOW}!${NC} Legacy installation detected at /opt/claude-web (not touched)"
        echo -e "    ${DIM}Remove manually with: sudo rm -rf /opt/claude-web${NC}"
        echo ""
    fi

    # Conditional restart: only what actually changed.
    # PTY restart kills sessions, so we avoid it whenever possible. Pure
    # registry changes go through SIGHUP — pty-manager re-derives its
    # lookup tables in-place, sessions stay alive.
    RESTARTED=0
    if $SVC_CMD is-active --quiet aiterm-connector 2>/dev/null; then
        if [ "$PTY_CHANGED" = "1" ]; then
            $SVC_CMD restart aiterm-pty 2>/dev/null && ok "PTY Manager restarted (active sessions reset)"
            RESTARTED=1
        elif [ "$REG_CHANGED" = "1" ]; then
            # Registry-only update: explicit SIGHUP for instant pickup; the
            # mtime poller would catch it within 5 s anyway, but the signal
            # makes the reload synchronous + visible in the log.
            pkill -HUP -f "python3.*$INSTALL_DIR/pty-manager.py" 2>/dev/null \
                && ok "PTY Manager hot-reloaded registries (sessions preserved)" \
                || ok "Registries updated (will hot-reload within 5 s)"
            RESTARTED=1
        fi
        if [ "$CONN_CHANGED" = "1" ]; then
            $SVC_CMD restart aiterm-connector 2>/dev/null && ok "Connector restarted"
            RESTARTED=1
        elif [ "$REG_CHANGED" = "1" ]; then
            # Connector reads registry fresh on every scan(), so no restart
            # needed. SIGHUP is a no-op for it today but cheap to send for
            # future-proofing if connector grows registry caches.
            pkill -HUP -f "python3.*$INSTALL_DIR/connector.py" 2>/dev/null || true
        fi
        [ "$RESTARTED" = "0" ] && ok "No changes — services untouched"
    else
        # Services not active (e.g. was remote-uninstalled or never started)
        pkill -f "python3.*$INSTALL_DIR/pty-manager.py" 2>/dev/null
        pkill -f "python3.*$INSTALL_DIR/connector.py" 2>/dev/null
        rm -f "$INSTALL_DIR/pty.sock" "$INSTALL_DIR/connector.lock" 2>/dev/null
        sleep 1
        # Use $SVC_CMD directly. Earlier we used `aiterm start` here, but
        # the aiterm CLI auto-detects /opt/aiterm even from a non-root
        # shell when both system + user installs coexist — polkit then
        # demands root and the start fails. $SVC_CMD already encodes
        # whether we should hit system or user systemd.
        $SVC_CMD start aiterm-pty 2>/dev/null || true
        sleep 1
        $SVC_CMD start aiterm-connector 2>/dev/null || true
        sleep 1
        if $SVC_CMD is-active --quiet aiterm-connector 2>/dev/null; then
            RESTARTED=1
            ok "Connector started"
        elif command -v aiterm &>/dev/null && [ "$MODE" = "system" ] && [ "$(id -u)" -eq 0 ]; then
            # Last-resort fallback: only when we're definitely going to
            # hit the right install via the CLI.
            aiterm start && RESTARTED=1
        else
            # Bare-process fallback (no systemd available, e.g. WSL1)
            nohup "$PY" "$INSTALL_DIR/pty-manager.py" >> "$INSTALL_DIR/connector.log" 2>&1 &
            sleep 1
            nohup "$PY" "$INSTALL_DIR/connector.py" >> "$INSTALL_DIR/connector.log" 2>&1 &
            RESTARTED=1
            ok "Connector started (no systemd, processes spawned directly)"
        fi
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Update complete!${NC}"
    echo ""
    exit 0
fi

# ── Fresh install (or re-pair of existing install) ──
# Pre-existing state we must be able to restore if anything below fails.
PRESERVED_NAME=""
BACKUP_JSON=""
IS_REPAIR=0
if [ "$FORCE_PAIR" -eq 1 ] && [ -f "$INSTALL_DIR/connector.json" ]; then
    IS_REPAIR=1
    BACKUP_JSON=$(mktemp)
    cp "$INSTALL_DIR/connector.json" "$BACKUP_JSON"
    # Carry over the friendly name so the re-pair shows up with the same label.
    PRESERVED_NAME=$(python3 -c "import json
try: print(json.load(open('$INSTALL_DIR/connector.json')).get('name',''))
except Exception: print('')" 2>/dev/null)
fi

# Guarantee services come back up no matter how the script exits from here on.
# In repair mode: if pairing fails, restore the old connector.json + old services.
# In fresh install: services just get (re)started at the end.
cleanup_on_fail() {
    local rc=$?
    [ $rc -eq 0 ] && return
    echo ""
    echo -e "${YELLOW}  !${NC} Something went wrong. Cleaning up so your system is not left broken."
    if [ "$IS_REPAIR" = "1" ] && [ -n "$BACKUP_JSON" ] && [ -f "$BACKUP_JSON" ]; then
        cp "$BACKUP_JSON" "$INSTALL_DIR/connector.json"
        chmod 600 "$INSTALL_DIR/connector.json" 2>/dev/null || true
        echo -e "${GREEN}  ✓${NC} Restored previous connector.json (re-pair aborted, old pairing still valid)."
    fi
    # Best-effort service restart so the customer is not stuck.
    $SVC_CMD start aiterm-pty aiterm-connector 2>/dev/null || true
    rm -f "$BACKUP_JSON" 2>/dev/null
    echo -e "${DIM}  Retry with:  curl -sSL https://aiterm.io/install | bash${NC}"
    echo ""
    exit $rc
}
trap cleanup_on_fail EXIT

echo ""
if [ "$IS_REPAIR" = "1" ]; then
    echo -e "${BOLD}  ┌──────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │     AITerm Connector Re-Pairing       │${NC}"
    echo -e "${BOLD}  └──────────────────────────────────────┘${NC}"
    echo ""
    info "Re-pairing existing installation ($INSTALL_DIR)"
    if [ -n "$PRESERVED_NAME" ]; then
        info "Keeping machine name: ${BOLD}$PRESERVED_NAME${NC}"
    fi
elif [ "$HAS_PAIRING" -eq 0 ] && [ -f "$INSTALL_DIR/connector.py" ]; then
    echo -e "${BOLD}  ┌──────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │      AITerm Connector Pairing         │${NC}"
    echo -e "${BOLD}  └──────────────────────────────────────┘${NC}"
    echo ""
    info "Existing installation detected, but no pairing yet. Starting pairing flow."
else
    echo -e "${BOLD}  ┌──────────────────────────────────────┐${NC}"
    echo -e "${BOLD}  │         AITerm Connector Setup        │${NC}"
    echo -e "${BOLD}  └──────────────────────────────────────┘${NC}"
    echo ""
fi

if [ "$MODE" = "system" ]; then
    info "System-wide installation (root)"
else
    info "Per-user installation ($USER)"
fi

# ── Dependencies ──
if ! command -v python3 &>/dev/null; then
    if [ "$MODE" = "system" ]; then
        info "Installing Python3..."
        apt-get update -qq && apt-get install -y -qq python3 2>/dev/null || dnf install -y python3 2>/dev/null || fail "Python3 is missing"
    else
        fail "Python3 is missing. Install with: sudo apt install python3"
    fi
fi
ok "Python3"

ensure_python_deps
ok "Dependencies installed (websockets, cryptography)"

command -v curl &>/dev/null || fail "curl is required"

mkdir -p "$INSTALL_DIR/uploads"

# ── Download (signed + hash-verified) ──
info "Downloading connector (signed manifest)..."
signed_download
ok "Connector installed (Ed25519 signature + SHA-256 verified)"
[ "$BIN_DIR" != "/usr/local/bin" ] && ensure_path "$BIN_DIR"

# ── Pairing ──
# On re-pair, reuse the customer's existing machine name instead of silently
# reverting to the bare hostname (which often looks like 'v22018...'-style
# cloud IDs and confuses users).
if [ -n "$PRESERVED_NAME" ]; then
    HOSTNAME="$PRESERVED_NAME"
else
    HOSTNAME=$(hostname)
fi

info "Registering with AITerm..."
PAIRING_RESP=$(curl -sSL -X POST "${API_URL}/api/pairing/request" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"$HOSTNAME\"}" 2>/dev/null)

PAIRING_OK=$(echo "$PAIRING_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',''))" 2>/dev/null)
PAIRING_CODE=$(echo "$PAIRING_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('code',''))" 2>/dev/null)

[ "$PAIRING_OK" != "True" ] && fail "Pairing failed. Server unreachable?"

PAIR_URL="${API_URL}/pair/${PAIRING_CODE}"

echo ""
echo -e "${BOLD}  ┌────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}  │                                                                │${NC}"
echo -e "${BOLD}  │  ${NC}${CYAN}Open this link in your browser:${NC}${BOLD}                                │${NC}"
echo -e "${BOLD}  │                                                                │${NC}"
URL_LEN=${#PAIR_URL}
PAD=$((60 - URL_LEN))
[ $PAD -lt 0 ] && PAD=0
SPACES=$(printf '%*s' "$PAD" '')
echo -e "${BOLD}  │    ${NC}${YELLOW}${PAIR_URL}${NC}${SPACES}${BOLD}│${NC}"
echo -e "${BOLD}  │                                                                │${NC}"
echo -e "${BOLD}  │  ${NC}${DIM}Sign in and confirm. This terminal is waiting.${NC}${DIM}               ${BOLD}│${NC}"
echo -e "${BOLD}  │                                                                │${NC}"
echo -e "${BOLD}  └────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# Poll for confirmation
TOKEN=""
POLL_COUNT=0
MAX_POLLS=360

info "Waiting for confirmation in the dashboard..."
while [ -z "$TOKEN" ] && [ $POLL_COUNT -lt $MAX_POLLS ]; do
    POLL_RESP=$(curl -sSL "${API_URL}/api/pairing/status?code=${PAIRING_CODE}" 2>/dev/null)
    STATUS=$(echo "$POLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)

    if [ "$STATUS" = "confirmed" ]; then
        TOKEN=$(echo "$POLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
        break
    elif [ "$STATUS" = "expired" ]; then
        fail "Pairing code expired. Please try again."
    fi

    sleep 10
    POLL_COUNT=$((POLL_COUNT+1))
    printf "\r  ${CYAN}▸${NC} Waiting for confirmation... (%d/%d)" "$((POLL_COUNT*10))" "3600" 2>/dev/null
done

[ -z "$TOKEN" ] && fail "Timeout. No confirmation received."
echo ""
ok "Pairing confirmed!"

# ── Config ──
# Pick a default working directory. This is just the *fallback* used by
# the CWD picker in the dashboard when starting a session — the picker
# always lets the user pick from scanned project dirs at session-start
# time, so we don't bother prompting at install. Priority:
#   1. Re-pair with an existing connector.json → keep its default_cwd.
#   2. Otherwise → user's $HOME (the picker fills in scanned candidates).
DEFAULT_CWD=""
if [ "$IS_REPAIR" = "1" ] && [ -n "$BACKUP_JSON" ] && [ -f "$BACKUP_JSON" ]; then
    OLD_CWD=$(python3 -c "import json
try: print(json.load(open('$BACKUP_JSON')).get('default_cwd',''))
except Exception: print('')" 2>/dev/null)
    if [ -n "$OLD_CWD" ] && [ -d "$OLD_CWD" ]; then
        DEFAULT_CWD="$OLD_CWD"
        info "Keeping working directory: ${BOLD}$DEFAULT_CWD${NC}"
    fi
fi

if [ -z "$DEFAULT_CWD" ]; then
    DEFAULT_CWD=$(eval echo ~)
    info "Default working directory: ${BOLD}$DEFAULT_CWD${NC} ${DIM}(per-session selection in dashboard)${NC}"
fi

python3 - "$INSTALL_DIR" "$HUB_URL" "$TOKEN" "$DEFAULT_CWD" "$HOSTNAME" << 'PYCFG'
import json, sys, os
install_dir, hub_url, token, default_cwd, hostname = sys.argv[1:6]
cfg = {
    "default_cwd": default_cwd,
    "max_upload_mb": 20,
    "upload_dir": install_dir + "/uploads",
    "name": hostname,
    "hub_url": hub_url,
    "hub_token": token,
}
import stat
cfg_path = install_dir + "/connector.json"
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
os.chmod(cfg_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
PYCFG
ok "Configuration saved (0600)"

# ── Honeytokens ──
# Deploy decoy files in standard attacker-recon paths. The connector will
# watch them and alert the hub on any read. Runs here (not from the service)
# because systemd's ProtectHome=read-only blocks /root + /home writes.
if python3 "$INSTALL_DIR/connector.py" --deploy-honeytokens > /tmp/aiterm-honeytokens.log 2>&1; then
    # grep -c prints "0" AND exits 1 when no match. Under `set -e` the
    # bare assignment would kill the script on a re-pair (where every
    # honeytoken path already exists, so connector.py prints zero new
    # entries). Trailing `|| true` swallows the exit; the empty-string
    # guard covers the file-missing case where grep prints nothing.
    HT_COUNT=$(grep -c '^  •' /tmp/aiterm-honeytokens.log 2>/dev/null || true)
    [ -z "$HT_COUNT" ] && HT_COUNT=0
    if [ "$HT_COUNT" -gt 0 ] 2>/dev/null; then
        ok "Honeytokens deployed ($HT_COUNT decoys — any access triggers an alert)"
    fi
    rm -f /tmp/aiterm-honeytokens.log
fi

# ── Systemd ──
info "Setting up services..."

write_units
# Every systemctl/loginctl call below is shielded with `|| true` because
# the post-restart `is-active` check at the bottom of this block is the
# authoritative success test. Without the shield, a transient failure
# (unrelated unit broken on the host, brief activation race, etc.) trips
# `set -e` and the EXIT trap rolls back a *successful* re-pair — the
# customer ends up with their old token even though pairing went fine.
$SVC_CMD daemon-reload 2>/dev/null || true

if [ "$MODE" = "system" ]; then
    if systemctl is-active --quiet aiterm-connector 2>/dev/null; then
        systemctl restart aiterm-pty aiterm-connector 2>/dev/null || true
        ok "Services restarted (were already running)"
    else
        systemctl enable --now aiterm-pty 2>/dev/null || true
        sleep 1
        systemctl enable --now aiterm-connector 2>/dev/null || true
    fi
else
    if $SVC_CMD is-active --quiet aiterm-connector 2>/dev/null; then
        $SVC_CMD restart aiterm-pty aiterm-connector 2>/dev/null || true
        ok "Services restarted (were already running)"
    else
        $SVC_CMD enable --now aiterm-pty 2>/dev/null || true
        sleep 1
        $SVC_CMD enable --now aiterm-connector 2>/dev/null || true
    fi

    # Enable linger so services survive logout
    LINGER_OK=0
    loginctl enable-linger "$TARGET_USER" 2>/dev/null && LINGER_OK=1 && ok "Autostart enabled (linger)" || true
fi

sleep 2

SVC_STARTED=0
if $SVC_CMD is-active --quiet aiterm-connector 2>/dev/null; then
    ok "Connected"
    SVC_STARTED=1
elif [ "$MODE" = "user" ]; then
    info "Service could not start automatically"
else
    fail "Connector failed to start. Check: journalctl -u aiterm-connector"
fi

# Success — cancel the cleanup trap and remove backup.
trap - EXIT
[ -n "$BACKUP_JSON" ] && rm -f "$BACKUP_JSON"

echo ""
if [ "$IS_REPAIR" = "1" ]; then
    echo -e "  ${GREEN}${BOLD}Re-paired.${NC} Machine reconnected under the new token."
    echo -e "  ${DIM}The old entry may show as 'offline' in the dashboard — you can remove it with the 'Remove' button.${NC}"
else
    echo -e "  ${GREEN}${BOLD}Done!${NC} Machine will appear in the dashboard."
fi
echo -e "  ${DIM}AI backends can be scanned from the dashboard.${NC}"

if [ "$MODE" = "user" ]; then
    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    ${CYAN}aiterm start${NC}     Start connector"
    echo -e "    ${CYAN}aiterm stop${NC}      Stop connector"
    echo -e "    ${CYAN}aiterm restart${NC}   Restart connector"
    echo -e "    ${CYAN}aiterm status${NC}    Show status"
    echo -e "    ${CYAN}aiterm logs${NC}      Show logs"
    if [ "$SVC_STARTED" -eq 0 ]; then
        echo ""
        echo -e "  ${YELLOW}Start now with:${NC}  aiterm start"
    fi
    if [ "${LINGER_OK:-0}" -eq 0 ]; then
        echo ""
        echo -e "  ${DIM}For autostart after reboot (requires root):${NC}"
        echo -e "  ${DIM}  sudo loginctl enable-linger $TARGET_USER${NC}"
    fi
fi
echo ""
