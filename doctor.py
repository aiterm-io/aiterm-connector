#!/usr/bin/env python3
"""AITerm Doctor — read-only server security checkup.

Cross-distro (Debian/Ubuntu, RHEL/Alma/Rocky/Fedora, openSUSE, Arch):
detects the package manager and adapts checks. Output is a prioritised list
with one-line "why it matters" + copy-paste fix command for every issue.

Hard rule (see memory feedback_no_filesystem_automation.md):
  This script READS only. It never modifies the system. Even with --json
  there is no --fix mode — the user types the fix themselves.

Usage:
  aiterm doctor              # human-readable
  aiterm doctor --json       # JSON output for automation
  aiterm doctor --quiet      # only crit + warn, suppress ok rows
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta


# ── Output formatting ────────────────────────────────────────────

class C:
    """Terminal colors. Auto-disabled when not a TTY."""
    if sys.stdout.isatty():
        OK = "\033[0;32m"
        WARN = "\033[0;33m"
        CRIT = "\033[0;31m"
        DIM = "\033[2m"
        BOLD = "\033[1m"
        END = "\033[0m"
    else:
        OK = WARN = CRIT = DIM = BOLD = END = ""


SEVERITY_ICON = {"ok": "✓", "warn": "⚠", "crit": "✗"}
SEVERITY_COLOR = {"ok": C.OK, "warn": C.WARN, "crit": C.CRIT}


def result(severity, name, summary, why=None, fix=None):
    """One check returns this shape. severity ∈ {ok, warn, crit}."""
    return {
        "severity": severity,
        "name": name,
        "summary": summary,
        "why": why or "",
        "fix": fix or "",
    }


# ── Distro / package-manager detection ──────────────────────────

def detect_distro():
    """Return {id, family, pkg, service_mgr}. Falls back to unknown."""
    info = {"id": "unknown", "family": "unknown", "pkg": "", "service_mgr": "systemctl"}
    try:
        with open("/etc/os-release") as f:
            for ln in f:
                if "=" not in ln:
                    continue
                k, v = ln.strip().split("=", 1)
                v = v.strip('"')
                if k == "ID":
                    info["id"] = v
                elif k == "ID_LIKE":
                    info["id_like"] = v
    except Exception:
        return info
    family_map = {
        "debian": ("debian", "apt"),
        "ubuntu": ("debian", "apt"),
        "rhel":   ("rhel", "dnf"),
        "centos": ("rhel", "dnf"),
        "fedora": ("rhel", "dnf"),
        "almalinux": ("rhel", "dnf"),
        "rocky": ("rhel", "dnf"),
        "amzn":  ("rhel", "dnf"),
        "opensuse-leap": ("suse", "zypper"),
        "opensuse-tumbleweed": ("suse", "zypper"),
        "sles":  ("suse", "zypper"),
        "arch":  ("arch", "pacman"),
        "manjaro": ("arch", "pacman"),
        "alpine": ("alpine", "apk"),
    }
    fam = family_map.get(info["id"])
    if not fam:
        # Try ID_LIKE
        for like in (info.get("id_like", "") or "").split():
            fam = family_map.get(like)
            if fam:
                break
    if fam:
        info["family"], info["pkg"] = fam
    return info


def install_cmd(pkg_name, distro):
    """Return the right install one-liner for the detected family."""
    pkg = distro.get("pkg")
    if pkg == "apt":     return f"sudo apt-get install -y {pkg_name}"
    if pkg == "dnf":     return f"sudo dnf install -y {pkg_name}"
    if pkg == "zypper":  return f"sudo zypper install -y {pkg_name}"
    if pkg == "pacman":  return f"sudo pacman -S --noconfirm {pkg_name}"
    if pkg == "apk":     return f"sudo apk add {pkg_name}"
    return f"# install {pkg_name} via your package manager"


def systemd_active(unit):
    """True if the systemd unit is active (running)."""
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


# ── Individual checks ───────────────────────────────────────────

def check_fail2ban(distro):
    """fail2ban: catches automated SSH/HTTP brute force at the network level."""
    if shutil.which("fail2ban-client") and systemd_active("fail2ban"):
        return result("ok", "fail2ban", "installed and running")
    if shutil.which("fail2ban-client"):
        return result("warn", "fail2ban", "installed but service is not active",
                      why="fail2ban watches auth logs and bans brute-force IPs. Without the service running, attackers retry forever.",
                      fix="sudo systemctl enable --now fail2ban")
    return result("warn", "fail2ban", "not installed",
                  why="Without fail2ban, every public IP can hammer your SSH/HTTP endpoints indefinitely.",
                  fix=install_cmd("fail2ban", distro) + " && sudo systemctl enable --now fail2ban")


def _read_sshd_config():
    """Parse /etc/ssh/sshd_config + drop-ins. Returns dict of (key.lower → value)."""
    paths = ["/etc/ssh/sshd_config"]
    drop = "/etc/ssh/sshd_config.d"
    if os.path.isdir(drop):
        try:
            for f in sorted(os.listdir(drop)):
                if f.endswith(".conf"):
                    paths.append(os.path.join(drop, f))
        except Exception:
            pass
    cfg = {}
    for p in paths:
        try:
            with open(p) as f:
                for ln in f:
                    s = ln.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split(None, 1)
                    if len(parts) == 2:
                        # later files override earlier (same as sshd's behaviour)
                        cfg[parts[0].lower()] = parts[1].strip()
        except (FileNotFoundError, PermissionError):
            continue
    return cfg


def check_sshd_root_login():
    """SSH root login: should be 'no' or 'prohibit-password' (key-only)."""
    cfg = _read_sshd_config()
    val = (cfg.get("permitrootlogin") or "yes").lower()  # default in OpenSSH is yes
    if val == "no":
        return result("ok", "SSH root login", "disabled")
    if val == "prohibit-password":
        return result("ok", "SSH root login", "key-only (prohibit-password)")
    return result("crit" if val == "yes" else "warn", "SSH root login",
                  f"PermitRootLogin = {val}",
                  why="Direct root login is the #1 SSH-bruteforce target. Either disable it or restrict to keys only.",
                  fix='sudo sed -i "s/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/" /etc/ssh/sshd_config && sudo systemctl reload sshd')


def check_sshd_password_auth():
    """Password auth on SSH: should be off in favor of keys."""
    cfg = _read_sshd_config()
    val = (cfg.get("passwordauthentication") or "yes").lower()
    if val == "no":
        return result("ok", "SSH password auth", "disabled (key-only)")
    return result("warn", "SSH password auth",
                  f"PasswordAuthentication = {val}",
                  why="Allowing passwords lets brute-forcers compete. Public-key only is the standard for production.",
                  fix='sudo sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && sudo systemctl reload sshd')


def check_sshd_pubkey():
    cfg = _read_sshd_config()
    val = (cfg.get("pubkeyauthentication") or "yes").lower()
    if val == "yes":
        return result("ok", "SSH pubkey auth", "enabled")
    return result("crit", "SSH pubkey auth", "DISABLED",
                  why="Without pubkey auth you cannot harden SSH (you would be locked into passwords).",
                  fix='sudo sed -i "s/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config && sudo systemctl reload sshd')


def check_firewall(distro):
    """ufw / firewalld / nftables: at least one should be active."""
    if shutil.which("ufw"):
        try:
            r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "Status: active" in r.stdout:
                return result("ok", "firewall (ufw)", "active")
            return result("warn", "firewall (ufw)", "installed but inactive",
                          why="An inactive firewall lets every listening service face the public internet.",
                          fix="sudo ufw enable")
        except Exception:
            pass
    if shutil.which("firewall-cmd") and systemd_active("firewalld"):
        return result("ok", "firewall (firewalld)", "active")
    # nftables direct
    if systemd_active("nftables"):
        return result("ok", "firewall (nftables)", "active")
    if systemd_active("iptables"):
        return result("ok", "firewall (iptables)", "active")
    fix = install_cmd("ufw", distro) + " && sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable"
    if distro.get("family") == "rhel":
        fix = install_cmd("firewalld", distro) + " && sudo systemctl enable --now firewalld"
    return result("warn", "firewall", "no active firewall detected",
                  why="Every package you install can listen on a port. A default-deny firewall keeps surprises off the internet.",
                  fix=fix)


def check_unattended_upgrades(distro):
    """Auto security updates: distro-specific."""
    family = distro.get("family")
    if family == "debian":
        active = systemd_active("unattended-upgrades")
        if active:
            return result("ok", "auto security updates", "unattended-upgrades active")
        if shutil.which("unattended-upgrade"):
            return result("warn", "auto security updates", "package present but service not enabled",
                          fix="sudo systemctl enable --now unattended-upgrades")
        return result("warn", "auto security updates", "unattended-upgrades not installed",
                      why="Without auto-updates, security patches wait for you. CVEs land in scanners faster than humans patch.",
                      fix="sudo apt-get install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")
    if family == "rhel":
        if systemd_active("dnf-automatic.timer") or systemd_active("dnf-automatic-install.timer"):
            return result("ok", "auto security updates", "dnf-automatic active")
        return result("warn", "auto security updates", "dnf-automatic not enabled",
                      fix="sudo dnf install -y dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer")
    if family == "suse":
        return result("warn", "auto security updates", "manual review required",
                      why="openSUSE has no built-in equivalent — review the YaST 'Online Update Configuration' module.",
                      fix="sudo zypper install yast2-online-update-configuration  # then configure in YaST")
    if family == "arch":
        return result("warn", "auto security updates", "rolling-release: no auto-update by design",
                      why="Arch is a rolling release — auto-update can break things. Schedule a regular manual update window.",
                      fix="# weekly: sudo pacman -Syu  (review changes first)")
    return result("warn", "auto security updates", "distro not recognised",
                  why="Could not detect package manager.")


def check_last_update():
    """When was the last package-manager refresh? Stale = bad."""
    candidates = [
        "/var/lib/apt/periodic/update-success-stamp",
        "/var/cache/apt/pkgcache.bin",
        "/var/lib/dnf/last_makecache",
        "/var/cache/zypp",
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                age_days = (datetime.now() - datetime.fromtimestamp(os.path.getmtime(path))).days
                if age_days < 7:
                    return result("ok", "package list freshness", f"refreshed {age_days}d ago")
                if age_days < 30:
                    return result("warn", "package list freshness", f"{age_days}d since last refresh",
                                  fix="sudo apt-get update  # or dnf check-update / zypper refresh")
                return result("crit", "package list freshness", f"{age_days}d since last refresh — STALE",
                              why="If your package list is stale, even apt-get upgrade installs nothing useful.",
                              fix="sudo apt-get update && sudo apt-get upgrade")
            except Exception:
                continue
    return result("warn", "package list freshness", "could not determine",
                  why="No known timestamp file found.")


def check_open_ports():
    """ss -tln to enumerate listeners. Flag dangerous defaults."""
    if not shutil.which("ss"):
        return result("warn", "open ports", "ss command not available")
    try:
        r = subprocess.run(["ss", "-tlnH"], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
    except Exception:
        return result("warn", "open ports", "could not query ss")
    dangerous = {
        "23":  ("Telnet", "Cleartext credentials over the wire."),
        "21":  ("FTP",    "Cleartext authentication; use SFTP/SSHFS instead."),
        "873": ("rsync daemon", "Often misconfigured to expose data."),
        "2049": ("NFS",    "Without Kerberos, NFS auth is effectively trust-the-IP."),
        "5984": ("CouchDB", "Older defaults bound to 0.0.0.0 with no auth."),
        "27017": ("MongoDB", "Pre-4.0 defaults exposed to the world without auth."),
        "9200": ("Elasticsearch", "Default no-auth, full read/write."),
        "6379": ("Redis", "Default no-auth, full RCE via CONFIG SET."),
    }
    found = []
    for ln in lines:
        m = re.search(r"(\d+\.\d+\.\d+\.\d+|\*|\[::\]):(\d+)\s", ln)
        if not m:
            continue
        ip, port = m.group(1), m.group(2)
        if ip not in ("127.0.0.1", "::1") and port in dangerous:
            name, reason = dangerous[port]
            found.append((port, name, reason))
    if not found:
        return result("ok", "open ports", "no risky listeners on public interfaces")
    descriptions = "\n        ".join(f"  {p} ({n}): {r}" for p, n, r in found)
    return result("crit", "open ports", f"{len(found)} risky listener(s) on public interfaces",
                  why="Listed services have a history of being exposed without auth or with cleartext credentials:\n        " + descriptions,
                  fix="# review who really needs each: ss -tlnp\n# bind to 127.0.0.1 in their config, or block via firewall")


def check_time_sync():
    """Time sync: certs, fail2ban findtime, audit logs all rely on accurate clocks."""
    if systemd_active("systemd-timesyncd") or systemd_active("chronyd") or systemd_active("ntpd") or systemd_active("ntp"):
        return result("ok", "time sync", "active")
    return result("warn", "time sync", "no NTP daemon active",
                  why="TLS certificate validation, fail2ban time-windows and audit log timestamps all depend on clock accuracy.",
                  fix="sudo timedatectl set-ntp true   # or install chrony / ntp")


def check_disk():
    """Root filesystem usage."""
    try:
        st = shutil.disk_usage("/")
        pct = round(st.used / st.total * 100)
        if pct < 80:
            return result("ok", "disk /", f"{pct}% used")
        if pct < 90:
            return result("warn", "disk /", f"{pct}% used")
        return result("crit", "disk /", f"{pct}% used — close to full",
                      why="When / fills up, services fail to write logs and crash unpredictably.",
                      fix="sudo journalctl --vacuum-time=2weeks; sudo apt-get autoremove   # or equivalent")
    except Exception:
        return result("warn", "disk /", "could not determine usage")


def check_aiterm_services():
    """If we're running on a paired AITerm machine, check connector + pty."""
    has_aiterm = os.path.exists("/opt/aiterm/connector.py") or os.path.exists(os.path.expanduser("~/.local/share/aiterm/connector.py"))
    if not has_aiterm:
        return None
    statuses = []
    for unit in ("aiterm-connector", "aiterm-pty"):
        statuses.append((unit, systemd_active(unit)))
    bad = [u for u, ok in statuses if not ok]
    if not bad:
        return result("ok", "AITerm services", "connector + pty-manager active")
    return result("warn", "AITerm services", f"{', '.join(bad)} not active",
                  fix=f"sudo systemctl restart {' '.join(bad)}")


# ── Runner ──────────────────────────────────────────────────────

CHECKS = [
    ("fail2ban",            check_fail2ban),
    ("ssh-root",            lambda d: check_sshd_root_login()),
    ("ssh-password",        lambda d: check_sshd_password_auth()),
    ("ssh-pubkey",          lambda d: check_sshd_pubkey()),
    ("firewall",            check_firewall),
    ("auto-updates",        check_unattended_upgrades),
    ("package-freshness",   lambda d: check_last_update()),
    ("open-ports",          lambda d: check_open_ports()),
    ("time-sync",           lambda d: check_time_sync()),
    ("disk",                lambda d: check_disk()),
    ("aiterm-services",     lambda d: check_aiterm_services()),
]


def run_all():
    distro = detect_distro()
    rows = []
    for cid, fn in CHECKS:
        try:
            r = fn(distro)
        except Exception as e:
            r = result("warn", cid, f"check failed: {e}")
        if r is not None:
            r["id"] = cid
            rows.append(r)
    return distro, rows


def print_human(distro, rows, quiet=False):
    print()
    print(f"  {C.BOLD}AITerm Doctor{C.END}  —  {distro.get('id', '?')} ({distro.get('family', '?')}, {distro.get('pkg', '?')})")
    print(f"  {C.DIM}read-only checkup; never modifies your system{C.END}")
    print()
    counts = {"ok": 0, "warn": 0, "crit": 0}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        if quiet and r["severity"] == "ok":
            continue
        col = SEVERITY_COLOR[r["severity"]]
        icon = SEVERITY_ICON[r["severity"]]
        print(f"  {col}{icon}{C.END} {C.BOLD}{r['name']}{C.END} — {r['summary']}")
        if r["why"]:
            print(f"    {C.DIM}why:{C.END} {r['why']}")
        if r["fix"]:
            print(f"    {C.DIM}fix:{C.END} {C.BOLD}{r['fix']}{C.END}")
        print()
    print(f"  {C.OK}{counts['ok']} ok{C.END}  ·  {C.WARN}{counts['warn']} warn{C.END}  ·  {C.CRIT}{counts['crit']} crit{C.END}")
    print()
    if counts["crit"] > 0:
        return 2
    if counts["warn"] > 0:
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(prog="aiterm doctor",
                                 description="Read-only server security checkup.")
    ap.add_argument("--json", action="store_true", help="Output as JSON.")
    ap.add_argument("--quiet", action="store_true", help="Suppress 'ok' rows.")
    args = ap.parse_args()
    distro, rows = run_all()
    if args.json:
        print(json.dumps({"distro": distro, "checks": rows}, indent=2))
        return 0
    return print_human(distro, rows, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
