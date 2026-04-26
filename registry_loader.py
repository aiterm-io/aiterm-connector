"""Shared registry loader for connector.py / pty-manager.py / doctor.py.

Loads ai-registry.json, guard-patterns.json, doctor-checks.json from disk
(installed alongside the connector). Falls back gracefully to a built-in
minimal default when a file is missing or malformed — old connectors
without registry files keep working until they `aiterm update`.
"""
import json
import os
from pathlib import Path

_BASE_DIR = Path(__file__).parent

# ── Built-in fallback (matches a subset of the shipped registry) ──
# Used only when the JSON file is missing — so a connector that was
# installed before the registry feature existed still has a working
# baseline AI list. Will be overridden the first time the user updates.
_FALLBACK_AI_REGISTRY = {
    "version": 0,
    "ais": [
        {"id": "claude", "label": "Claude Code", "icon": "C", "pricing_tag": "paid",
         "scan": {"binary": "claude",
                  "extra_paths": ["~/.local/bin/claude", "/root/.local/bin/claude",
                                  "/usr/local/bin/claude", "/usr/bin/claude"],
                  "version_arg": "--version",
                  "running_patterns": ["claude --chat", "claude chat", "claude -c"]},
         "start": {"args": [], "needs_model": False}},
        {"id": "ollama", "label": "Ollama", "icon": "O", "pricing_tag": "free",
         "scan": {"binary": "ollama", "extra_paths": [],
                  "version_arg": "--version",
                  "running_patterns": ["ollama serve", "ollama run"],
                  "list_models_cmd": ["ollama", "list"]},
         "start": {"args": [], "needs_model": True,
                   "model_arg_template": ["run", "{model}"]}},
        {"id": "bash", "label": "Bash Shell", "icon": "$", "pricing_tag": "free",
         "hidden_in_wizard": True, "scan": None,
         "start": {"binary": "bash", "args": [], "needs_model": False}},
    ],
}

_FALLBACK_GUARD_PATTERNS = {
    "version": 0,
    "patterns": [
        {"id": "rm-rf-root", "regex": r"rm\s+(-[rRf]+\s+)+/(?!\S)",
         "severity": "crit", "scope": "always",
         "reason": "Recursive delete of the root filesystem."},
        {"id": "curl-pipe-bash", "regex": r"curl\s+[^|]*\|\s*(bash|sh|zsh|fish)\b",
         "severity": "warn", "scope": "always",
         "reason": "Piping a remote script straight into a shell."},
        {"id": "reverse-shell-bash", "regex": r"bash\s+-i\s+>&\s*/dev/tcp/",
         "severity": "crit", "scope": "always",
         "reason": "Bash reverse shell via /dev/tcp."},
    ],
}

_FALLBACK_DOCTOR_CHECKS = {"version": 0, "checks": []}


def _load_registry(filename, fallback):
    """Read a JSON registry from the connector's install dir. Returns the
    fallback structure on any failure. Verbose stderr on JSON errors so
    operators see why a registry didn't load."""
    p = _BASE_DIR / filename
    if not p.exists():
        return fallback
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Sanity: top-level must be a dict with a 'version' int.
        if not isinstance(data, dict) or "version" not in data:
            return fallback
        return data
    except (OSError, json.JSONDecodeError) as e:
        print(f"[registry_loader] {filename}: {e}", flush=True)
        return fallback


def load_ai_registry():
    return _load_registry("ai-registry.json", _FALLBACK_AI_REGISTRY)


def load_guard_patterns():
    return _load_registry("guard-patterns.json", _FALLBACK_GUARD_PATTERNS)


def load_doctor_checks():
    return _load_registry("doctor-checks.json", _FALLBACK_DOCTOR_CHECKS)


# ── Helpers that derive the legacy data structures from the registry ──
# So existing code paths don't need restructuring; they just receive the
# same dicts they always did, populated from the registry.

def derive_ai_commands():
    """Returns dict ai_id → binary name (for AI_COMMANDS)."""
    out = {}
    for ai in load_ai_registry().get("ais", []):
        scan = ai.get("scan") or {}
        start = ai.get("start") or {}
        binary = start.get("binary") or scan.get("binary")
        if binary:
            out[ai["id"]] = binary
    return out


def derive_default_args():
    """Returns dict ai_id → list of default args (for AI_DEFAULT_ARGS)."""
    out = {}
    for ai in load_ai_registry().get("ais", []):
        start = ai.get("start") or {}
        args = start.get("args") or []
        if args:
            out[ai["id"]] = list(args)
    return out


def derive_extra_paths():
    """Returns dict ai_id → list of extra search paths (for EXTRA_PATHS)."""
    out = {}
    for ai in load_ai_registry().get("ais", []):
        scan = ai.get("scan") or {}
        paths = scan.get("extra_paths") or []
        if paths:
            out[ai["id"]] = [os.path.expanduser(p) for p in paths]
    return out


def derive_running_patterns(ai_id):
    """For _proc_running checks. Returns list of substring patterns."""
    for ai in load_ai_registry().get("ais", []):
        if ai["id"] == ai_id:
            return (ai.get("scan") or {}).get("running_patterns") or []
    return []


def is_ollama_like(ai_id):
    """True if the AI uses model arguments (e.g. 'ollama run llama3')."""
    for ai in load_ai_registry().get("ais", []):
        if ai["id"] == ai_id:
            return bool((ai.get("start") or {}).get("needs_model"))
    return False
