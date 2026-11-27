"""Saved connection profiles for ZainWolf Tunnel (v1.0.1).

Profiles live in %APPDATA%\\ZainWolfTunnel\\profiles.json. A profile stores the
server (host:port@username — the password is NEVER stored), proxy mode, proxy
host:port, payload, local ports, system-proxy choice and Full Traffic choice.
Only the Python standard library is used, so this module is unit-testable
without Tkinter or any network access.
"""
from __future__ import annotations

import json
from pathlib import Path

from noway_core import parse_server_spec

PROFILE_FIELDS = (
    "server",
    "proxy_mode",
    "proxy",
    "payload",
    "local_port",
    "http_port",
    "use_system_proxy",
    "full_traffic",
)


def load_profiles(path) -> dict:
    """Return {name: {field: value}}; missing or corrupt files give {}."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    profiles = {}
    for name, values in data.items():
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(values, dict):
            continue
        profiles[name.strip()] = {
            field: values[field] for field in PROFILE_FIELDS if field in values
        }
    return profiles


def save_profiles(path, profiles: dict) -> None:
    """Write the profiles dict atomically (temp file + replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(profiles, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def save_profile(path, name: str, data: dict) -> dict:
    """Create or overwrite one profile; returns the full profiles dict."""
    profiles = load_profiles(path)
    profiles[name.strip()] = {
        field: data.get(field) for field in PROFILE_FIELDS
    }
    save_profiles(path, profiles)
    return profiles


def delete_profile(path, name: str) -> dict:
    """Remove one profile (no-op when absent); returns the full profiles dict."""
    profiles = load_profiles(path)
    profiles.pop(name.strip(), None)
    save_profiles(path, profiles)
    return profiles


def strip_password_from_server_spec(spec: str) -> str:
    """Return 'host:port@username' (no password) for storage, or '' if invalid."""
    try:
        host, port, username, _password = parse_server_spec(spec)
    except ValueError:
        return ""
    host_display = f"[{host}]" if ":" in host else host
    return f"{host_display}:{port}@{username}"
