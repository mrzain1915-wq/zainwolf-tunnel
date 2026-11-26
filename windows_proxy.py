"""Temporary Windows per-user system proxy management for ZainWolf Tunnel.

Only HTTP/HTTPS apps that honor the Windows system proxy are routed. This is not a
replacement for a Wintun/TUN driver and does not capture arbitrary UDP/app traffic.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
VALUE_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride")


def _is_windows():
    return os.name == "nt"


def _registry_module():
    if not _is_windows():
        raise OSError("Windows system proxy can only be changed on Windows")
    import winreg
    return winreg


def _notify_windows():
    import ctypes
    wininet = ctypes.windll.wininet
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    INTERNET_OPTION_REFRESH = 37
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def _read_original():
    winreg = _registry_module()
    result = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_READ) as key:
        for name in VALUE_NAMES:
            try:
                value, kind = winreg.QueryValueEx(key, name)
                result[name] = {"exists": True, "value": value, "kind": kind}
            except FileNotFoundError:
                result[name] = {"exists": False}
    return result


def _write_original(original):
    winreg = _registry_module()
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
        for name in VALUE_NAMES:
            item = original.get(name, {"exists": False})
            if item.get("exists"):
                winreg.SetValueEx(key, name, 0, item["kind"], item["value"])
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
    _notify_windows()


def _pid_alive(pid):
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def recover_stale_windows_proxy(backup_file: Path):
    """Restore a previous app instance's proxy only if its PID is no longer alive."""
    backup_file = Path(backup_file)
    if not backup_file.exists() or not _is_windows():
        return
    try:
        data = json.loads(backup_file.read_text(encoding="utf-8"))
        if _pid_alive(data.get("owner_pid")):
            return
        _write_original(data.get("original", {}))
        backup_file.unlink(missing_ok=True)
    except Exception:
        # Keep the backup file for manual recovery if a registry restoration fails.
        raise


def apply_windows_system_proxy(proxy_address: str, backup_file: Path):
    """Point the current Windows user at a local proxy, preserving old settings."""
    winreg = _registry_module()
    backup_file = Path(backup_file)
    if backup_file.exists():
        data = json.loads(backup_file.read_text(encoding="utf-8"))
        # If an old owner is no longer running, recover its state before applying anew.
        if not _pid_alive(data.get("owner_pid")):
            _write_original(data.get("original", {}))
            backup_file.unlink(missing_ok=True)
        else:
            # The current instance may already have applied this proxy; do not overwrite
            # the user's pre-tunnel backup with our own values.
            raise RuntimeError("A ZainWolf Tunnel system-proxy session is already active")
    original = _read_original()
    backup_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = backup_file.with_suffix(backup_file.suffix + ".tmp")
    temp_file.write_text(json.dumps({"owner_pid": os.getpid(), "original": original}, indent=2), encoding="utf-8")
    temp_file.replace(backup_file)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_address)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>;localhost;127.*")
        _notify_windows()
    except Exception:
        _write_original(original)
        backup_file.unlink(missing_ok=True)
        raise


def restore_windows_system_proxy(backup_file: Path):
    """Restore the saved pre-tunnel proxy values, including previously absent values."""
    backup_file = Path(backup_file)
    if not backup_file.exists():
        return
    data = json.loads(backup_file.read_text(encoding="utf-8"))
    _write_original(data.get("original", {}))
    backup_file.unlink(missing_ok=True)
