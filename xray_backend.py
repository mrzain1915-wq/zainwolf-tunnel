"""Runtime config utilities for Xray Core profiles (VLESS/VMess/Trojan)."""
from __future__ import annotations

import copy
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "ZainWolfTunnel"


def find_xray_binary(project_dir: Path | None = None) -> Path | None:
    """Find xray.exe beside the project, in tools/, or bundled by PyInstaller."""
    candidates: list[Path] = []
    if getattr(sys, "_MEIPASS", None):
        base = Path(sys._MEIPASS)
        candidates.extend([base / "xray.exe", base / "tools" / "xray.exe"])
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
        candidates.extend([base / "xray.exe", base / "tools" / "xray.exe"])
    if project_dir:
        project_dir = Path(project_dir)
        candidates.extend([project_dir / "tools" / "xray.exe", project_dir / "xray.exe"])
    candidates.extend([APP_DIR / "tools" / "xray.exe", APP_DIR / "xray.exe"])
    for path in candidates:
        if path.is_file():
            return path
    return None


def build_runtime_config(profile: dict[str, Any], socks_port: int, http_port: int) -> dict[str, Any]:
    """Build a localhost-only Xray config around an imported outbound profile."""
    outbound = profile.get("outbound")
    if not isinstance(outbound, dict):
        raise ValueError("This imported link did not produce a usable Xray outbound profile.")
    protocol = str(outbound.get("protocol", "")).lower()
    if protocol not in {"vless", "vmess", "trojan", "socks", "shadowsocks"}:
        raise ValueError(f"Unsupported Xray outbound protocol: {protocol or '(missing)'}")
    for label, port in (("SOCKS5", socks_port), ("HTTP", http_port)):
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"{label} local port must be between 1 and 65535.")
    if socks_port == http_port:
        raise ValueError("SOCKS5 and HTTP local ports must be different.")

    config: dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "zainwolf-socks-in", "listen": "127.0.0.1", "port": socks_port,
             "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 0}},
            {"tag": "zainwolf-http-in", "listen": "127.0.0.1", "port": http_port,
             "protocol": "http", "settings": {"allowTransparent": False, "userLevel": 0}},
        ],
        "outbounds": [copy.deepcopy(outbound), {"tag": "zainwolf-direct", "protocol": "freedom", "settings": {}}],
    }
    source = profile.get("source_config")
    if isinstance(source, dict):
        # Keep non-routing metadata such as DNS/log settings but ensure proxy outbound remains first.
        for key in ("dns", "policy", "stats", "api"):
            if key in source:
                config[key] = copy.deepcopy(source[key])
    return config


def write_runtime_config(profile: dict[str, Any], socks_port: int, http_port: int, app_dir: Path | None = None) -> Path:
    base = Path(app_dir or APP_DIR)
    base.mkdir(parents=True, exist_ok=True)
    path = base / "active_xray_config.json"
    data = build_runtime_config(profile, socks_port, http_port)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)
    return path


def resolve_endpoint_ipv4(host: str) -> str:
    """Resolve one IPv4 endpoint for the Full Traffic route bypass."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        for family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM):
            if family == socket.AF_INET:
                return sockaddr[0]
    except OSError as exc:
        raise OSError(f"Could not resolve proxy endpoint {host!r} to IPv4 for Full Traffic mode: {exc}") from exc
    raise OSError(f"Could not resolve proxy endpoint {host!r} to an IPv4 address for Full Traffic mode.")
