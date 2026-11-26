"""Connection profile import for SSH links and Xray/V2Ray client profiles.

This module parses VLESS, VMess, and Trojan links into native Xray outbound
objects. A running connection for these protocols requires the Xray Core
executable; they are never misinterpreted as SSH credentials.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from noway_core import parse_host_port, parse_server_spec

_PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "socks"}


def _endpoint(host: str, port: int) -> str:
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{host_display}:{port}"


def _ssh_result(host: str, port: int, username: str = "", password: str = "") -> dict[str, Any]:
    if not host or not 1 <= int(port) <= 65535:
        raise ValueError("SSH link must contain a valid host and port.")
    return {
        "kind": "ssh", "protocol": "ssh", "host": host, "port": int(port),
        "username": username, "password": password,
        "server_field": f"{_endpoint(host, int(port))}@{username}:{password}" if username else "",
        "missing_credentials": not bool(username and password),
    }


def _legacy_ssh(value: str) -> dict[str, Any]:
    host, port, username, password = parse_server_spec(value)
    return _ssh_result(host, port, username, password)


def _parse_ssh_uri(value: str) -> dict[str, Any]:
    body = value[len("ssh://"):]
    if "@" in body:
        left, right = body.split("@", 1)
        if re.search(r":\d+$", left) and ":" in right:
            try:
                return _legacy_ssh(body)
            except ValueError:
                pass
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port or 22
    except ValueError as exc:
        try:
            return _legacy_ssh(body)
        except ValueError:
            raise ValueError(f"SSH link format is invalid: {exc}") from exc
    if not host:
        raise ValueError("SSH link needs a server address, e.g. ssh://user:password@example.com:22")
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    if username and ":" in username:
        raise ValueError("SSH username cannot contain an unescaped colon in this app's import format.")
    return _ssh_result(host, port, username, password)


def _query(parsed) -> dict[str, str]:
    return {k: values[-1] for k, values in parse_qs(parsed.query, keep_blank_values=True).items()}


def _port(value: Any, default: int | None = None) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        if default is not None:
            return default
        raise ValueError("Proxy link has no valid server port.")
    if not 1 <= port <= 65535:
        raise ValueError("Proxy port must be between 1 and 65535.")
    return port


def _stream_settings(network: str, security: str, q: dict[str, str], fallback_host: str = "") -> dict[str, Any]:
    """Build the Xray streamSettings for common share-link transports."""
    net = (network or "tcp").lower()
    sec = (security or "none").lower()
    stream: dict[str, Any] = {"network": net, "security": sec}
    if sec == "tls":
        tls: dict[str, Any] = {"allowInsecure": q.get("allowInsecure", "false").lower() in {"1", "true", "yes"}}
        sni = q.get("sni") or q.get("servername")
        if sni:
            tls["serverName"] = sni
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        if q.get("alpn"):
            tls["alpn"] = [item.strip() for item in q["alpn"].split(",") if item.strip()]
        stream["tlsSettings"] = tls
    elif sec == "reality":
        reality: dict[str, Any] = {}
        for src, dst in (("sni", "serverName"), ("fp", "fingerprint"), ("pbk", "publicKey"), ("sid", "shortId"), ("spx", "spiderX")):
            if q.get(src):
                reality[dst] = q[src]
        stream["realitySettings"] = reality
    if net in {"ws", "websocket"}:
        ws: dict[str, Any] = {"path": q.get("path", "/") or "/"}
        host_header = q.get("host") or q.get("authority") or fallback_host
        if host_header:
            ws["headers"] = {"Host": host_header}
        stream["network"] = "ws"
        stream["wsSettings"] = ws
    elif net in {"grpc"}:
        stream["grpcSettings"] = {
            "serviceName": q.get("serviceName", q.get("path", "")),
            "multiMode": q.get("mode", "") == "multi",
        }
    elif net in {"httpupgrade", "http-upgrade"}:
        stream["network"] = "httpupgrade"
        httpupgrade: dict[str, Any] = {"path": q.get("path", "/") or "/"}
        host_header = q.get("host") or q.get("authority") or fallback_host
        if host_header:
            httpupgrade["host"] = host_header
        stream["httpupgradeSettings"] = httpupgrade
    elif net in {"xhttp", "splithttp"}:
        stream["network"] = "xhttp"
        xhttp: dict[str, Any] = {"path": q.get("path", "/") or "/"}
        host_header = q.get("host") or q.get("authority") or fallback_host
        if host_header:
            xhttp["host"] = host_header
        if q.get("mode"):
            xhttp["mode"] = q["mode"]
        stream["xhttpSettings"] = xhttp
    elif net == "tcp" and q.get("headerType", "none").lower() == "http":
        stream["tcpSettings"] = {"header": {"type": "http", "request": {"headers": {"Host": [q.get("host", fallback_host)]}}}}
    return stream


def _parse_vless_uri(value: str) -> dict[str, Any]:
    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError("VLESS link needs a server address, e.g. vless://UUID@host:443?... .")
    user_id = unquote(parsed.username or "")
    if not user_id:
        raise ValueError("VLESS link is missing the UUID/user ID before @.")
    port = _port(parsed.port, 443)
    q = _query(parsed)
    network = q.get("type", q.get("network", "tcp"))
    security = q.get("security", "none")
    user: dict[str, Any] = {"id": user_id, "encryption": q.get("encryption", "none")}
    if q.get("flow"):
        user["flow"] = q["flow"]
    outbound: dict[str, Any] = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed.hostname, "port": port, "users": [user]}]},
        "streamSettings": _stream_settings(network, security, q, parsed.hostname),
        "tag": "noway-vless",
    }
    if q.get("serviceName") and network == "grpc":
        outbound["streamSettings"].setdefault("grpcSettings", {})["serviceName"] = q["serviceName"]
    return _profile_result("vless", parsed.hostname, port, outbound, unquote(parsed.fragment), network, security,
                           (q.get("sni") or q.get("servername") or ""))


def _decode_vmess_payload(value: str) -> dict[str, Any]:
    payload = value[len("vmess://"):].strip()
    payload += "=" * ((4 - len(payload) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        data = json.loads(raw.decode("utf-8-sig"))
    except Exception as exc:
        raise ValueError("VMess link must contain a valid Base64-encoded JSON profile.") from exc
    if not isinstance(data, dict):
        raise ValueError("VMess share link decoded to an invalid JSON object.")
    return data


def _parse_vmess_uri(value: str) -> dict[str, Any]:
    data = _decode_vmess_payload(value)
    host = str(data.get("add") or data.get("address") or "").strip()
    if not host:
        raise ValueError("VMess JSON is missing the server address ('add').")
    port = _port(data.get("port"))
    user_id = str(data.get("id") or "").strip()
    if not user_id:
        raise ValueError("VMess JSON is missing the UUID ('id').")
    network = str(data.get("net", "tcp")).lower()
    security = "tls" if str(data.get("tls", "")).lower() in {"tls", "xtls"} else "none"
    q = {
        "type": network,
        "security": security,
        "sni": str(data.get("sni") or ""),
        "host": str(data.get("host") or ""),
        "path": str(data.get("path") or "/"),
        "fp": str(data.get("fp") or ""),
        "serviceName": str(data.get("path") or data.get("serviceName") or ""),
        "headerType": str(data.get("type") or "none"),
    }
    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{
            "id": user_id, "alterId": int(data.get("aid") or 0),
            "security": str(data.get("scy") or "auto"), "level": 0,
        }]}]},
        "streamSettings": _stream_settings(network, security, q, host),
        "tag": "noway-vmess",
    }
    return _profile_result("vmess", host, port, outbound, str(data.get("ps") or "VMess"), network, security,
                           q.get("sni", ""))


def _parse_trojan_uri(value: str) -> dict[str, Any]:
    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError("Trojan link needs a server address.")
    password = unquote(parsed.username or "")
    if not password:
        raise ValueError("Trojan link is missing its password before @.")
    port = _port(parsed.port, 443)
    q = _query(parsed)
    network = q.get("type", q.get("network", "tcp"))
    security = q.get("security", "tls")
    server = {"address": parsed.hostname, "port": port, "password": password}
    outbound = {
        "protocol": "trojan", "settings": {"servers": [server]},
        "streamSettings": _stream_settings(network, security, q, parsed.hostname),
        "tag": "noway-trojan",
    }
    return _profile_result("trojan", parsed.hostname, port, outbound, unquote(parsed.fragment), network, security,
                           q.get("sni", ""))


def _profile_result(protocol: str, host: str, port: int, outbound: dict[str, Any], name: str,
                    network: str, security: str, sni: str) -> dict[str, Any]:
    return {"kind": "proxy_uri", "protocol": protocol, "host": host, "port": port,
            "name": name, "network": network, "security": security, "sni": sni,
            "outbound": outbound, "profile_ready": True}


def _metadata_for_outbound(outbound: dict[str, Any]) -> dict[str, Any]:
    protocol = str(outbound.get("protocol", "")).lower()
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    host, port = "", None
    try:
        if protocol in {"vless", "vmess"}:
            node = (settings.get("vnext") or [{}])[0]
            host, port = node.get("address", ""), node.get("port")
        elif protocol in {"trojan", "socks", "shadowsocks"}:
            node = (settings.get("servers") or [{}])[0]
            host, port = node.get("address", ""), node.get("port")
    except (AttributeError, IndexError, TypeError):
        pass
    security = str(stream.get("security", "none"))
    network = str(stream.get("network", "tcp"))
    tls = stream.get("tlsSettings") or {}
    reality = stream.get("realitySettings") or {}
    name = str(outbound.get("tag", protocol.upper()))
    return {"protocol": protocol, "host": str(host or ""),
            "port": _port(port, 443) if port is not None else None,
            "security": security, "network": network,
            "sni": str(tls.get("serverName") or reality.get("serverName") or ""),
            "tag": name}


def _json_profile(value: str) -> dict[str, Any]:
    try:
        config = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"The pasted text looks like JSON but is invalid: {exc.msg} (line {exc.lineno}).") from exc
    if not isinstance(config, dict):
        raise ValueError("JSON configuration must be an object.")
    outbounds = config.get("outbounds")
    if isinstance(outbounds, list):
        for outbound in outbounds:
            if not isinstance(outbound, dict):
                continue
            protocol = str(outbound.get("protocol", "")).lower()
            if protocol not in _PROXY_PROTOCOLS:
                continue
            meta = _metadata_for_outbound(outbound)
            # Preserve the selected outbound as-is, including transport/security options.
            return {"kind": "proxy_json", **meta, "outbound": outbound,
                    "name": meta.get("tag") or protocol.upper(), "profile_ready": True,
                    "source_config": {k: v for k, v in config.items() if k in {"dns", "routing", "policy", "stats", "log", "api"}}}
    if config.get("inbounds") and not outbounds:
        return {"kind": "server_json", "protocol": "inbound", "inbound_count": len(config.get("inbounds", []))}
    raise ValueError("JSON configuration has no supported client outbound (VLESS/VMess/Trojan/SOCKS/Shadowsocks).")


def parse_import_text(text: str) -> dict[str, Any]:
    """Parse SSH account strings, proxy share links, or Xray/V2Ray outbound JSON."""
    value = text.strip()
    if not value:
        raise ValueError("Paste an SSH link, proxy link, account string, or JSON configuration first.")
    lower = value.lower()
    if lower.startswith("{"):
        return _json_profile(value)
    if lower.startswith("vless://"):
        return _parse_vless_uri(value)
    if lower.startswith("vmess://"):
        return _parse_vmess_uri(value)
    if lower.startswith("trojan://"):
        return _parse_trojan_uri(value)
    if lower.startswith(("ss://", "socks://")):
        scheme = lower.split(":", 1)[0]
        return {"kind": "proxy_uri", "protocol": scheme, "profile_ready": False}
    if lower.startswith("ssh://"):
        return _parse_ssh_uri(value)
    try:
        return _legacy_ssh(value)
    except ValueError as exc:
        raise ValueError(
            "Unrecognized config. Use ssh://user:password@host:22, "
            "host:port@username:password, a VLESS/VMess/Trojan share link, or an Xray/V2Ray JSON outbound."
        ) from exc
