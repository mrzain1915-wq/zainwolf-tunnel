"""Network helpers for ZainWolf Tunnel. Uses only the Python standard library."""
from __future__ import annotations

import re
import select
import socket
import time
from typing import Callable, Optional, Tuple

DEFAULT_PAYLOAD = (
    "CONNECT [host_port] [protocol][crlf]"
    "Host: [host_port][crlf]"
    "Proxy-Connection: Keep-Alive[crlf][crlf]"
)


def parse_server_spec(spec: str) -> Tuple[str, int, str, str]:
    """Parse host:port@username:password; password may contain ':' or '@'."""
    raw = spec.strip()
    if "@" not in raw:
        raise ValueError("Server format must be host:port@username:password")
    endpoint, credentials = raw.split("@", 1)
    if ":" not in credentials:
        raise ValueError("Credentials must be username:password")
    username, password = credentials.split(":", 1)
    if not username.strip():
        raise ValueError("SSH username is required")
    if not password:
        raise ValueError("SSH password is required")
    host, port = parse_host_port(endpoint)
    return host, port, username.strip(), password


def parse_host_port(spec: str) -> Tuple[str, int]:
    """Parse host:port, including bracketed IPv6 endpoints."""
    raw = spec.strip()
    if not raw:
        raise ValueError("Host and port are required")
    if raw.startswith("["):
        close = raw.find("]")
        if close < 0 or close + 1 >= len(raw) or raw[close + 1] != ":":
            raise ValueError("IPv6 endpoints must look like [2001:db8::1]:443")
        host, port_text = raw[1:close], raw[close + 2 :]
    else:
        if ":" not in raw:
            raise ValueError("Use host:port, for example ssh.example.com:443")
        host, port_text = raw.rsplit(":", 1)
    if not host.strip():
        raise ValueError("Host is required")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("Port must be a number from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return host.strip(), port


def build_payload(template: str, host: str, port: int) -> bytes:
    """Expand common HTTP Injector-style tokens and return Latin-1 bytes."""
    host_port = f"{host}:{port}"
    text = template.strip("\n") or DEFAULT_PAYLOAD
    # Support people pasting literal escape sequences as well as [crlf] tokens.
    text = text.replace("\\r\\n", "\r\n").replace("\\n", "\n").replace("\\r", "\r")
    values = {
        "host_port": host_port,
        "host": host,
        "port": str(port),
        "ssh": host_port,
        "protocol": "HTTP/1.1",
        "netData": f"CONNECT {host_port} HTTP/1.1",
        "crlf": "\r\n",
        "lfcr": "\n\r",
        "cr": "\r",
        "lf": "\n",
    }
    token_re = re.compile(r"\[(host_port|host|port|ssh|protocol|netData|crlf|lfcr|cr|lf)\]")
    text = token_re.sub(lambda match: values[match.group(1)], text)
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("Payload contains characters outside Latin-1; use ASCII/HTTP text") from exc


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("Proxy closed the connection during handshake")
        data.extend(chunk)
    return bytes(data)


def _read_http_response_head(sock: socket.socket, deadline: float) -> Tuple[str, dict]:
    """Read exactly one HTTP response header block without consuming later tunnel bytes."""
    response = bytearray()
    while not response.endswith(b"\r\n\r\n") and not response.endswith(b"\n\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the next HTTP response")
        sock.settimeout(remaining)
        byte = sock.recv(1)
        if not byte:
            raise OSError("Proxy closed the connection before completing an HTTP response")
        response.extend(byte)
        if len(response) > 16384:
            raise OSError("Proxy response headers exceeded 16 KB")

    lines = bytes(response).replace(b"\r\n", b"\n").split(b"\n")
    first_line = lines[0].decode("latin-1", "replace").strip()
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)", first_line, re.IGNORECASE)
    if not match:
        raise OSError(f"Expected an HTTP response, received: {first_line[:160] or '(empty line)'}")
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.decode("latin-1", "replace").strip().lower()] = value.decode("latin-1", "replace").strip()
    return first_line, {"status": int(match.group(1)), "headers": headers}


def _read_exact_with_deadline(sock: socket.socket, count: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out while reading the HTTP response body")
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("Proxy closed the connection while sending an HTTP response body")
        data.extend(chunk)
    return bytes(data)


def _discard_http_response_body(sock: socket.socket, headers: dict, deadline: float) -> None:
    """Consume a redirect/interim response body if its length is explicitly framed."""
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        # Read chunk-size lines and discard each chunk, including the final trailer block.
        while True:
            line = bytearray()
            while not line.endswith(b"\r\n"):
                if deadline <= time.monotonic():
                    raise TimeoutError("Timed out reading chunked HTTP response")
                sock.settimeout(deadline - time.monotonic())
                byte = sock.recv(1)
                if not byte:
                    raise OSError("Proxy closed during chunked HTTP response")
                line.extend(byte)
                if len(line) > 1024:
                    raise OSError("Invalid HTTP chunk-size line")
            try:
                chunk_size = int(bytes(line).strip().split(b";", 1)[0], 16)
            except ValueError as exc:
                raise OSError("Proxy returned an invalid chunked response") from exc
            if chunk_size == 0:
                # Final chunk is followed by zero or more trailers and a blank line.
                trailer = bytearray()
                while not trailer.endswith(b"\r\n\r\n") and not trailer.endswith(b"\n\n"):
                    if deadline <= time.monotonic():
                        raise TimeoutError("Timed out reading HTTP response trailers")
                    sock.settimeout(deadline - time.monotonic())
                    byte = sock.recv(1)
                    if not byte:
                        raise OSError("Proxy closed while sending HTTP response trailers")
                    trailer.extend(byte)
                    if len(trailer) > 16384:
                        raise OSError("HTTP response trailers exceeded 16 KB")
                return
            _read_exact_with_deadline(sock, chunk_size + 2, deadline)  # data plus CRLF
        
    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            count = int(content_length)
        except ValueError as exc:
            raise OSError("Proxy returned an invalid Content-Length") from exc
        if count < 0 or count > 8 * 1024 * 1024:
            raise OSError("Proxy response body length is unreasonable")
        _read_exact_with_deadline(sock, count, deadline)


def _peek_next_http_response(sock: socket.socket, timeout: float) -> str:
    """Return 'http', 'other', or 'timeout' without consuming bytes from the socket."""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        ready, _, _ = select.select([sock], [], [], remaining)
        if not ready:
            return "timeout"
        try:
            prefix = sock.recv(5, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            continue
        if not prefix:
            return "closed"
        if prefix.startswith(b"HTTP/") or b"HTTP/".startswith(prefix):
            # A partial prefix is enough: the next header reader will finish it.
            return "http"
        return "other"


def open_http_proxy_tunnel(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    payload_template: str,
    timeout: float = 15.0,
    status_callback: Optional[Callable[[str], None]] = None,
) -> socket.socket:
    """Send a custom payload and handle chained HTTP statuses used by payload tunnels.

    Some payload-based fronting setups return a redirect (3xx), followed by a protocol
    switch (101) and then a successful tunnel response. A redirect is not itself proof
    of a tunnel, so this continues only when another HTTP response follows; it still
    rejects ordinary proxy errors such as 403/407/502. If 101 is followed by raw protocol
    bytes instead of another HTTP status, the stream is handed to SSH without consuming
    those bytes.
    """
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        deadline = time.monotonic() + timeout
        sock.settimeout(timeout)
        payload = build_payload(payload_template, target_host, target_port)
        if not payload.endswith((b"\r\n\r\n", b"\n\n")):
            payload += b"\r\n\r\n"
        sock.sendall(payload)

        status_chain = []
        intermediate_codes = {100, 101, 102, 103, 301, 302, 303, 307, 308}
        for _ in range(8):
            first_line, response = _read_http_response_head(sock, deadline)
            status_code = response["status"]
            headers = response["headers"]
            status_chain.append(f"{status_code}")
            if status_callback:
                status_callback(first_line)

            if 200 <= status_code < 300:
                sock.settimeout(None)
                return sock

            if status_code not in intermediate_codes:
                raise OSError(f"HTTP proxy rejected payload: {first_line[:160]}")

            # Redirect responses may carry an HTML body; consume it before looking for
            # a following response, otherwise that body could be mistaken for a status.
            if status_code in {301, 302, 303, 307, 308}:
                _discard_http_response_body(sock, headers, deadline)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if status_code == 101:
                    sock.settimeout(None)
                    return sock
                break
            peek_timeout = min(remaining, 2.0 if status_code != 101 else 1.0)
            next_response = _peek_next_http_response(sock, peek_timeout)
            if next_response == "http":
                continue
            if status_code == 101 and next_response in {"other", "timeout"}:
                # HTTP 101 switches protocols. Leave any SSH banner/data unread for Paramiko.
                sock.settimeout(None)
                return sock
            if status_code == 101 and next_response == "closed":
                raise OSError("Proxy closed immediately after HTTP 101 Switching Protocols")
            if next_response == "other" and status_code in {301, 302, 303, 307, 308}:
                # Some compatible endpoints pass the SSH banner directly after a redirect.
                # Peek at it so Paramiko receives the entire banner unchanged.
                prefix = sock.recv(4, socket.MSG_PEEK)
                if prefix == b"SSH-":
                    sock.settimeout(None)
                    return sock
                raise OSError(
                    f"HTTP payload returned {first_line[:80]} but no follow-up tunnel response arrived; "
                    "verify the payload and proxy mode"
                )
            if next_response == "timeout":
                break
            if next_response == "closed":
                raise OSError("Proxy closed after HTTP payload response(s): " + " -> ".join(status_chain))

        raise OSError(
            "HTTP payload did not establish a tunnel (responses: " + " -> ".join(status_chain) + "). "
            "The proxy must continue with a tunnel response; check the payload and proxy settings."
        )
    except Exception:
        sock.close()
        raise


def open_socks5_proxy_tunnel(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 15.0,
) -> socket.socket:
    """Open a TCP tunnel through a no-auth SOCKS5 upstream proxy."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        version, method = _recv_exact(sock, 2)
        if version != 5 or method != 0:
            raise OSError("SOCKS5 proxy requires authentication or rejected no-auth mode")

        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise OSError("Target hostname is too long for SOCKS5")
        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
        sock.sendall(request)
        version, reply, _reserved, addr_type = _recv_exact(sock, 4)
        if version != 5 or reply != 0:
            reasons = {
                1: "general failure", 2: "connection not allowed", 3: "network unreachable",
                4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                7: "command unsupported", 8: "address type unsupported",
            }
            raise OSError(f"SOCKS5 proxy could not reach SSH server: {reasons.get(reply, f'error {reply}')}")
        if addr_type == 1:
            _recv_exact(sock, 4 + 2)
        elif addr_type == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif addr_type == 4:
            _recv_exact(sock, 16 + 2)
        else:
            raise OSError("SOCKS5 proxy returned an invalid address type")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise
