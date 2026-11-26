from __future__ import annotations

import base64
import hashlib
import os
import queue
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from pathlib import Path

from noway_core import DEFAULT_PAYLOAD, open_http_proxy_tunnel, open_socks5_proxy_tunnel, parse_host_port, parse_server_spec
from config_import import parse_import_text
from xray_backend import find_xray_binary, resolve_endpoint_ipv4, write_runtime_config
from windows_proxy import apply_windows_system_proxy, restore_windows_system_proxy, recover_stale_windows_proxy
from windows_tun import FullTrafficManager, helpers_available, is_admin

try:
    import paramiko
except ImportError:
    paramiko = None

APP_NAME = "ZainWolf Tunnel"
APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "ZainWolfTunnel"
SETTINGS_FILE = APP_DIR / "settings.json"
KNOWN_HOSTS_FILE = APP_DIR / "known_hosts"

BG = "#0b1020"
PANEL = "#131c2e"
PANEL_2 = "#172239"
BORDER = "#293650"
TEXT = "#edf2ff"
MUTED = "#98a7c4"
GREEN = "#40e0a0"
RED = "#ff647c"
BLUE = "#79a9ff"


class HostKeyPromptPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    """Ask before trusting a first-seen SSH host key; saved keys are checked thereafter."""
    def __init__(self, app):
        self.app = app

    def missing_host_key(self, client, hostname, key):
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        event = threading.Event()
        request = {"kind": "host_key", "hostname": hostname, "key_type": key.get_name(),
                   "fingerprint": "SHA256:" + fingerprint, "event": event, "accepted": False}
        self.app.messages.put(request)
        deadline = time.monotonic() + 180
        while not event.wait(0.25):
            if self.app.close_requested:
                raise paramiko.SSHException("Application closed before host-key confirmation")
            if time.monotonic() >= deadline:
                raise paramiko.SSHException("Timed out waiting for host-key confirmation")
        if not request["accepted"]:
            raise paramiko.SSHException("SSH host key was not trusted; connection cancelled")
        client._host_keys.add(hostname, key.get_name(), key)
        client.save_host_keys(str(KNOWN_HOSTS_FILE))


class LocalSocksServer:
    """Small, no-auth SOCKS5 server that forwards TCP streams over SSH channels."""
    def __init__(self, transport, host="127.0.0.1", port=1080):
        self.transport = transport
        self.host = host
        self.port = int(port)
        self.stop_event = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, self.port))
        self.listener.listen(64)
        self.listener.settimeout(1.0)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        try:
            self.listener.close()
        except OSError:
            pass

    @staticmethod
    def _read_exact(sock, length):
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise OSError("Client disconnected")
            data.extend(chunk)
        return bytes(data)

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, address), daemon=True).start()

    def _handle(self, conn, address):
        channel = None
        try:
            conn.settimeout(20)
            version, nmethods = self._read_exact(conn, 2)
            if version != 5:
                return
            methods = self._read_exact(conn, nmethods)
            if 0 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x00")
            version, command, _reserved, atyp = self._read_exact(conn, 4)
            if version != 5 or command != 1:
                conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if atyp == 1:
                target_host = socket.inet_ntop(socket.AF_INET, self._read_exact(conn, 4))
            elif atyp == 3:
                length = self._read_exact(conn, 1)[0]
                target_host = self._read_exact(conn, length).decode("idna")
            elif atyp == 4:
                target_host = socket.inet_ntop(socket.AF_INET6, self._read_exact(conn, 16))
            else:
                conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            target_port = int.from_bytes(self._read_exact(conn, 2), "big")
            if not self.transport or not self.transport.is_active():
                conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            channel = self.transport.open_channel(
                "direct-tcpip", (target_host, target_port), address, timeout=15
            )
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.settimeout(None)
            self._relay(conn, channel)
        except Exception:
            try:
                conn.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass

    @staticmethod
    def _relay(client_sock, channel):
        """Relay bytes between a real client socket and a Paramiko SSH Channel.

        On Windows, select.select() can monitor Winsock sockets but not Paramiko's
        pipe-backed Channel.fileno(). Therefore we select only the client socket and
        poll Channel.recv_ready() for data from SSH. Socket-like test doubles retain a
        fallback path so the relay can also be integration-tested without Paramiko.
        """
        import select
        use_paramiko_polling = callable(getattr(channel, "recv_ready", None))
        client_eof = False
        while True:
            try:
                readable = []
                if not client_eof:
                    readable, _, _ = select.select([client_sock], [], [], 0.05)
            except (OSError, ValueError):
                return

            if readable:
                try:
                    data = client_sock.recv(32768)
                except OSError:
                    return
                if not data:
                    client_eof = True
                    try:
                        channel.shutdown_write()
                    except (AttributeError, OSError, EOFError):
                        return
                else:
                    try:
                        channel.sendall(data)
                    except Exception:
                        return

            try:
                if use_paramiko_polling:
                    remote_ready = channel.recv_ready()
                else:
                    remote_ready = bool(select.select([channel], [], [], 0)[0])
                if remote_ready:
                    data = channel.recv(32768)
                    if not data:
                        return
                    client_sock.sendall(data)
                elif client_eof:
                    time.sleep(0.05)
                elif getattr(channel, "closed", False) and not getattr(channel, "recv_ready", lambda: False)():
                    return
            except (OSError, EOFError, ValueError):
                return


class LocalHttpProxyServer:
    """HTTP proxy that opens each destination through the authenticated SSH transport.

    It supports HTTPS CONNECT and ordinary absolute-form HTTP requests. This allows
    browsers and Windows applications that honor the Windows system HTTP proxy to use
    the SSH tunnel without manually configuring each app's SOCKS setting.
    """
    def __init__(self, transport, host="127.0.0.1", port=8081):
        self.transport = transport
        self.host = host
        self.port = int(port)
        self.stop_event = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, self.port))
        self.listener.listen(64)
        self.listener.settimeout(1.0)
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        try:
            self.listener.close()
        except OSError:
            pass

    @staticmethod
    def _read_request_headers(conn):
        data = bytearray()
        while not data.endswith(b"\r\n\r\n") and not data.endswith(b"\n\n"):
            chunk = conn.recv(1)
            if not chunk:
                raise OSError("Browser closed before sending complete HTTP headers")
            data.extend(chunk)
            if len(data) > 65536:
                raise OSError("HTTP request headers exceeded 64 KB")
        return bytes(data)

    @staticmethod
    def _send_error(conn, code, message):
        body = (message + "\n").encode("utf-8", "replace")
        response = (
            f"HTTP/1.1 {code} {message}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii", "replace") + body
        try:
            conn.sendall(response)
        except OSError:
            pass

    def _accept_loop(self):
        while not self.stop_event.is_set():
            try:
                conn, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, address), daemon=True).start()

    def _handle(self, conn, address):
        channel = None
        answered = False
        try:
            conn.settimeout(30)
            raw = self._read_request_headers(conn)
            header_block = raw.replace(b"\r\n", b"\n")
            lines = header_block.split(b"\n")
            request_line = lines[0].decode("latin-1", "replace").strip()
            parts = request_line.split(" ", 2)
            if len(parts) != 3:
                self._send_error(conn, 400, "Bad Request")
                return
            method, target, version = parts
            is_connect = method.upper() == "CONNECT"

            if is_connect:
                try:
                    target_host, target_port = parse_host_port(target)
                except ValueError:
                    self._send_error(conn, 400, "Invalid CONNECT target")
                    return
                outbound = b""
            else:
                from urllib.parse import urlsplit
                parsed = urlsplit(target)
                if parsed.scheme.lower() != "http" or not parsed.hostname:
                    self._send_error(conn, 501, "Only HTTP and HTTPS CONNECT are supported")
                    return
                target_host = parsed.hostname
                target_port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                forwarded_lines = [f"{method} {path} {version}"]
                saw_host = False
                for raw_line in lines[1:]:
                    if not raw_line:
                        break
                    line = raw_line.decode("latin-1", "replace")
                    lower = line.split(":", 1)[0].strip().lower()
                    if lower in {"proxy-connection", "proxy-authorization", "connection"}:
                        continue
                    if lower == "host":
                        saw_host = True
                    forwarded_lines.append(line)
                if not saw_host:
                    host_header = target_host if target_port == 80 else f"{target_host}:{target_port}"
                    forwarded_lines.append(f"Host: {host_header}")
                forwarded_lines.append("Connection: close")
                outbound = ("\r\n".join(forwarded_lines) + "\r\n\r\n").encode("latin-1", "replace")

            if not self.transport or not self.transport.is_active():
                self._send_error(conn, 503, "SSH tunnel is not active")
                return
            channel = self.transport.open_channel(
                "direct-tcpip", (target_host, target_port), address, timeout=15
            )
            if is_connect:
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: ZainWolfTunnel\r\n\r\n")
            else:
                channel.sendall(outbound)
            answered = True
            conn.settimeout(None)
            LocalSocksServer._relay(conn, channel)
        except Exception as exc:
            if not answered:
                self._send_error(conn, 502, "Bad Gateway")
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if channel is not None:
                try:
                    channel.close()
                except Exception:
                    pass


class ZainWolfTunnelApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        self.root.configure(bg=BG)
        self.root.geometry("1080x800")
        self.root.minsize(940, 760)
        self.messages = queue.Queue()
        self.client = None
        self.xray_process = None
        self.xray_config_path = None
        self.active_proxy_profile = None
        self.socks_server = None
        self.http_server = None
        self.full_traffic_manager = None
        self.system_proxy_active = False
        # Undo a stale proxy redirection left by a previous crashed instance.
        try:
            recover_stale_windows_proxy(APP_DIR / "system_proxy_backup.json")
        except Exception:
            pass
        self.connecting = False
        self.close_requested = False
        self.last_error = None
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if not KNOWN_HOSTS_FILE.exists():
            KNOWN_HOSTS_FILE.write_text("", encoding="utf-8")
        self._configure_style()
        self._build_ui()
        self._load_settings()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._process_messages)
        if paramiko is None:
            self.root.after(250, self._missing_dependency)

    def _configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Heading.TLabel", background=PANEL, foreground=TEXT, font=("Segoe UI Semibold", 11))
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 24))
        style.configure("TEntry", fieldbackground="#0c1425", foreground=TEXT,
                        insertcolor=TEXT, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER,
                        padding=9)
        style.configure("TCombobox", fieldbackground="#0c1425", background="#0c1425",
                        foreground=TEXT, arrowcolor=GREEN, padding=8)
        style.map("TCombobox", fieldbackground=[("readonly", "#0c1425")],
                  foreground=[("readonly", TEXT)])
        style.configure("Green.TButton", background=GREEN, foreground="#07121a",
                        font=("Segoe UI Semibold", 10), borderwidth=0, padding=(14, 10))
        style.map("Green.TButton", background=[("active", "#66edb5"), ("disabled", "#335b53")])
        style.configure("Secondary.TButton", background="#25334c", foreground=TEXT,
                        font=("Segoe UI Semibold", 10), borderwidth=0, padding=(12, 10))
        style.map("Secondary.TButton", background=[("active", "#334666"), ("disabled", "#1b263a")])

    def _panel(self, parent, title, subtitle=None):
        outer = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        header = tk.Frame(outer, bg=PANEL)
        header.pack(fill="x", padx=16, pady=(10, 5))
        ttk.Label(header, text=title, style="Heading.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(header, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(3, 0))
        body = tk.Frame(outer, bg=PANEL)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 11))
        return outer, body

    def _field(self, parent, label, variable, placeholder=None, show=None):
        wrap = tk.Frame(parent, bg=PANEL)
        tk.Label(wrap, text=label, bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(0, 5))
        entry = ttk.Entry(wrap, textvariable=variable, show=show or "")
        entry.pack(fill="x")
        if placeholder and not variable.get():
            entry.insert(0, placeholder)
            entry.configure(foreground="#71809d")
            def clear_hint(_event):
                if entry.get() == placeholder:
                    entry.delete(0, "end")
                    entry.configure(foreground=TEXT)
            def restore_hint(_event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.configure(foreground="#71809d")
            entry.bind("<FocusIn>", clear_hint)
            entry.bind("<FocusOut>", restore_hint)
        return wrap, entry

    def _build_ui(self):
        top = tk.Frame(self.root, bg=BG)
        top.pack(fill="x", padx=22, pady=(12, 8))
        brand = tk.Frame(top, bg=BG)
        brand.pack(side="left", fill="x", expand=True)
        ttk.Label(brand, text="ZAINWOLF TUNNEL", style="Title.TLabel").pack(anchor="w")
        self.subtitle_var = tk.StringVar(value="SSH  •  PROXY  •  PAYLOAD  •  LOCAL SOCKS5")
        tk.Label(brand, textvariable=self.subtitle_var, bg=BG, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 0))
        self.status_dot = tk.Label(top, text="●  DISCONNECTED", bg=BG, fg=MUTED,
                                   font=("Segoe UI Semibold", 10))
        self.status_dot.pack(side="right", padx=(8, 0), pady=10)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=22)
        body.columnconfigure(0, weight=6, uniform="main")
        body.columnconfigure(1, weight=4, uniform="main")
        body.rowconfigure(1, weight=1)

        # Top row: server and upstream proxy side by side.
        self.server_var = tk.StringVar()
        p, pb = self._panel(body, "SSH SERVER", "Format: host:port@username:password")
        p.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 10))
        wrap, _ = self._field(pb, "Server / login", self.server_var,
                              "ssh.example.com:443@user:password", show="")
        wrap.pack(fill="x")
        import_buttons = tk.Frame(pb, bg=PANEL)
        import_buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(import_buttons, text="Import Link / JSON…", style="Secondary.TButton",
                   command=self.import_config).pack(side="left")
        ttk.Button(import_buttons, text="Use SSH fields", style="Secondary.TButton",
                   command=self.use_ssh_profile).pack(side="left", padx=(7, 0))
        tk.Label(pb, text="SSH passwords are not saved in settings. Imported Xray profiles use the Xray Core engine.", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8), wraplength=510, justify="left").pack(anchor="w", pady=(5, 0))

        self.proxy_mode_var = tk.StringVar(value="HTTP + Payload")
        self.proxy_var = tk.StringVar()
        p, pb = self._panel(body, "UPSTREAM PROXY", "Direct SSH, HTTP payload proxy, or SOCKS5")
        p.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 10))
        proxy_fields = tk.Frame(pb, bg=PANEL)
        proxy_fields.pack(fill="x")
        proxy_fields.columnconfigure(0, weight=1)
        proxy_fields.columnconfigure(1, weight=1)
        mode_wrap = tk.Frame(proxy_fields, bg=PANEL)
        mode_wrap.grid(row=0, column=0, sticky="ew", padx=(0, 7))
        tk.Label(mode_wrap, text="Proxy mode", bg=PANEL, fg=MUTED,
                 font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(0, 5))
        self.proxy_mode_box = ttk.Combobox(mode_wrap, textvariable=self.proxy_mode_var, state="readonly",
                                           values=("Direct SSH", "HTTP + Payload", "SOCKS5"))
        self.proxy_mode_box.pack(fill="x")
        proxy_wrap, self.proxy_entry = self._field(proxy_fields, "Proxy host:port", self.proxy_var,
                                                   "proxy.example.com:8080")
        proxy_wrap.grid(row=0, column=1, sticky="ew")
        self.proxy_mode_box.bind("<<ComboboxSelected>>", self._proxy_mode_changed)

        # Bottom row: payload editor and compact tunnel controls.
        p, pb = self._panel(body, "PAYLOAD", "Tokens are substituted before the SSH handshake")
        p.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(0, 0))
        row = tk.Frame(pb, bg=PANEL)
        row.pack(fill="x", pady=(0, 6))
        tk.Label(row, text="HTTP CONNECT payload", bg=PANEL, fg=MUTED,
                 font=("Segoe UI Semibold", 9)).pack(side="left")
        ttk.Button(row, text="Reset default", style="Secondary.TButton", command=self.reset_payload).pack(side="right")
        self.payload_text = tk.Text(pb, height=4, wrap="word", bg="#0c1425", fg=TEXT,
                                    insertbackground=TEXT, relief="flat", highlightthickness=1,
                                    highlightbackground=BORDER, highlightcolor=GREEN,
                                    font=("Consolas", 9), padx=10, pady=8, undo=True)
        self.payload_text.pack(fill="both", expand=True)
        self.payload_text.insert("1.0", DEFAULT_PAYLOAD)
        tk.Label(pb, text="Tokens: [host] [port] [host_port] [ssh] [protocol] [netData] [cr] [lf] [crlf] [lfcr]",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=570,
                 justify="left").pack(anchor="w", pady=(6, 0))

        p, pb = self._panel(body, "LOCAL TUNNEL & CONTROLS", None)
        p.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(0, 0))
        self.local_port_var = tk.StringVar(value="1080")
        self.http_port_var = tk.StringVar(value="8081")
        ports_row = tk.Frame(pb, bg=PANEL)
        ports_row.pack(fill="x")
        ports_row.columnconfigure(0, weight=1)
        ports_row.columnconfigure(1, weight=1)
        wrap, _ = self._field(ports_row, "Local SOCKS5 port", self.local_port_var)
        wrap.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        wrap, _ = self._field(ports_row, "Local HTTP proxy port", self.http_port_var)
        wrap.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        self.use_system_proxy_var = tk.BooleanVar(value=True)
        tk.Checkbutton(pb, text="Route Windows proxy-aware apps (browser/web) through tunnel",
                       variable=self.use_system_proxy_var, bg=PANEL, fg=TEXT, selectcolor=BG,
                       activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 8),
                       anchor="w").pack(fill="x", pady=(7, 1))
        self.full_traffic_var = tk.BooleanVar(value=False)
        tk.Checkbutton(pb, text="Full Traffic: IPv4 TCP (Wintun; Administrator)",
                       variable=self.full_traffic_var, bg=PANEL, fg="#ffd479", selectcolor=BG,
                       activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 8, "bold"),
                       anchor="w").pack(fill="x", pady=(1, 1))
        self.local_address = tk.StringVar(value="SOCKS5 127.0.0.1:1080  |  HTTP 127.0.0.1:8081")
        tk.Label(pb, textvariable=self.local_address, bg=PANEL_2, fg=GREEN,
                 font=("Consolas", 9, "bold"), padx=8, pady=7, anchor="w").pack(fill="x", pady=(4, 7))
        buttons = tk.Frame(pb, bg=PANEL)
        buttons.pack(fill="x", pady=(0, 7))
        buttons.columnconfigure(0, weight=1)
        buttons.columnconfigure(1, weight=1)
        self.connect_button = ttk.Button(buttons, text="CONNECT  →", style="Green.TButton", command=self.connect)
        self.connect_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.disconnect_button = ttk.Button(buttons, text="DISCONNECT", style="Secondary.TButton",
                                            command=self.disconnect, state="disabled")
        self.disconnect_button.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.copy_button = ttk.Button(pb, text="Copy proxy addresses", style="Secondary.TButton", command=self.copy_address)
        self.copy_button.pack(fill="x")
        tk.Label(pb, text="Full Traffic routes IPv4/TCP via Wintun. DNS uses the underlying resolver; UDP and IPv6 are not tunneled by this SSH relay.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=350,
                 justify="left").pack(anchor="w", pady=(5, 0))

        logs_outer = tk.Frame(self.root, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        logs_outer.pack(fill="both", padx=22, pady=(8, 8))
        log_head = tk.Frame(logs_outer, bg=PANEL)
        log_head.pack(fill="x", padx=16, pady=(8, 4))
        tk.Label(log_head, text="CONNECTION LOG", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(side="left")
        tk.Label(log_head, text="  ·  passwords are not logged", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="left", padx=(5, 0))
        ttk.Button(log_head, text="Clear", style="Secondary.TButton", command=self.clear_logs).pack(side="right")
        self.log_text = tk.Text(logs_outer, height=3, wrap="word", bg="#080e1a", fg="#b7c6e2",
                                insertbackground=TEXT, relief="flat", state="disabled",
                                font=("Consolas", 9), padx=10, pady=6)
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 9))
        self.log_text.tag_configure("ok", foreground=GREEN)
        self.log_text.tag_configure("error", foreground=RED)
        self.log_text.tag_configure("info", foreground=BLUE)
        self.log("Ready. Enter your SSH account details to begin.", "info")

    def _proxy_mode_changed(self, _event=None):
        mode = self.proxy_mode_var.get()
        state = "disabled" if mode == "Direct SSH" else "normal"
        self.proxy_entry.configure(state=state)
        self.log(f"Proxy mode set to {mode}.", "info")

    def _effective_full_traffic_mode(self):
        """Use Full Traffic only when its platform, privileges, and helper files are ready.

        Missing optional TUN prerequisites must not block a regular SSH or Xray local-proxy
        connection. In that case turn the saved preference off, tell the user what was
        changed, and let the caller continue with SOCKS5/HTTP proxy mode.
        """
        if not bool(self.full_traffic_var.get()):
            return False

        reason = None
        if os.name != "nt":
            reason = "Full Traffic is available only on Windows 10/11."
        elif not is_admin():
            reason = "Full Traffic requires administrator rights."
        elif not helpers_available():
            reason = "Full Traffic helper files are missing (tun2socks.exe and/or wintun.dll)."

        if reason:
            self.full_traffic_var.set(False)
            self.log(
                f"{reason} Continuing with local SOCKS5/HTTP proxy mode only; "
                "system-proxy-aware apps can still use the tunnel, but other apps will not be routed.",
                "error",
            )
            # Persist the fallback so the next launch does not repeatedly request unavailable TUN mode.
            self._save_settings()
            messagebox.showwarning(
                "Full Traffic unavailable",
                f"{reason}\n\n"
                "ZainWolf Tunnel will continue in local SOCKS5/HTTP proxy mode. "
                "VLESS/VMess/Trojan via Xray and SSH can still connect without tun2socks. "
                "Full Traffic will work only after its helper files are installed and the EXE is rebuilt.",
                parent=self.root,
            )
            return False
        return True

    def use_ssh_profile(self):
        """Switch back to the existing SSH connection backend."""
        self.active_proxy_profile = None
        self.subtitle_var.set("SSH  •  PROXY  •  PAYLOAD  •  LOCAL SOCKS5")
        self.log("SSH mode selected. The server/login field will be used on Connect.", "info")

    def import_config(self):
        """Import SSH credentials or parse a VLESS/VMess/Trojan/Xray profile."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Import Connection Link / JSON")
        dialog.configure(bg=PANEL)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("690x420")
        tk.Label(dialog, text="Paste SSH link, proxy link, or Xray/V2Ray JSON", bg=PANEL,
                 fg=TEXT, font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=14, pady=(14, 5))
        tk.Label(dialog, text="Examples: ssh://user:password@host:22  |  vless://UUID@host:443?...  |  host:port@user:password",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9), wraplength=650,
                 justify="left").pack(anchor="w", padx=14, pady=(0, 8))
        editor = tk.Text(dialog, height=12, wrap="word", bg="#0c1425", fg=TEXT,
                         insertbackground=TEXT, relief="flat", highlightthickness=1,
                         highlightbackground=BORDER, font=("Consolas", 9), padx=9, pady=8)
        editor.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        btnrow = tk.Frame(dialog, bg=PANEL)
        btnrow.pack(fill="x", padx=14, pady=(0, 14))

        def do_import():
            try:
                result = parse_import_text(editor.get("1.0", "end-1c"))
                kind = result["kind"]
                if kind == "ssh":
                    username = result.get("username", "")
                    password = result.get("password", "")
                    if not username:
                        username = simpledialog.askstring("SSH username", "Enter SSH username:", parent=dialog) or ""
                    if not username.strip():
                        messagebox.showerror("Import SSH link", "SSH username is required.", parent=dialog)
                        return
                    if not password:
                        password = simpledialog.askstring("SSH password", "Enter SSH password (not saved in settings):",
                                                           show="*", parent=dialog) or ""
                    if not password:
                        messagebox.showerror("Import SSH link", "SSH password is required. Password-only/key authentication is not supported by this importer yet.", parent=dialog)
                        return
                    host_display = f"[{result['host']}]" if ":" in result["host"] and not result["host"].startswith("[") else result["host"]
                    self.active_proxy_profile = None
                    self.subtitle_var.set("SSH  •  PROXY  •  PAYLOAD  •  LOCAL SOCKS5")
                    self.server_var.set(f"{host_display}:{result['port']}@{username.strip()}:{password}")
                    self.log(f"Imported SSH endpoint {host_display}:{result['port']} (credentials are not logged).", "ok")
                    dialog.destroy()
                    messagebox.showinfo("Import complete", "SSH host, port, username and password fields were filled. Review proxy/payload options before connecting.", parent=self.root)
                    return
                if kind in ("proxy_json", "proxy_uri"):
                    protocol = str(result.get("protocol", "unknown")).upper()
                    if not result.get("profile_ready") or not isinstance(result.get("outbound"), dict):
                        messagebox.showerror("Unsupported profile", f"{protocol} was detected, but this link format could not be converted into an Xray outbound. Check that the URI includes credentials and a server address.", parent=dialog)
                        return
                    self.active_proxy_profile = result
                    self.subtitle_var.set(f"{protocol}  •  XRAY CORE  •  LOCAL SOCKS5 / HTTP")
                    self.log(f"Imported {protocol} profile {result.get('name') or ''}; endpoint {result.get('host')}:{result.get('port')} (credentials hidden).", "ok")
                    dialog.destroy()
                    xray_path = find_xray_binary(Path(__file__).resolve().parent)
                    if xray_path:
                        runtime_message = f"Xray engine found: {xray_path}"
                    else:
                        runtime_message = ("Xray Core executable was not found. Download the official Windows 64-bit Xray Core ZIP, "
                                           "copy xray.exe to this project's tools/xray.exe or %APPDATA%/ZainWolfTunnel/tools/xray.exe, "
                                           "then click CONNECT. You can import the link now and install the engine later.")
                    messagebox.showinfo(
                        "Profile imported",
                        f"{protocol} profile parsed successfully.\n\n"
                        f"Server: {result.get('host')}:{result.get('port')}\n"
                        f"Transport: {result.get('network', 'tcp')}  |  Security: {result.get('security', 'none')}\n"
                        f"SNI: {result.get('sni') or '(not specified)'}\n\n{runtime_message}\n\n"
                        "Click CONNECT to start this profile. SSH payload fields are not used for Xray profiles.",
                        parent=self.root,
                    )
                    return
                if kind == "server_json":
                    messagebox.showinfo("Server-side JSON detected", "This JSON contains inbound/server configuration only. It does not provide a client outbound. Paste a VLESS/VMess/Trojan link or Xray/V2Ray JSON containing a supported outbound.", parent=dialog)
                    return
            except Exception as exc:
                messagebox.showerror("Import failed", str(exc), parent=dialog)

        ttk.Button(btnrow, text="Import / Detect", style="Green.TButton", command=do_import).pack(side="right")
        ttk.Button(btnrow, text="Cancel", style="Secondary.TButton", command=dialog.destroy).pack(side="right", padx=(0, 8))
        editor.focus_set()

    def reset_payload(self):
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", DEFAULT_PAYLOAD)

    def copy_address(self):
        address = (f"SOCKS5 127.0.0.1:{self.local_port_var.get().strip()}\n"
                   f"HTTP 127.0.0.1:{self.http_port_var.get().strip()}")
        self.root.clipboard_clear()
        self.root.clipboard_append(address)
        self.log("Copied local SOCKS5 and HTTP proxy addresses.", "ok")

    def log(self, message, level="info"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_logs(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _set_status(self, connected, text=None):
        if connected:
            self.status_dot.configure(text="●  CONNECTED", fg=GREEN)
            self.connect_button.configure(state="disabled")
            self.disconnect_button.configure(state="normal")
        elif self.connecting:
            self.status_dot.configure(text="●  CONNECTING", fg=BLUE)
            self.connect_button.configure(state="disabled")
            self.disconnect_button.configure(state="disabled")
        else:
            self.status_dot.configure(text=text or "●  DISCONNECTED", fg=MUTED if not text else RED)
            self.connect_button.configure(state="normal")
            self.disconnect_button.configure(state="disabled")

    def connect(self):
        if self.connecting or self.client or self.xray_process:
            return
        if self.active_proxy_profile is not None:
            self.connect_xray_profile()
            return
        if paramiko is None:
            self._missing_dependency()
            return
        try:
            host, port, username, password = parse_server_spec(self.server_var.get())
            mode = self.proxy_mode_var.get()
            proxy_host = proxy_port = None
            if mode != "Direct SSH":
                proxy_host, proxy_port = parse_host_port(self.proxy_var.get())
            local_port = int(self.local_port_var.get().strip())
            http_port = int(self.http_port_var.get().strip())
            if not 1 <= local_port <= 65535:
                raise ValueError("Local SOCKS5 port must be between 1 and 65535")
            if not 1 <= http_port <= 65535:
                raise ValueError("Local HTTP proxy port must be between 1 and 65535")
            if local_port == http_port:
                raise ValueError("SOCKS5 port and HTTP proxy port must be different")
            use_system_proxy = bool(self.use_system_proxy_var.get())
            full_traffic = self._effective_full_traffic_mode()
            payload = self.payload_text.get("1.0", "end-1c")
        except Exception as exc:
            messagebox.showerror("Check your settings", str(exc), parent=self.root)
            return

        self.connecting = True
        self.last_error = None
        self._set_status(False)
        self.log("Starting SSH connection…", "info")
        self.messages.put({"kind": "log", "message": f"SSH target: {host}:{port}; mode: {mode}.", "level": "info"})
        self._save_settings()
        thread = threading.Thread(target=self._connect_worker,
                                  args=(host, port, username, password, mode, proxy_host, proxy_port, payload, local_port, http_port, use_system_proxy, full_traffic),
                                  daemon=True)
        thread.start()

    @staticmethod
    def _local_port_is_free(port):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", int(port)))
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def connect_xray_profile(self):
        """Start Xray Core using the imported VLESS/VMess/Trojan outbound."""
        profile = self.active_proxy_profile
        if not profile:
            return
        try:
            protocol = str(profile.get("protocol", "proxy")).upper()
            xray_bin = find_xray_binary(Path(__file__).resolve().parent)
            if not xray_bin:
                raise ValueError(
                    "Xray Core is required to connect this profile. Download the official Windows AMD64 "
                    "Xray Core release, then place xray.exe in tools/xray.exe beside the project or "
                    "%APPDATA%/ZainWolfTunnel/tools/xray.exe. Rebuild the EXE if you want to bundle it."
                )
            local_port = int(self.local_port_var.get().strip())
            http_port = int(self.http_port_var.get().strip())
            if not (1 <= local_port <= 65535 and 1 <= http_port <= 65535):
                raise ValueError("Local SOCKS5 and HTTP ports must be between 1 and 65535.")
            if local_port == http_port:
                raise ValueError("SOCKS5 port and HTTP proxy port must be different.")
            if not self._local_port_is_free(local_port):
                raise ValueError(f"Local SOCKS5 port {local_port} is already in use. Choose another port.")
            if not self._local_port_is_free(http_port):
                raise ValueError(f"Local HTTP port {http_port} is already in use. Choose another port.")
            use_system_proxy = bool(self.use_system_proxy_var.get())
            full_traffic = self._effective_full_traffic_mode()
            config_path = write_runtime_config(profile, local_port, http_port, APP_DIR)
            self.xray_config_path = config_path
        except Exception as exc:
            messagebox.showerror("Check your settings", str(exc), parent=self.root)
            return

        self.connecting = True
        self.last_error = None
        self._set_status(False)
        self.log(f"Starting Xray Core for imported {protocol} profile…", "info")
        self._save_settings()
        thread = threading.Thread(target=self._connect_xray_worker,
                                  args=(profile, xray_bin, config_path, local_port, http_port, use_system_proxy, full_traffic),
                                  daemon=True)
        thread.start()

    def _connect_xray_worker(self, profile, xray_bin, config_path, local_port, http_port, use_system_proxy, full_traffic):
        process = None
        tun_manager = None
        protocol = str(profile.get("protocol", "proxy")).upper()
        host = str(profile.get("host") or "")
        port = int(profile.get("port") or 0)
        log_path = APP_DIR / "xray.log"
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            self.messages.put({"kind": "log", "message": f"Starting local SOCKS5/HTTP inbounds for {protocol}…", "level": "info"})
            with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
                process = subprocess.Popen(
                    [str(xray_bin), "run", "-c", str(config_path)],
                    cwd=str(xray_bin.parent), stdin=subprocess.DEVNULL,
                    stdout=log_file, stderr=subprocess.STDOUT,
                    creationflags=creationflags,
                )
            deadline = time.monotonic() + 20.0
            ready = False
            while time.monotonic() < deadline:
                if self.close_requested:
                    raise RuntimeError("Application is closing.")
                if process.poll() is not None:
                    break
                socks_ready = self._tcp_listener_ready(local_port)
                http_ready = self._tcp_listener_ready(http_port)
                if socks_ready and http_ready:
                    ready = True
                    break
                time.sleep(0.25)
            if not ready:
                tail = ""
                try:
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-2400:]
                except OSError:
                    pass
                if process.poll() is not None:
                    raise RuntimeError(f"Xray Core exited with code {process.returncode}. See {log_path}.\n{tail[-1500:]}")
                raise RuntimeError(f"Xray Core did not start its local listeners within 20 seconds. See {log_path}.\n{tail[-1500:]}")
            if full_traffic:
                endpoint_ip = resolve_endpoint_ipv4(host)
                tun_manager = FullTrafficManager(
                    APP_DIR / "full_traffic_routes.json",
                    log_callback=lambda message, level="info": self.messages.put({"kind": "log", "message": message, "level": level}),
                )
                tun_manager.start(local_port, endpoint_ip)
            if self.close_requested:
                if tun_manager:
                    tun_manager.stop()
                process.terminate()
                process.wait(timeout=5)
                return
            self.messages.put({
                "kind": "connected", "engine": "xray", "protocol": protocol,
                "client": None, "server": None, "http_server": None,
                "xray_process": process, "xray_config_path": config_path,
                "tun_manager": tun_manager, "host": host, "port": port,
                "local_port": local_port, "http_port": http_port,
                "use_system_proxy": use_system_proxy,
            })
        except Exception as exc:
            if tun_manager:
                try:
                    tun_manager.stop()
                except Exception:
                    pass
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
            try:
                Path(config_path).unlink(missing_ok=True)
            except OSError:
                pass
            self.messages.put({"kind": "failed", "message": str(exc) or exc.__class__.__name__})

    @staticmethod
    def _tcp_listener_ready(port):
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.3):
                return True
        except OSError:
            return False

    def _connect_worker(self, host, port, username, password, mode, proxy_host, proxy_port, payload, local_port, http_port, use_system_proxy, full_traffic=False):
        sock = None
        client = None
        server = None
        http_server = None
        tun_manager = None
        try:
            if mode == "Direct SSH":
                self.messages.put({"kind": "log", "message": f"Opening direct TCP connection to {host}:{port}…", "level": "info"})
                sock = socket.create_connection((host, port), timeout=15)
                sock.settimeout(None)
            elif mode == "HTTP + Payload":
                self.messages.put({"kind": "log", "message": f"Connecting to HTTP proxy {proxy_host}:{proxy_port} and sending payload…", "level": "info"})
                sock = open_http_proxy_tunnel(
                    proxy_host, proxy_port, host, port, payload, timeout=15,
                    status_callback=lambda line: self.messages.put({
                        "kind": "log", "message": f"Payload response: {line}", "level": "info"
                    }),
                )
                self.messages.put({"kind": "log", "message": "Payload handshake advanced; starting SSH negotiation…", "level": "ok"})
            else:
                self.messages.put({"kind": "log", "message": f"Opening SOCKS5 route via {proxy_host}:{proxy_port}…", "level": "info"})
                sock = open_socks5_proxy_tunnel(proxy_host, proxy_port, host, port, timeout=15)
                self.messages.put({"kind": "log", "message": "SOCKS5 upstream proxy route established.", "level": "ok"})

            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.load_host_keys(str(KNOWN_HOSTS_FILE))
            client.set_missing_host_key_policy(HostKeyPromptPolicy(self))
            client.connect(hostname=host, port=port, username=username, password=password, sock=sock,
                           timeout=15, banner_timeout=20, auth_timeout=20,
                           allow_agent=False, look_for_keys=False)
            transport = client.get_transport()
            if not transport or not transport.is_active():
                raise RuntimeError("SSH transport did not become active")
            transport.set_keepalive(30)
            if self.close_requested:
                client.close()
                return
            server = LocalSocksServer(transport, "127.0.0.1", local_port)
            http_server = LocalHttpProxyServer(transport, "127.0.0.1", http_port)
            server.start()
            http_server.start()
            if full_traffic:
                try:
                    endpoint_ip = sock.getpeername()[0]
                except Exception as exc:
                    raise RuntimeError("Could not detect the IPv4 address of the connected SSH/proxy endpoint.") from exc
                tun_manager = FullTrafficManager(
                    APP_DIR / "full_traffic_routes.json",
                    log_callback=lambda message, level="info": self.messages.put({"kind": "log", "message": message, "level": level}),
                )
                tun_manager.start(local_port, endpoint_ip)
            if self.close_requested:
                if tun_manager:
                    tun_manager.stop()
                if http_server:
                    http_server.close()
                if server:
                    server.close()
                try:
                    client.close()
                except Exception:
                    pass
                return
            self.messages.put({"kind": "connected", "client": client, "server": server,
                               "http_server": http_server, "tun_manager": tun_manager,
                               "host": host, "port": port,
                               "local_port": local_port, "http_port": http_port,
                               "use_system_proxy": use_system_proxy})
        except Exception as exc:
            if tun_manager:
                try:
                    tun_manager.stop()
                except Exception:
                    pass
            if http_server:
                http_server.close()
            if server:
                server.close()
            if client:
                try:
                    client.close()
                except Exception:
                    pass
            elif sock:
                try:
                    sock.close()
                except OSError:
                    pass
            self.messages.put({"kind": "failed", "message": str(exc) or exc.__class__.__name__})

    def _process_messages(self):
        try:
            while True:
                item = self.messages.get_nowait()
                kind = item.get("kind")
                if kind == "log":
                    self.log(item["message"], item.get("level", "info"))
                elif kind == "host_key":
                    message = (
                        f"First time connecting to SSH host:\n\n{item['hostname']}\n"
                        f"Key type: {item['key_type']}\nFingerprint: {item['fingerprint']}\n\n"
                        "Only accept if this fingerprint matches a trusted value from your server administrator.\n\nTrust this key and save it?"
                    )
                    item["accepted"] = messagebox.askyesno("Verify SSH host key", message, parent=self.root)
                    item["event"].set()
                elif kind == "connected":
                    self.client = item["client"]
                    self.xray_process = item.get("xray_process")
                    self.xray_config_path = item.get("xray_config_path", self.xray_config_path)
                    self.socks_server = item["server"]
                    self.http_server = item["http_server"]
                    self.full_traffic_manager = item.get("tun_manager")
                    self.connecting = False
                    self.local_address.set(f"SOCKS5 127.0.0.1:{item['local_port']}  |  HTTP 127.0.0.1:{item['http_port']}")
                    self._set_status(True)
                    if item.get("engine") == "xray":
                        self.log(f"Xray {item.get('protocol', 'proxy')} engine started for {item['host']}:{item['port']}.", "ok")
                    else:
                        self.log(f"SSH connected to {item['host']}:{item['port']}.", "ok")
                    self.log(f"Local SOCKS5 listening on 127.0.0.1:{item['local_port']}.", "ok")
                    self.log(f"Local HTTP proxy listening on 127.0.0.1:{item['http_port']}.", "ok")
                    if self.full_traffic_manager:
                        self.log("Full Traffic mode is active (IPv4/TCP only).", "ok")
                    if item.get("use_system_proxy"):
                        try:
                            apply_windows_system_proxy(f"127.0.0.1:{item['http_port']}", APP_DIR / "system_proxy_backup.json")
                            self.system_proxy_active = True
                            self.log("Windows system proxy enabled; HTTP/HTTPS browser traffic should use ZainWolf Tunnel.", "ok")
                        except Exception as exc:
                            self.log(f"Could not change Windows system proxy: {exc}", "error")
                            self.log(f"Manual browser proxy: HTTP 127.0.0.1:{item['http_port']} (HTTPS uses CONNECT).", "info")
                    else:
                        self.log(f"System proxy is off. Set browser HTTP proxy to 127.0.0.1:{item['http_port']} or SOCKS5 to 127.0.0.1:{item['local_port']}.", "info")
                elif kind == "failed":
                    self.connecting = False
                    self._set_status(False, "●  CONNECTION FAILED")
                    self.log(f"Connection failed: {item['message']}", "error")
                    messagebox.showerror("Connection failed", item["message"], parent=self.root)
        except queue.Empty:
            pass
        if self.xray_process and self.xray_process.poll() is not None:
            self.log(f"Xray Core exited (code {self.xray_process.returncode}); stopping the profile.", "error")
            self.disconnect()
        if self.full_traffic_manager and not self.full_traffic_manager.is_running():
            self.log("tun2socks stopped unexpectedly; restoring routes and disconnecting.", "error")
            self.disconnect()
        if not self.close_requested:
            self.root.after(100, self._process_messages)

    def disconnect(self):
        had_connection = (self.client is not None or self.xray_process is not None or self.socks_server is not None
                          or self.http_server is not None or self.full_traffic_manager is not None)
        if self.full_traffic_manager:
            try:
                self.full_traffic_manager.stop()
                self.log("Full Traffic routes removed; the previous default route is active again.", "ok")
            except Exception as exc:
                self.log(f"Full Traffic cleanup reported an error: {exc}. Run restore_network_routes.bat as Administrator if internet stays offline.", "error")
            self.full_traffic_manager = None
        if self.system_proxy_active:
            try:
                restore_windows_system_proxy(APP_DIR / "system_proxy_backup.json")
                self.log("Previous Windows system proxy settings restored.", "info")
            except Exception as exc:
                self.log(f"Could not restore Windows proxy settings automatically: {exc}", "error")
            self.system_proxy_active = False
        if self.http_server:
            self.http_server.close()
            self.http_server = None
        if self.socks_server:
            self.socks_server.close()
            self.socks_server = None
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
        if self.xray_process:
            try:
                if self.xray_process.poll() is None:
                    self.xray_process.terminate()
                    try:
                        self.xray_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.xray_process.kill()
                self.log("Xray Core stopped.", "info")
            except Exception as exc:
                self.log(f"Could not stop Xray Core cleanly: {exc}", "error")
            self.xray_process = None
        if self.xray_config_path:
            try:
                Path(self.xray_config_path).unlink(missing_ok=True)
            except OSError:
                pass
            self.xray_config_path = None
        self.connecting = False
        self._set_status(False)
        if had_connection:
            self.log("Tunnel disconnected.", "info")

    def _save_settings(self):
        # Deliberately never persist the server field because it includes the SSH password.
        try:
            import json
            settings = {
                "proxy_mode": self.proxy_mode_var.get(),
                "proxy": self.proxy_var.get(),
                "local_port": self.local_port_var.get(),
                "http_port": self.http_port_var.get(),
                "use_system_proxy": self.use_system_proxy_var.get(),
                "full_traffic": self.full_traffic_var.get(),
                "payload": self.payload_text.get("1.0", "end-1c"),
            }
            APP_DIR.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        except Exception as exc:
            self.log(f"Settings could not be saved: {exc}", "error")

    def _load_settings(self):
        try:
            import json
            if not SETTINGS_FILE.exists():
                return
            settings = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            self.proxy_mode_var.set(settings.get("proxy_mode", "HTTP + Payload"))
            self.proxy_var.set(settings.get("proxy", ""))
            self.local_port_var.set(str(settings.get("local_port", "1080")))
            self.http_port_var.set(str(settings.get("http_port", "8081")))
            self.use_system_proxy_var.set(bool(settings.get("use_system_proxy", True)))
            saved_full_traffic = bool(settings.get("full_traffic", False))
            self.full_traffic_var.set(saved_full_traffic)
            self.payload_text.delete("1.0", "end")
            self.payload_text.insert("1.0", settings.get("payload", DEFAULT_PAYLOAD))
            self.local_address.set(f"SOCKS5 127.0.0.1:{self.local_port_var.get()}  |  HTTP 127.0.0.1:{self.http_port_var.get()}")
            self._proxy_mode_changed()
            if saved_full_traffic and (os.name != "nt" or not is_admin() or not helpers_available()):
                self.full_traffic_var.set(False)
                self.log(
                    "Saved Full Traffic preference was turned off because Windows/admin/helper requirements "
                    "are not met. Local SOCKS5/HTTP mode remains available.",
                    "error",
                )
                self._save_settings()
        except Exception:
            self.log("Could not load saved settings; defaults are available.", "error")

    def _missing_dependency(self):
        messagebox.showerror(
            "Missing dependency",
            "ZainWolf Tunnel needs Paramiko for SSH connections.\n\n"
            "Run run_noway_tunnel.bat; it installs the required Python package automatically.\n"
            "An internet connection is needed for first-time setup.",
            parent=self.root,
        )

    def on_close(self):
        self.close_requested = True
        self._save_settings()
        self.disconnect()
        self.root.destroy()


def main():
    root = tk.Tk()
    ZainWolfTunnelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
