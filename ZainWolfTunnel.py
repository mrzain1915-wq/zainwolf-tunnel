from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from pathlib import Path

from noway_core import (
    DEFAULT_PAYLOAD,
    format_failure_message,
    open_http_proxy_tunnel,
    open_socks5_proxy_tunnel,
    parse_host_port,
    parse_server_spec,
    probe_first_hop,
    safe_server_display,
)
from config_import import parse_import_text
from tunnel_profiles import (
    delete_profile as delete_stored_profile,
    load_profiles as load_stored_profiles,
    save_profile as save_stored_profile,
    strip_password_from_server_spec,
)
from xray_backend import find_xray_binary, resolve_endpoint_ipv4, write_runtime_config
from windows_proxy import apply_windows_system_proxy, restore_windows_system_proxy, recover_stale_windows_proxy
from windows_tun import FullTrafficManager, helpers_available, is_admin

try:
    import paramiko
except ImportError:
    paramiko = None

APP_NAME = "ZainWolf Tunnel"
APP_VERSION = "1.0.1"
APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "ZainWolfTunnel"
SETTINGS_FILE = APP_DIR / "settings.json"
PROFILES_FILE = APP_DIR / "profiles.json"
LOG_FILE = APP_DIR / "zainwolf.log"
KNOWN_HOSTS_FILE = APP_DIR / "known_hosts"

BG = "#0b1020"
SIDEBAR_BG = "#0d1526"
PANEL = "#131c2e"
PANEL_2 = "#172239"
BORDER = "#293650"
TEXT = "#edf2ff"
MUTED = "#98a7c4"
GREEN = "#40e0a0"
RED = "#ff647c"
BLUE = "#79a9ff"


def should_auto_reconnect(auto_enabled, manual_disconnect, close_requested, attempts, max_attempts=3):
    """Decide whether an automatic reconnect may be attempted after a drop."""
    return bool(auto_enabled) and not manual_disconnect and not close_requested and attempts < max_attempts


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
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.configure(bg=BG)
        self.root.geometry("1120x820")
        self.root.minsize(980, 760)
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
        self._manual_disconnect = False
        self._reconnect_attempts = 0
        self._auto_reconnecting = False
        self._last_profile = ""
        # Kept for import/use-ssh flows; the hero area shows the live detail.
        self.subtitle_var = tk.StringVar(value="SSH  •  PROXY  •  PAYLOAD  •  LOCAL SOCKS5")
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if not KNOWN_HOSTS_FILE.exists():
            KNOWN_HOSTS_FILE.write_text("", encoding="utf-8")
        # Session log state: in-memory lines plus a persistent file. Ready before
        # any log() call so the first "Ready" line is recorded in both places.
        self._log_lines = []
        self._log_lock = threading.Lock()
        self._write_log_session_header()
        self._configure_style()
        self._build_ui()
        self._load_settings()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._process_messages)
        if self.start_minimized_var.get():
            self.root.iconify()
        if paramiko is None:
            self.root.after(250, self._missing_dependency)

    def _write_log_session_header(self):
        try:
            with self._log_lock:
                with LOG_FILE.open("a", encoding="utf-8", errors="replace") as handle:
                    handle.write(f"\n--- {APP_NAME} {APP_VERSION} session started "
                                 f"{time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        except OSError:
            pass

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
        style.configure("Hero.TButton", background=GREEN, foreground="#07121a",
                        font=("Segoe UI Semibold", 13), borderwidth=0, padding=(26, 15))
        style.map("Hero.TButton", background=[("active", "#66edb5"), ("disabled", "#335b53")])
        style.configure("HeroSecondary.TButton", background="#25334c", foreground=TEXT,
                        font=("Segoe UI Semibold", 13), borderwidth=0, padding=(22, 15))
        style.map("HeroSecondary.TButton", background=[("active", "#334666"), ("disabled", "#1b263a")])

    def _panel(self, parent, title, subtitle=None):
        outer = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        header = tk.Frame(outer, bg=PANEL)
        header.pack(fill="x", padx=18, pady=(12, 6))
        ttk.Label(header, text=title, style="Heading.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(header, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(3, 0))
        body = tk.Frame(outer, bg=PANEL)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))
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

    # ------------------------------------------------------------------
    # Layout: left sidebar + pages (Connect / Profiles / Logs / Settings)
    # ------------------------------------------------------------------

    def _build_ui(self):
        self.root.columnconfigure(0, weight=0)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Left sidebar: brand, navigation, connection status.
        sidebar = tk.Frame(self.root, bg=SIDEBAR_BG, width=208)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=SIDEBAR_BG)
        brand.pack(fill="x", padx=18, pady=(20, 6))
        tk.Label(brand, text="ZAINWOLF", bg=SIDEBAR_BG, fg=TEXT,
                 font=("Segoe UI Semibold", 20)).pack(anchor="w")
        tk.Label(brand, text="TUNNEL", bg=SIDEBAR_BG, fg=GREEN,
                 font=("Segoe UI Semibold", 20)).pack(anchor="w")
        tk.Label(brand, text=f"Version {APP_VERSION}", bg=SIDEBAR_BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=18, pady=(10, 12))

        self.nav_buttons = {}
        for key, label in (("connect", "Connect"), ("profiles", "Profiles"),
                           ("logs", "Logs"), ("settings", "Settings")):
            button = tk.Button(sidebar, text=label, font=("Segoe UI Semibold", 11),
                               bg=SIDEBAR_BG, fg=TEXT, activebackground=PANEL_2,
                               activeforeground=TEXT, relief="flat", anchor="w",
                               padx=18, pady=11, borderwidth=0, highlightthickness=0,
                               command=lambda k=key: self._show_page(k))
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = button

        tk.Frame(sidebar, bg=SIDEBAR_BG).pack(fill="both", expand=True)
        self.status_dot = tk.Label(sidebar, text="●  DISCONNECTED", bg=SIDEBAR_BG, fg=MUTED,
                                   font=("Segoe UI Semibold", 10), anchor="w")
        self.status_dot.pack(fill="x", padx=18, pady=(4, 18))

        # Main content area: one page visible at a time, status bar at bottom.
        content = tk.Frame(self.root, bg=BG)
        content.grid(row=0, column=1, sticky="nsew")
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=1)

        self.pages = {}
        self._build_connect_page(content)
        self._build_profiles_page(content)
        self._build_logs_page(content)
        self._build_settings_page(content)

        self.status_bar_var = tk.StringVar(value="Disconnected")
        self.status_bar_right_var = tk.StringVar(value="")
        statusbar = tk.Frame(content, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        statusbar.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 12))
        tk.Label(statusbar, textvariable=self.status_bar_var, bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="left", padx=12, pady=7)
        tk.Label(statusbar, textvariable=self.status_bar_right_var, bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9)).pack(side="right", padx=12, pady=7)

        self._show_page("connect")
        self.log("Ready. Enter your SSH account details to begin.", "info")

    def _show_page(self, key):
        for name, frame in self.pages.items():
            if name == key:
                frame.grid()
            else:
                frame.grid_remove()
        for name, button in self.nav_buttons.items():
            if name == key:
                button.configure(bg="#22345a", fg=GREEN)
            else:
                button.configure(bg=SIDEBAR_BG, fg=TEXT)
        if key == "logs":
            self._refresh_logs_page()

    def _refresh_logs_page(self):
        widget = getattr(self, "logs_page_text", None)
        if widget is None:
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for line, level in self._log_lines:
            widget.insert("end", line + "\n", level)
        widget.see("end")
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # Connect page: hero connect area + cards + compact log strip
    # ------------------------------------------------------------------

    def _build_connect_page(self, content):
        page = tk.Frame(content, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.columnconfigure(0, weight=6, uniform="main")
        page.columnconfigure(1, weight=4, uniform="main")
        page.rowconfigure(1, weight=1)
        page.rowconfigure(2, weight=1)
        self.pages["connect"] = page

        # Hero card: at-a-glance status + large connect control.
        hero = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        hero.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(18, 12))
        hero.columnconfigure(0, weight=1)
        hero_text = tk.Frame(hero, bg=PANEL)
        hero_text.grid(row=0, column=0, sticky="w", padx=20, pady=16)
        self.hero_status_var = tk.StringVar(value="Disconnected")
        self.hero_status_label = tk.Label(hero_text, textvariable=self.hero_status_var,
                                          bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 26))
        self.hero_status_label.pack(anchor="w")
        self.hero_detail_var = tk.StringVar(value="No server configured")
        tk.Label(hero_text, textvariable=self.hero_detail_var, bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))
        hero_buttons = tk.Frame(hero, bg=PANEL)
        hero_buttons.grid(row=0, column=1, sticky="e", padx=20, pady=16)
        self.connect_button = ttk.Button(hero_buttons, text="CONNECT", style="Hero.TButton",
                                         command=self.connect)
        self.connect_button.pack(side="left", padx=(0, 8))
        self.disconnect_button = ttk.Button(hero_buttons, text="DISCONNECT",
                                            style="HeroSecondary.TButton",
                                            command=self.disconnect_user, state="disabled")
        self.disconnect_button.pack(side="left")

        # Server card.
        self.server_var = tk.StringVar()
        p, pb = self._panel(page, "SSH SERVER", "Format: host:port@username:password")
        p.grid(row=1, column=0, sticky="nsew", padx=(18, 6), pady=(0, 12))
        wrap, _ = self._field(pb, "Server / login", self.server_var,
                              "ssh.example.com:443@user:password", show="")
        wrap.pack(fill="x")
        import_buttons = tk.Frame(pb, bg=PANEL)
        import_buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(import_buttons, text="Import Link / JSON…", style="Secondary.TButton",
                   command=self.import_config).pack(side="left")
        ttk.Button(import_buttons, text="Use SSH fields", style="Secondary.TButton",
                   command=self.use_ssh_profile).pack(side="left", padx=(7, 0))
        tk.Label(pb, text="SSH passwords are not saved in settings. Imported Xray profiles use the Xray Core engine.", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8), wraplength=510, justify="left").pack(anchor="w", pady=(7, 0))

        # Upstream proxy card.
        self.proxy_mode_var = tk.StringVar(value="HTTP + Payload")
        self.proxy_var = tk.StringVar()
        p, pb = self._panel(page, "UPSTREAM PROXY", "Direct SSH, HTTP payload proxy, or SOCKS5")
        p.grid(row=1, column=1, sticky="nsew", padx=(6, 18), pady=(0, 12))
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

        # Payload card.
        p, pb = self._panel(page, "PAYLOAD", "Tokens are substituted before the SSH handshake")
        p.grid(row=2, column=0, sticky="nsew", padx=(18, 6), pady=(0, 12))
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

        # Local tunnel & controls card.
        p, pb = self._panel(page, "LOCAL TUNNEL & CONTROLS", None)
        p.grid(row=2, column=1, sticky="nsew", padx=(6, 18), pady=(0, 12))
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
        self.copy_button = ttk.Button(pb, text="Copy proxy addresses", style="Secondary.TButton", command=self.copy_address)
        self.copy_button.pack(fill="x")
        tk.Label(pb, text="Full Traffic routes IPv4/TCP via Wintun. DNS uses the underlying resolver; UDP and IPv6 are not tunneled by this SSH relay.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=350,
                 justify="left").pack(anchor="w", pady=(5, 0))

        # Compact log strip.
        logs_outer = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        logs_outer.grid(row=3, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 12))
        log_head = tk.Frame(logs_outer, bg=PANEL)
        log_head.pack(fill="x", padx=16, pady=(8, 4))
        tk.Label(log_head, text="CONNECTION LOG", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(side="left")
        tk.Label(log_head, text="  ·  passwords are not logged", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="left", padx=(5, 0))
        ttk.Button(log_head, text="View Log →", style="Secondary.TButton",
                   command=lambda: self._show_page("logs")).pack(side="right", padx=(0, 6))
        ttk.Button(log_head, text="Clear", style="Secondary.TButton", command=self.clear_logs).pack(side="right")
        self.log_text = tk.Text(logs_outer, height=3, wrap="word", bg="#080e1a", fg="#b7c6e2",
                                insertbackground=TEXT, relief="flat", state="disabled",
                                font=("Consolas", 9), padx=10, pady=6)
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 9))
        self.log_text.tag_configure("ok", foreground=GREEN)
        self.log_text.tag_configure("error", foreground=RED)
        self.log_text.tag_configure("info", foreground=BLUE)

    # ------------------------------------------------------------------
    # Profiles page
    # ------------------------------------------------------------------

    def _build_profiles_page(self, content):
        page = tk.Frame(content, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.columnconfigure(0, weight=1)
        self.pages["profiles"] = page

        p, pb = self._panel(page, "CONNECTION PROFILES",
                            "Save the current settings under a name, then load them in one click. Passwords are never stored.")
        p.grid(row=0, column=0, sticky="nsew", padx=18, pady=(18, 12))

        row = tk.Frame(pb, bg=PANEL)
        row.pack(fill="x")
        tk.Label(row, text="Profile", bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 9)).pack(side="left", padx=(0, 8))
        self.profile_var = tk.StringVar()
        self.profile_box = ttk.Combobox(row, textvariable=self.profile_var, values=[])
        self.profile_box.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Save", style="Secondary.TButton", command=self.save_profile).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Delete", style="Secondary.TButton", command=self.delete_profile).pack(side="left", padx=(6, 0))
        self.profile_box.bind("<<ComboboxSelected>>", self._profile_selected)

        tk.Label(pb, text="Type a new name and click Save to create a profile. Select a saved profile to load it.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(8, 0))

        tk.Label(pb, text="Saved profiles", bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 9)).pack(anchor="w", pady=(14, 5))
        self.profile_listbox = tk.Listbox(pb, height=10, bg="#0c1425", fg=TEXT, relief="flat",
                                          highlightthickness=1, highlightbackground=BORDER,
                                          selectbackground="#22345a", font=("Segoe UI", 10))
        self.profile_listbox.pack(fill="both", expand=True)
        self.profile_listbox.bind("<<ListboxSelect>>", self._profile_list_selected)
        self.profile_listbox.bind("<Double-Button-1>", self._profile_selected)

        tk.Label(pb, text="A profile stores the server (without password), proxy mode, proxy host:port, payload, local ports, system-proxy choice and Full Traffic choice.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=640, justify="left").pack(anchor="w", pady=(10, 0))
        self._refresh_profile_lists()

    def _refresh_profile_lists(self):
        profiles = load_stored_profiles(PROFILES_FILE)
        names = sorted(profiles)
        self.profile_box["values"] = names
        self.profile_listbox.delete(0, "end")
        for name in names:
            self.profile_listbox.insert("end", name)

    def _current_profile_data(self):
        return {
            "server": strip_password_from_server_spec(self.server_var.get()),
            "proxy_mode": self.proxy_mode_var.get(),
            "proxy": self.proxy_var.get(),
            "payload": self.payload_text.get("1.0", "end-1c"),
            "local_port": self.local_port_var.get(),
            "http_port": self.http_port_var.get(),
            "use_system_proxy": self.use_system_proxy_var.get(),
            "full_traffic": self.full_traffic_var.get(),
        }

    def _apply_profile_data(self, data):
        self.active_proxy_profile = None
        self.subtitle_var.set("SSH  •  PROXY  •  PAYLOAD  •  LOCAL SOCKS5")
        server = (data.get("server") or "").strip()
        # Stored without password; the trailing colon shows where to type it.
        self.server_var.set(f"{server}:" if server else "")
        self.proxy_mode_var.set(data.get("proxy_mode") or "HTTP + Payload")
        self.proxy_var.set(data.get("proxy") or "")
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", data.get("payload") or DEFAULT_PAYLOAD)
        self.local_port_var.set(str(data.get("local_port") or "1080"))
        self.http_port_var.set(str(data.get("http_port") or "8081"))
        self.use_system_proxy_var.set(bool(data.get("use_system_proxy", True)))
        self.full_traffic_var.set(bool(data.get("full_traffic", False)))
        self._proxy_mode_changed()
        self.local_address.set(f"SOCKS5 127.0.0.1:{self.local_port_var.get()}  |  HTTP 127.0.0.1:{self.http_port_var.get()}")
        self._update_hero()

    def _load_profile_by_name(self, name):
        profiles = load_stored_profiles(PROFILES_FILE)
        data = profiles.get(name)
        if data is None:
            return
        self._apply_profile_data(data)
        self._set_last_profile(name)
        self.log(f"Profile '{name}' loaded. Enter the SSH password, then CONNECT.", "ok")

    def _profile_selected(self, _event=None):
        name = self.profile_var.get().strip()
        if name:
            self._load_profile_by_name(name)

    def _profile_list_selected(self, _event=None):
        selection = self.profile_listbox.curselection()
        if not selection:
            return
        name = self.profile_listbox.get(selection[0])
        self.profile_var.set(name)
        self._load_profile_by_name(name)

    def save_profile(self):
        name = self.profile_var.get().strip()
        if not name:
            messagebox.showerror("Save profile", "Type a profile name first.", parent=self.root)
            return
        save_stored_profile(PROFILES_FILE, name, self._current_profile_data())
        self._refresh_profile_lists()
        self._set_last_profile(name)
        self.log(f"Profile '{name}' saved (password not stored).", "ok")

    def delete_profile(self):
        name = self.profile_var.get().strip()
        if not name:
            messagebox.showerror("Delete profile", "Select a profile to delete.", parent=self.root)
            return
        profiles = load_stored_profiles(PROFILES_FILE)
        if name not in profiles:
            messagebox.showinfo("Delete profile", f"No saved profile named '{name}'.", parent=self.root)
            return
        if not messagebox.askyesno("Delete profile", f"Delete profile '{name}'?", parent=self.root):
            return
        delete_stored_profile(PROFILES_FILE, name)
        self.profile_var.set("")
        self._refresh_profile_lists()
        if getattr(self, "_last_profile", "") == name:
            self._set_last_profile("")
        self.log(f"Profile '{name}' deleted.", "info")

    def _set_last_profile(self, name):
        self._last_profile = name
        self._save_settings()

    # ------------------------------------------------------------------
    # Logs page: full session log viewer
    # ------------------------------------------------------------------

    def _build_logs_page(self, content):
        page = tk.Frame(content, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.columnconfigure(0, weight=1)
        page.rowconfigure(1, weight=1)
        self.pages["logs"] = page

        header = tk.Frame(page, bg=BG)
        header.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 8))
        tk.Label(header, text="Session Log", bg=BG, fg=TEXT,
                 font=("Segoe UI Semibold", 14)).pack(side="left")
        ttk.Button(header, text="Save to File…", style="Secondary.TButton",
                   command=self.save_log_to_file).pack(side="right")
        ttk.Button(header, text="Copy All", style="Secondary.TButton",
                   command=self.copy_log).pack(side="right", padx=(0, 6))
        ttk.Button(header, text="Clear", style="Secondary.TButton",
                   command=self.clear_logs).pack(side="right", padx=(0, 6))

        logs_frame = tk.Frame(page, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        logs_frame.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 8))
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)
        self.logs_page_text = tk.Text(logs_frame, wrap="word", bg="#080e1a", fg="#b7c6e2",
                                      insertbackground=TEXT, relief="flat", state="disabled",
                                      font=("Consolas", 9), padx=10, pady=8)
        self.logs_page_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(logs_frame, orient="vertical", command=self.logs_page_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.logs_page_text.configure(yscrollcommand=scrollbar.set)
        self.logs_page_text.tag_configure("ok", foreground=GREEN)
        self.logs_page_text.tag_configure("error", foreground=RED)
        self.logs_page_text.tag_configure("info", foreground=BLUE)

        tk.Label(page, text=f"Log file: {LOG_FILE}", bg=BG, fg=MUTED,
                 font=("Segoe UI", 9)).grid(row=2, column=0, sticky="w", padx=18, pady=(0, 12))

    def copy_log(self):
        text = "\n".join(line for line, _level in self._log_lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log("Log copied to clipboard.", "ok")

    def save_log_to_file(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save log", defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="zainwolf.log",
        )
        if not path:
            return
        try:
            Path(path).write_text("\n".join(line for line, _level in self._log_lines) + "\n", encoding="utf-8")
            self.log(f"Log saved to {path}.", "ok")
        except OSError as exc:
            messagebox.showerror("Save log", f"Could not save the log: {exc}", parent=self.root)

    # ------------------------------------------------------------------
    # Settings page: only real, working options
    # ------------------------------------------------------------------

    def _build_settings_page(self, content):
        page = tk.Frame(content, bg=BG)
        page.grid(row=0, column=0, sticky="nsew")
        page.columnconfigure(0, weight=1)
        self.pages["settings"] = page

        self.auto_reconnect_var = tk.BooleanVar(value=False)
        self.remember_last_profile_var = tk.BooleanVar(value=True)
        self.clear_log_on_exit_var = tk.BooleanVar(value=False)
        self.start_minimized_var = tk.BooleanVar(value=False)

        p, pb = self._panel(page, "CONNECTION", "Reconnect and profile behaviour")
        p.grid(row=0, column=0, sticky="ew", padx=18, pady=(18, 12))
        self._settings_check(pb, "Auto-reconnect on drop",
                             "If the tunnel drops unexpectedly, try reconnecting automatically (up to 3 attempts, 5 seconds apart).",
                             self.auto_reconnect_var)
        self._settings_check(pb, "Remember last profile",
                             "Load the last used profile automatically when the app starts.",
                             self.remember_last_profile_var)

        p, pb = self._panel(page, "LOGS", "What happens to the session log")
        p.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 12))
        self._settings_check(pb, "Clear log on exit",
                             "Delete the saved log file when the app closes.",
                             self.clear_log_on_exit_var)

        p, pb = self._panel(page, "STARTUP", "How the app starts")
        p.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 12))
        self._settings_check(pb, "Start minimized",
                             "Open the app minimized to the taskbar.",
                             self.start_minimized_var)

        p, pb = self._panel(page, "ABOUT", None)
        p.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 12))
        tk.Label(pb, text=f"{APP_NAME}  •  Version {APP_VERSION}", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w")
        tk.Label(pb, text=f"Settings: {SETTINGS_FILE}\nProfiles: {PROFILES_FILE}\nLog: {LOG_FILE}",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9), justify="left").pack(anchor="w", pady=(6, 0))
        tk.Label(pb, text="Full Traffic routes IPv4/TCP via Wintun. DNS uses the underlying resolver; UDP and IPv6 are not tunneled by this SSH relay.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=640, justify="left").pack(anchor="w", pady=(8, 0))

    def _settings_check(self, parent, title, description, variable):
        wrap = tk.Frame(parent, bg=PANEL)
        wrap.pack(fill="x", pady=(2, 8))
        tk.Checkbutton(wrap, text=title, variable=variable, bg=PANEL, fg=TEXT, selectcolor=BG,
                       activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI Semibold", 10),
                       anchor="w", command=self._save_settings).pack(anchor="w")
        tk.Label(wrap, text=description, bg=PANEL, fg=MUTED, font=("Segoe UI", 9),
                 wraplength=640, justify="left").pack(anchor="w", padx=(24, 0))

    # ------------------------------------------------------------------
    # Hero status + logging
    # ------------------------------------------------------------------

    def _hero_detail(self):
        """One-line summary for the hero area; never includes a password."""
        if self.active_proxy_profile is not None:
            protocol = str(self.active_proxy_profile.get("protocol", "proxy")).upper()
            host = self.active_proxy_profile.get("host") or ""
            port = self.active_proxy_profile.get("port") or ""
            return f"{protocol} profile  •  {host}:{port}" if host else f"{protocol} profile"
        server = safe_server_display(self.server_var.get())
        if server:
            return f"SSH server {server}  •  {self.proxy_mode_var.get()}"
        return f"No server configured  •  {self.proxy_mode_var.get()}"

    def _update_hero(self):
        if getattr(self, "hero_detail_var", None) is not None:
            self.hero_detail_var.set(self._hero_detail())

    def _proxy_mode_changed(self, _event=None):
        mode = self.proxy_mode_var.get()
        state = "disabled" if mode == "Direct SSH" else "normal"
        self.proxy_entry.configure(state=state)
        self.log(f"Proxy mode set to {mode}.", "info")
        self._update_hero()

    def log(self, message, level="info"):
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        self._log_lines.append((line, level))
        try:
            with self._log_lock:
                with LOG_FILE.open("a", encoding="utf-8", errors="replace") as handle:
                    handle.write(line + "\n")
        except OSError:
            pass
        for widget in (getattr(self, "log_text", None), getattr(self, "logs_page_text", None)):
            if widget is None:
                continue
            try:
                widget.configure(state="normal")
                widget.insert("end", line + "\n", level)
                widget.see("end")
                widget.configure(state="disabled")
            except tk.TclError:
                pass

    def clear_logs(self):
        self._log_lines.clear()
        for widget in (getattr(self, "log_text", None), getattr(self, "logs_page_text", None)):
            if widget is None:
                continue
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")
        self.log("Log view cleared. (The saved log file was kept.)", "info")

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
        self._update_hero()

    def reset_payload(self):
        self.payload_text.delete("1.0", "end")
        self.payload_text.insert("1.0", DEFAULT_PAYLOAD)

    def copy_address(self):
        address = (f"SOCKS5 127.0.0.1:{self.local_port_var.get().strip()}\n"
                   f"HTTP 127.0.0.1:{self.http_port_var.get().strip()}")
        self.root.clipboard_clear()
        self.root.clipboard_append(address)
        self.log("Copied local SOCKS5 and HTTP proxy addresses.", "ok")

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
                    self._update_hero()
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
                    self._update_hero()
                    return
                if kind == "server_json":
                    messagebox.showinfo("Server-side JSON detected", "This JSON contains inbound/server configuration only. It does not provide a client outbound. Paste a VLESS/VMess/Trojan link or Xray/V2Ray JSON containing a supported outbound.", parent=dialog)
                    return
            except Exception as exc:
                messagebox.showerror("Import failed", str(exc), parent=dialog)

        ttk.Button(btnrow, text="Import / Detect", style="Green.TButton", command=do_import).pack(side="right")
        ttk.Button(btnrow, text="Cancel", style="Secondary.TButton", command=dialog.destroy).pack(side="right", padx=(0, 8))
        editor.focus_set()

    def _set_status(self, connected, text=None):
        if connected:
            self.hero_status_var.set("Connected")
            self.hero_status_label.configure(fg=GREEN)
            self.status_dot.configure(text="●  CONNECTED", fg=GREEN)
            self.status_bar_var.set(f"Connected — SOCKS5 127.0.0.1:{self.local_port_var.get()}  |  HTTP 127.0.0.1:{self.http_port_var.get()}")
            self.status_bar_right_var.set(self._hero_detail())
            self.connect_button.configure(state="disabled")
            self.disconnect_button.configure(state="normal")
        elif self.connecting:
            self.hero_status_var.set("Connecting…")
            self.hero_status_label.configure(fg=BLUE)
            self.status_dot.configure(text="●  CONNECTING", fg=BLUE)
            self.status_bar_var.set("Connecting…")
            self.status_bar_right_var.set("")
            self.connect_button.configure(state="disabled")
            self.disconnect_button.configure(state="disabled")
        else:
            failed = bool(text and "FAILED" in text)
            self.hero_status_var.set("Connection failed" if failed else "Disconnected")
            self.hero_status_label.configure(fg=RED if failed else MUTED)
            self.status_dot.configure(text=text or "●  DISCONNECTED", fg=RED if failed else MUTED)
            self.status_bar_var.set("Connection failed" if failed else "Disconnected")
            self.status_bar_right_var.set("")
            self.connect_button.configure(state="normal")
            self.disconnect_button.configure(state="disabled")
        self._update_hero()

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
            # Fail fast when the Xray endpoint itself cannot be reached.
            self.messages.put({"kind": "log", "message": f"Checking that {host}:{port} is reachable (Xray {protocol})…", "level": "info"})
            reachable, probe_detail = probe_first_hop(host, port, timeout=5.0)
            if not reachable:
                self.messages.put({"kind": "log", "message": probe_detail, "level": "error"})
                raise RuntimeError(probe_detail)
            self.messages.put({"kind": "log", "message": probe_detail, "level": "ok"})
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
                try:
                    tun_manager.start(local_port, endpoint_ip)
                except Exception as exc:
                    raise RuntimeError(f"Full Traffic could not start: {exc}") from exc
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
            self.messages.put({"kind": "failed", "message": format_failure_message(exc, host, port, f"Xray {protocol}")})

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
            # Fail fast: validate the first hop before any SSH work.
            if mode == "Direct SSH":
                first_host, first_port = host, port
            else:
                first_host, first_port = proxy_host, proxy_port
            self.messages.put({"kind": "log", "message": f"Checking that {first_host}:{first_port} is reachable ({mode})…", "level": "info"})
            reachable, probe_detail = probe_first_hop(first_host, first_port, timeout=5.0)
            if not reachable:
                self.messages.put({"kind": "log", "message": probe_detail, "level": "error"})
                raise RuntimeError(probe_detail)
            self.messages.put({"kind": "log", "message": probe_detail, "level": "ok"})

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
            # Verify the local listeners actually accept connections before
            # reporting success — a "connected" tunnel with dead local ports
            # looks like "connected but no internet".
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if self._tcp_listener_ready(local_port) and self._tcp_listener_ready(http_port):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(
                    f"Local SOCKS5/HTTP listeners did not start on 127.0.0.1:{local_port}/{http_port}. "
                    "Another program may already be using these ports — choose different local ports."
                )
            if full_traffic:
                try:
                    endpoint_ip = sock.getpeername()[0]
                except Exception as exc:
                    raise RuntimeError("Could not detect the IPv4 address of the connected SSH/proxy endpoint.") from exc
                tun_manager = FullTrafficManager(
                    APP_DIR / "full_traffic_routes.json",
                    log_callback=lambda message, level="info": self.messages.put({"kind": "log", "message": message, "level": level}),
                )
                try:
                    tun_manager.start(local_port, endpoint_ip)
                except Exception as exc:
                    raise RuntimeError(f"Full Traffic could not start: {exc}") from exc
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
            self.messages.put({"kind": "failed", "message": format_failure_message(exc, host, port, mode)})

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
                    self._reconnect_attempts = 0
                    self._manual_disconnect = False
                    self._auto_reconnecting = False
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
                    self.last_error = item["message"]
                    was_auto = self._auto_reconnecting
                    self._auto_reconnecting = False
                    self._set_status(False, "●  CONNECTION FAILED")
                    short = item["message"].split("\n")[0][:140]
                    self.status_bar_var.set(f"Connection failed — {short}")
                    self.log(f"Connection failed: {item['message']}", "error")
                    if was_auto and should_auto_reconnect(
                            self.auto_reconnect_var.get(), self._manual_disconnect,
                            self.close_requested, self._reconnect_attempts):
                        self._reconnect_attempts += 1
                        self.log(f"Reconnect attempt {self._reconnect_attempts} failed; retrying in 5 seconds…", "error")
                        self.root.after(5000, self._attempt_reconnect)
                    else:
                        messagebox.showerror("Connection failed", item["message"], parent=self.root)
        except queue.Empty:
            pass
        if self.xray_process and self.xray_process.poll() is not None:
            self.log(f"Xray Core exited (code {self.xray_process.returncode}); stopping the profile.", "error")
            self.disconnect()
            self._maybe_auto_reconnect()
        if self.full_traffic_manager and not self.full_traffic_manager.is_running():
            self.log("tun2socks stopped unexpectedly; restoring routes and disconnecting.", "error")
            self.disconnect()
            self._maybe_auto_reconnect()
        if not self.close_requested:
            self.root.after(100, self._process_messages)

    def _maybe_auto_reconnect(self):
        """After an unexpected drop, schedule a reconnect when the setting is on."""
        if not should_auto_reconnect(self.auto_reconnect_var.get(), self._manual_disconnect,
                                     self.close_requested, self._reconnect_attempts):
            return
        self._reconnect_attempts += 1
        self.log(f"Connection dropped. Reconnecting in 5 seconds (attempt {self._reconnect_attempts}/3)…", "error")
        self.root.after(5000, self._attempt_reconnect)

    def _attempt_reconnect(self):
        if not should_auto_reconnect(self.auto_reconnect_var.get(), self._manual_disconnect,
                                     self.close_requested, self._reconnect_attempts):
            self.log("Auto-reconnect stopped.", "info")
            return
        if self.connecting or self.client or self.xray_process:
            return
        self._auto_reconnecting = True
        self.log(f"Auto-reconnect attempt {self._reconnect_attempts}/3…", "info")
        self.connect()

    def disconnect_user(self):
        """Manual disconnect from the hero button: never auto-reconnect after it."""
        self._manual_disconnect = True
        self._reconnect_attempts = 0
        self.disconnect()

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
            settings = {
                "proxy_mode": self.proxy_mode_var.get(),
                "proxy": self.proxy_var.get(),
                "local_port": self.local_port_var.get(),
                "http_port": self.http_port_var.get(),
                "use_system_proxy": self.use_system_proxy_var.get(),
                "full_traffic": self.full_traffic_var.get(),
                "payload": self.payload_text.get("1.0", "end-1c"),
                "auto_reconnect": self.auto_reconnect_var.get(),
                "remember_last_profile": self.remember_last_profile_var.get(),
                "clear_log_on_exit": self.clear_log_on_exit_var.get(),
                "start_minimized": self.start_minimized_var.get(),
                "last_profile": getattr(self, "_last_profile", ""),
            }
            APP_DIR.mkdir(parents=True, exist_ok=True)
            SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        except Exception as exc:
            self.log(f"Settings could not be saved: {exc}", "error")

    def _load_settings(self):
        try:
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
            self.auto_reconnect_var.set(bool(settings.get("auto_reconnect", False)))
            self.remember_last_profile_var.set(bool(settings.get("remember_last_profile", True)))
            self.clear_log_on_exit_var.set(bool(settings.get("clear_log_on_exit", False)))
            self.start_minimized_var.set(bool(settings.get("start_minimized", False)))
            self._last_profile = str(settings.get("last_profile") or "")
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
            if self.remember_last_profile_var.get() and self._last_profile:
                profiles = load_stored_profiles(PROFILES_FILE)
                if self._last_profile in profiles:
                    self.profile_var.set(self._last_profile)
                    self._apply_profile_data(profiles[self._last_profile])
                    self.log(f"Loaded last used profile '{self._last_profile}'.", "info")
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
        if self.clear_log_on_exit_var.get():
            try:
                LOG_FILE.unlink(missing_ok=True)
            except OSError:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    ZainWolfTunnelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
