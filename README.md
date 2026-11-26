# ZainWolf Tunnel — Windows 10/11

ZainWolf Tunnel is a dark-themed SSH tunnelling prototype. It supports:

- **Direct SSH** — connect directly to the SSH endpoint.
- **HTTP + Payload** — connect to an upstream HTTP proxy, send a configurable payload, then negotiate SSH through the accepted connection.
- **SOCKS5 upstream** — establish SSH through an upstream SOCKS5 proxy that allows no-auth connections.
- **Local application proxies** — a local SOCKS5 endpoint (default `127.0.0.1:1080`) and HTTP proxy (default `127.0.0.1:8081`) that forward TCP streams through SSH.
- **SSH link import** — paste `ssh://username:password@host:port`, `ssh://username@host:port`, or the legacy `host:port@username:password` format to auto-fill SSH fields.
- **Xray/V2Ray profiles** — import VLESS, VMess, and Trojan share links or client JSON outbound profiles. The importer extracts server, port, UUID/password, transport (including WebSocket), TLS/Reality parameters, SNI, Host, path, fingerprint and flow where available. Connections use the official Xray Core runtime; import parsing works without Xray installed, but connecting a proxy profile requires `xray.exe`.
- **Optional Windows Full Traffic (IPv4/TCP)** — uses the official `tun2socks` helper and Wintun virtual adapter to capture regular IPv4 TCP flows from apps that do not use the Windows system proxy.

The local SOCKS5 server forwards TCP destinations using SSH `direct-tcpip` channels. The desktop app uses a worker relay that monitors native client sockets with `select()` and polls Paramiko channels with `recv_ready()`, rather than passing Paramiko's pipe-backed descriptor to Windows `select()`.

## Important Full Traffic limitations

Full Traffic is opt-in and disabled by default. It needs Windows 10/11 x64, Administrator privileges, `tun2socks.exe`, and the signed `wintun.dll`. If an old saved setting has Full Traffic enabled while the administrator/helper requirements are not met, the app now switches that preference off and continues in local SOCKS5/HTTP proxy mode instead of blocking an SSH or Xray connection. If Full Traffic is manually selected without its prerequisites, a warning is shown and the connection continues in local-proxy-only mode; Full Traffic itself remains unavailable until the helpers are installed and the EXE is rebuilt. This source-integrated package includes the official Wintun 0.14.1 AMD64 `wintun.dll` in `tools` and the `tun2socks` v2.7.0 source tree in `third_party/tun2socks-2.7.0`. The uploaded tun2socks archive did **not** contain a prebuilt `.exe`, so `BUILD_TUN2SOCKS_FROM_SOURCE.bat` compiles it locally using Go 1.26.3+ and the included source. This avoids downloading the GitHub release asset, though Go may still need dependencies from a Go module proxy on first build. The build script tries `goproxy.io`, then `proxy.golang.org`, then direct source access; it retries module download up to three times and keeps Go checksum verification enabled. `INSTALL_FULL_TRAFFIC_HELPERS.bat` invokes that source build and confirms both helper files. If you only need standard local-proxy mode, no Go toolchain is needed.

The SSH SOCKS5 relay is TCP-only. In Full Traffic mode, regular IPv4 TCP is routed through SSH; current DNS resolver addresses are given explicit routes via the underlying network so DNS continues to work, which means DNS queries are **not inside the SSH tunnel**. UDP applications and IPv6 are **not tunneled** by this build. Apps using QUIC, games, UDP, or IPv6 can fail or bypass the SSH path. Do not treat this as a privacy leak-proof VPN.

A default-route exception is installed for the SSH/proxy endpoint to prevent the tunnel from routing its own transport back into itself. Disconnect removes temporary routes. If Windows loses internet after a crash or forced shutdown, run `restore_network_routes.bat`; it requests elevation and removes the saved ZainWolf Tunnel routes. The active route list is also temporary and disappears on a Windows reboot.

The Windows TUN approach uses separate components (a virtual adapter, routing, and a SOCKS-facing `tun2socks` engine), not just a CONNECTED status or local proxy. See the upstream Windows example: https://github.com/xjasonlyu/tun2socks/wiki/Examples and Wintun overview: https://www.wintun.net/.

## Start on Windows

1. Install Python 3.10+ from https://www.python.org/downloads/windows/ if needed; enable the Python Launcher.
2. Extract the bundle to a normal writable folder.
3. For the standard local-proxy mode, double-click `run_noway_tunnel.bat`.
4. Enter SSH details in this format: `host:port@username:password`, e.g. `ssh.example.net:443@myuser:mypassword`, or click **Import Link / JSON…**.
5. Supported SSH import examples: `ssh://myuser:mypassword@ssh.example.net:22` and `ssh://myuser@ssh.example.net:22` (the latter prompts for the password). The legacy `ssh://host:port@username:password` form is also accepted.
6. Select `Direct SSH`, `HTTP + Payload`, or `SOCKS5`; for proxy modes, enter `proxyhost:port`.
7. Press **CONNECT**. On first use, verify the SSH host-key fingerprint against a trusted value before accepting it.
8. Keep **Route Windows proxy-aware apps** checked for browsers/apps honoring the Windows system proxy. On disconnect, the previous per-user proxy settings are restored.

### VLESS/VMess/Trojan links and JSON profiles

The importer supports share links such as `vless://UUID@host:443?type=ws&security=tls&host=example.com&path=%2F...`, `vmess://BASE64_JSON`, and `trojan://password@host:443?...`. For Xray/V2Ray client JSON, the app selects a supported `outbounds` entry and preserves that outbound's protocol and stream settings. A JSON file that contains only `inbounds` is usually server-side configuration; it does not tell a client how to connect to an outbound server.

To connect an imported VLESS/VMess/Trojan profile, install the official Xray Core Windows AMD64 runtime:

1. Run `INSTALL_XRAY_CORE.bat` to open the official [XTLS/Xray-core releases page](https://github.com/XTLS/Xray-core/releases/latest).
2. Download the official Windows 64-bit archive named `Xray-windows-64.zip` and save it beside the batch file.
3. Run `INSTALL_XRAY_CORE.bat` again. It extracts `xray.exe` to `tools\xray.exe`.
4. Rebuild `ZainWolfTunnel.exe` to bundle Xray Core, or copy the executable to `%APPDATA%\ZainWolfTunnel\tools\xray.exe` to let an existing EXE find it at runtime.
5. Paste/import the proxy link or JSON, then click Connect. Local listeners are `127.0.0.1:1080` (SOCKS5) and `127.0.0.1:8081` (HTTP) by default. The SSH payload settings do not apply to Xray profiles.

The runtime profile is written temporarily to `%APPDATA%\ZainWolfTunnel\active_xray_config.json` while connected and is deleted on Disconnect. Do not share imported links or JSON because they can contain valid credentials. Use only official Xray Core releases; this project does not bundle Xray Core itself.

## Build the EXE on Windows

1. Extract the whole project bundle.
2. Double-click `build_windows_exe.bat`. It installs Python build requirements, runs local tests, and creates `dist\ZainWolfTunnel.exe`. It does not require GitHub/Wintun downloads for a standard build. If `tools\xray.exe` is present it is bundled automatically; otherwise the built EXE can find a runtime at `%APPDATA%\ZainWolfTunnel\tools\xray.exe`.
3. To add Full Traffic support, run `INSTALL_FULL_TRAFFIC_HELPERS.bat` first; it builds tun2socks from the included source and uses the bundled Wintun DLL. If Go modules cannot be downloaded and are not cached, the standard EXE can still be built, but Full Traffic will remain unavailable.
4. If Full Traffic fails to start, inspect `%APPDATA%\ZainWolfTunnel\tun2socks.log` and the connection log.

This ZIP is a complete build kit and source package; it does not contain a precompiled Windows EXE. A native Windows build cannot be produced from the Linux environment used to prepare this package.

## Payload behavior

Tokens supported: `[host]`, `[port]`, `[host_port]`, `[ssh]`, `[protocol]`, `[netData]`, `[cr]`, `[lf]`, `[crlf]`, and `[lfcr]`.

The HTTP payload handshake can continue through supported intermediate response chains such as `301 Moved Permanently` → `101 Switching Protocols` → `200 Connection Established`, matching the response sequence in the supplied DarkTunnel log. A `301` alone does not prove that a tunnel was established; a compatible proxy/server and valid payload are still required. SOCKS5 upstream mode ignores the payload field.

## Security notes

- The app deliberately does not save the SSH server/login field because it contains the password. Other preferences are stored under `%APPDATA%\ZainWolfTunnel`. An active Xray profile's temporary JSON contains its UUID/password and is removed on Disconnect.
- The first-seen SSH host key is shown for confirmation and then stored in `known_hosts`.
- Use only SSH servers/proxies you own or have permission to use. The SSH account must allow TCP forwarding (`direct-tcpip`).
- Upstream proxy authentication is not supported in this initial version.
- The local SOCKS5 and HTTP listeners bind to `127.0.0.1` only, not to your LAN.

## Tests

From this folder run:

```bat
py -3 -m unittest -v test_config_import.py test_xray_backend.py test_noway_core.py test_windows_tun.py test_setup_script.py
```

The automated tests use mock proxy/SSH channels and pure route-planning tests. They do not perform a live test against a real SSH endpoint or modify a Windows route table. Full Traffic must still be tested on the target Windows PC and network.

## Upstream components

- tun2socks: https://github.com/xjasonlyu/tun2socks (the helper bootstrap downloads v2.7.0 for Windows AMD64; SHA-256 verified)
- Wintun: https://www.wintun.net/ (the helper bootstrap downloads official signed 0.14.1 AMD64 DLL; SHA-256 verified)
- Microsoft OpenSSH overview: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview


## Using the uploaded source archives

- `third_party/tun2socks-2.7.0/` contains the tun2socks source and MIT license. No prebuilt `tun2socks.exe` was present in the uploaded archive.
- `tools/wintun.dll` is the AMD64 DLL taken from the uploaded Wintun 0.14.1 archive. Its license is preserved in `tools/licenses/Wintun-LICENSE.txt`.
- To enable Full Traffic, install Go 1.26.3 or newer, then run `BUILD_TUN2SOCKS_FROM_SOURCE.bat`. The first source build may download Go modules. Then run `build_windows_exe.bat` again to bundle both helpers into the EXE.
- If all Go module sources time out, run `CHECK_GO_MODULE_NETWORK.bat`. The failure is then a network/proxy access problem, not a missing Go install. Try a mobile hotspot or set `HTTPS_PROXY`/`HTTP_PROXY` in Command Prompt if the network requires a proxy. This ZIP is not a fully offline Go build.


## Fixing Go module TLS handshake timeouts

- This bundle configures the Go module sources as `https://goproxy.io|https://proxy.golang.org|direct`. The pipe separator makes Go try the next source after timeout/network errors, rather than only after HTTP 404/410 responses.
- Run `CHECK_GO_MODULE_NETWORK.bat` to test name resolution and whether Go can download dependencies.
- If every source fails, connect the PC to a mobile hotspot/another network, or configure `HTTPS_PROXY` and `HTTP_PROXY` in the same Command Prompt if your network requires an explicit proxy. A browser extension proxy does not necessarily route command-line Go traffic.
- Keep module checksum verification enabled. Do not set `GOSUMDB=off` as a workaround.
