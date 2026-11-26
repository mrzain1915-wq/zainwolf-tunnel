# ZainWolf Tunnel — Build README

## What this is

**ZainWolf Tunnel** is a dark-themed Windows 10/11 desktop tunnel app
(Python + Tkinter). Paste an SSH server login (`host:port@user:password`) or
import a proxy link (`ssh://`, `vless://`, `vmess://`, `trojan://`, or an
Xray/V2Ray client JSON), click **CONNECT**, and the app opens local proxies
on the PC — SOCKS5 on `127.0.0.1:1080` and HTTP on `127.0.0.1:8081` — so
browsers and proxy-aware apps route through the tunnel.

SSH modes: **Direct SSH**, **HTTP + Payload** (custom payload tokens such as
`[host]`, `[crlf]` sent to an upstream HTTP proxy before SSH negotiates),
and **SOCKS5 upstream** (no-auth). VLESS/VMess/Trojan profiles connect
through the bundled Xray Core (`xray.exe`).

Optional **Full Traffic** mode (requires "Run as administrator") uses a
Wintun virtual adapter + tun2socks to capture all IPv4 TCP traffic from apps
that ignore the system proxy. If Full Traffic cannot start, the app warns
once and continues in local-proxy mode.

SSH passwords are never saved. Other settings live in
`%APPDATA%\ZainWolfTunnel`. Imported Xray profile JSON is written
temporarily while connected and deleted on Disconnect.

## How the build works (GitHub Actions)

Push to `main`/`master` or run the workflow manually
(`.github/workflows/build-windows.yml`, `windows-latest`, Python 3.12):

1. Verifies the bundled helpers exist in `tools/` (`tun2socks.exe`,
   `wintun.dll`, `xray.exe`) — the build fails loudly if any is missing,
   instead of silently producing a feature-poor EXE.
2. Installs `requirements.txt` + PyInstaller.
3. Runs the **full** test suite (45 tests).
4. Builds the one-file EXE with PyInstaller
   (`--name ZainWolfTunnel`, `--windowed`), bundling all three helpers.
5. Installs Inno Setup (via Chocolatey) and compiles `installer.iss`.
6. Publishes two artifacts (14-day retention):
   - `ZainWolfTunnel-Windows-x64` — `dist/ZainWolfTunnel.exe` (portable, for testing only)
   - `ZainWolfTunnel-Setup-1.0.0` — `Output/ZainWolfTunnel-Setup-1.0.0.exe` (**the installer — this is what users receive**)

## The installer

`installer.iss` (Inno Setup) installs to
`%ProgramFiles%\ZainWolf Tunnel\` with Start Menu and optional Desktop
shortcuts, requires administrator rights, and includes the third-party
notices, licences, and the `restore_network_routes` cleanup scripts.
Uninstalling runs the route-restore cleanup silently, so no temporary Full
Traffic routes are left behind. The app only works after installation —
users receive the setup EXE, never the raw portable EXE.

## Bundled helpers (already in `tools/`)

| File | Source | Size |
|---|---|---|
| `tun2socks.exe` | Built from `third_party/tun2socks-2.7.0/` with Go 1.27.4 (`GOOS=windows GOARCH=amd64 CGO_ENABLED=0`) | 12,495,872 bytes |
| `wintun.dll` | Wintun 0.14.1 AMD64, user-provided | 427,552 bytes |
| `xray.exe` | Official Xray-core **v26.11.9** (`Xray-windows-64.zip`, SHA-256 verified against the release `.dgst`) | 34,864,640 bytes |

To rebuild the helpers: `BUILD_TUN2SOCKS_FROM_SOURCE.bat` (needs Go 1.26.3+)
and `INSTALL_XRAY_CORE.bat` (needs the official `Xray-windows-64.zip`).
Do not replace `xray.exe` with an unofficial build.

## Local build (Windows only)

Double-click `build_windows_exe.bat`. It installs Python requirements, runs
the full test suite, and creates `dist\ZainWolfTunnel.exe`. To build the
installer locally, install Inno Setup 6 and run
`ISCC.exe installer.iss` from the project root.

## Honest limits — do not market this as a leak-proof VPN

- **TCP only.** UDP and IPv6 traffic is not tunnelled; apps using QUIC/UDP bypass the tunnel.
- **DNS is not inside the tunnel.** Resolver IPs get bypass routes so name resolution keeps working.
- **Upstream proxy auth is unsupported.** SOCKS5 upstream is no-auth only.
- **Full Traffic needs "Run as administrator".** Without admin rights the app falls back to local-proxy mode.
- **No live Windows smoke test has been done yet.** The test suite uses mocks and pure route-planning. Before distributing, test on a real Windows PC: SSH connect, VLESS connect, Full Traffic on/off, and confirm Disconnect restores the system proxy and routes.
