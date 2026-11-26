"""Optional IPv4 full-traffic routing for ZainWolf Tunnel on Windows.

Requires elevation plus the official xjasonlyu/tun2socks Windows binary and
WireGuard's signed Wintun DLL. SSH is still TCP-only: UDP applications are not
supported by the local SSH SOCKS5 server, and DNS resolver IPs are deliberately
routed over the underlying adapter so name resolution continues to work.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

TUN_NAME = "wintun"
TUN_ADDRESS = "198.18.0.1"
TUN_MASK = "255.254.0.0"
TUN_GATEWAY = TUN_ADDRESS
TUN_ROUTES = [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")]


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resource_dir() -> Path:
    # PyInstaller --onefile extracts the helper executables beside the frozen app resources.
    frozen_dir = getattr(sys, "_MEIPASS", None)
    return Path(frozen_dir) if frozen_dir else Path(__file__).resolve().parent


def helper_paths() -> tuple[Optional[Path], Optional[Path]]:
    root = resource_dir()
    candidates = [root, root / "tools", Path(__file__).resolve().parent / "tools"]
    tun = next((d / "tun2socks.exe" for d in candidates if (d / "tun2socks.exe").is_file()), None)
    wintun = next((d / "wintun.dll" for d in candidates if (d / "wintun.dll").is_file()), None)
    return tun, wintun


def helpers_available() -> bool:
    tun, wintun = helper_paths()
    return bool(tun and wintun)


def _hidden_kwargs():
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {"startupinfo": startupinfo, "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}


def _run(args, timeout=15, check=True):
    result = subprocess.run(
        [str(x) for x in args], capture_output=True, text=True, timeout=timeout,
        errors="replace", **_hidden_kwargs(),
    )
    if check and result.returncode:
        details = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"Command failed ({result.returncode}): {' '.join(map(str, args[:3]))}; {details[:300]}")
    return result


def _powershell(script: str, timeout=15) -> str:
    result = _run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], timeout=timeout)
    return result.stdout.strip()


def route_plan(endpoint_ip: str, gateway: str, physical_if: int, tun_if: int, dns_servers: list[str]) -> list[dict]:
    """Pure route planner, easy to test without changing the host route table."""
    endpoint = str(ipaddress.ip_address(endpoint_ip))
    if ipaddress.ip_address(endpoint).version != 4:
        raise ValueError("Full Traffic currently requires an IPv4 SSH/proxy endpoint.")
    gw = str(ipaddress.ip_address(gateway))
    if ipaddress.ip_address(gw).version != 4:
        raise ValueError("The underlying gateway must be IPv4.")
    if physical_if <= 0 or tun_if <= 0 or physical_if == tun_if:
        raise ValueError("Invalid physical/TUN interface index.")

    items = []
    bypasses = {endpoint}
    for candidate in dns_servers:
        try:
            addr = ipaddress.ip_address(str(candidate).strip())
        except ValueError:
            continue
        if addr.version == 4 and not addr.is_private and not addr.is_loopback and not addr.is_link_local and not addr.is_multicast:
            bypasses.add(str(addr))

    # Specific host routes must use the real gateway before the broad TUN routes are installed.
    for address in sorted(bypasses):
        items.append({"destination": address, "mask": "255.255.255.255", "gateway": gw, "interface": int(physical_if), "kind": "bypass"})
    for destination, mask in TUN_ROUTES:
        items.append({"destination": destination, "mask": mask, "gateway": TUN_GATEWAY, "interface": int(tun_if), "kind": "tun"})
    return items


class FullTrafficManager:
    """Start tun2socks and install temporary IPv4 split-default routes with rollback."""
    def __init__(self, state_file: Path, log_callback: Optional[Callable[[str, str], None]] = None):
        self.state_file = Path(state_file)
        self.log_callback = log_callback or (lambda message, level="info": None)
        self.process = None
        self.log_handle = None
        self.routes: list[dict] = []
        self.started = False
        self._lock = threading.RLock()

    def _log(self, message, level="info"):
        try:
            self.log_callback(message, level)
        except Exception:
            pass

    def _save_state(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        tmp.write_text(json.dumps({"routes": self.routes, "pid": os.getpid(), "created": time.time()}, indent=2), encoding="utf-8")
        tmp.replace(self.state_file)

    def _route_exists_on_physical(self, destination: str, mask: str, physical_if: int) -> bool:
        prefix = f"{destination}/32" if mask == "255.255.255.255" else None
        if not prefix:
            return False
        script = (
            f"$r=Get-NetRoute -DestinationPrefix '{prefix}' -AddressFamily IPv4 -ErrorAction SilentlyContinue "
            f"| Where-Object {{$_.InterfaceIndex -eq {int(physical_if)}}} | Select-Object -First 1; "
            "if($r){'yes'}else{'no'}"
        )
        try:
            return _powershell(script).lower() == "yes"
        except Exception:
            return False

    def _add_route(self, route: dict):
        if route["kind"] == "bypass" and self._route_exists_on_physical(route["destination"], route["mask"], route["interface"]):
            self._log(f"Endpoint/DNS route already exists outside TUN: {route['destination']}", "info")
            return
        _run(["route.exe", "ADD", route["destination"], "MASK", route["mask"], route["gateway"], "METRIC", "1", "IF", str(route["interface"])])
        self.routes.append(route)
        self._save_state()
        self._log(f"Added {route['kind']} route {route['destination']} / {route['mask']}.", "info")

    def _delete_route(self, route: dict) -> bool:
        result = _run(["route.exe", "DELETE", route["destination"], "MASK", route["mask"], route["gateway"], "IF", str(route["interface"])], check=False)
        if result.returncode == 0:
            return True
        detail = (result.stdout + " " + result.stderr).lower()
        # If the route is already absent, cleanup is effectively complete.
        if any(marker in detail for marker in ("cannot find", "not found", "no matching", "does not exist")):
            return True
        return False

    @staticmethod
    def _detect_physical_network():
        script = r'''
$routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch 'wintun|tun2socks|ZainWolf Tunnel' } |
  Sort-Object RouteMetric
$r = $routes | Select-Object -First 1
if ($null -eq $r) { throw 'No active IPv4 default route was found.' }
$dns = @((Get-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Where-Object { $_ })
[PSCustomObject]@{ gateway=[string]$r.NextHop; interfaceIndex=[int]$r.InterfaceIndex; interfaceAlias=[string]$r.InterfaceAlias; dns=@($dns) } | ConvertTo-Json -Compress
'''
        raw = _powershell(script, timeout=20)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Could not read the physical network route: {raw[:200]}") from exc
        if not data.get("gateway") or not data.get("interfaceIndex"):
            raise RuntimeError("Could not identify the active physical gateway/interface.")
        dns = data.get("dns", [])
        if isinstance(dns, str):
            dns = [dns]
        data["dns"] = [str(x) for x in dns if x]
        return data

    @staticmethod
    def _get_tun_interface_index():
        script = r'''
$a = Get-NetAdapter -Name 'wintun' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($a) { [string]$a.ifIndex }
'''
        raw = _powershell(script)
        try:
            return int(raw.splitlines()[-1].strip()) if raw else None
        except (ValueError, IndexError):
            return None

    def start(self, local_socks_port: int, endpoint_ip: str):
        with self._lock:
            if self.started:
                return
            if os.name != "nt":
                raise RuntimeError("Full Traffic mode is only supported on Windows 10/11.")
            if not is_admin():
                raise RuntimeError("Full Traffic needs Administrator rights. Close ZainWolf Tunnel, right-click it, choose 'Run as administrator', then connect again.")
            try:
                ipaddress.IPv4Address(endpoint_ip)
            except ValueError as exc:
                raise RuntimeError("Could not identify an IPv4 address for your SSH/proxy endpoint; Full Traffic needs IPv4.") from exc
            tun_bin, wintun_dll = helper_paths()
            if not tun_bin or not wintun_dll:
                raise RuntimeError("Full Traffic helpers are missing. Run setup_windows_tun_helpers.ps1 and rebuild the EXE.")
            if self.state_file.exists():
                try:
                    stale = json.loads(self.state_file.read_text(encoding="utf-8")).get("routes", [])
                    if stale:
                        raise RuntimeError("A previous Full Traffic session left a route recovery file. Run restore_network_routes.bat as Administrator before connecting.")
                except json.JSONDecodeError:
                    raise RuntimeError("The previous Full Traffic recovery file is invalid. Run restore_network_routes.bat as Administrator and check your network routes.")

            physical = self._detect_physical_network()
            self._log(f"Using underlying network {physical['interfaceAlias']} via {physical['gateway']}.", "info")
            log_path = self.state_file.with_name("tun2socks.log")
            self.log_handle = open(log_path, "ab", buffering=0)
            command = [str(tun_bin), "--device", TUN_NAME, "--proxy", f"socks5://127.0.0.1:{int(local_socks_port)}", "--loglevel", "info"]
            try:
                self.process = subprocess.Popen(command, cwd=str(tun_bin.parent), stdout=self.log_handle, stderr=subprocess.STDOUT, **_hidden_kwargs())
                self._log("Starting official tun2socks helper and waiting for Wintun interface…", "info")
                deadline = time.monotonic() + 12
                tun_index = None
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        tail = ""
                        try:
                            self.log_handle.flush()
                            tail = log_path.read_text(encoding="utf-8", errors="replace")[-1000:]
                        except Exception:
                            pass
                        raise RuntimeError("tun2socks stopped during startup. Check tools/wintun.dll and tun2socks.log. " + tail[-400:])
                    tun_index = self._get_tun_interface_index()
                    if tun_index:
                        break
                    time.sleep(0.25)
                if not tun_index:
                    raise RuntimeError("Wintun interface did not appear. Run as Administrator and check tun2socks.log.")

                _run(["netsh.exe", "interface", "ipv4", "set", "address", f"name={TUN_NAME}", "source=static", f"addr={TUN_ADDRESS}", f"mask={TUN_MASK}"], timeout=20)
                plan = route_plan(endpoint_ip, physical["gateway"], int(physical["interfaceIndex"]), int(tun_index), physical["dns"])
                for route in plan:
                    self._add_route(route)
                if self.process.poll() is not None:
                    raise RuntimeError("tun2socks exited after routes were installed. Check tun2socks.log.")
                self.started = True
                self._log("Full Traffic started: supported IPv4 TCP traffic is routed through the SSH SOCKS5 tunnel.", "ok")
                self._log("Important: DNS resolver IPs use the underlying network; UDP traffic is not supported by this SSH relay. IPv6 is not routed.", "info")
            except Exception:
                self.stop()
                raise

    def is_running(self) -> bool:
        return bool(self.started and self.process is not None and self.process.poll() is None)

    def stop(self):
        with self._lock:
            # Remove broad TUN routes first so Windows promptly falls back to the prior default route.
            tun_routes = [r for r in self.routes if r.get("kind") == "tun"]
            bypass_routes = [r for r in self.routes if r.get("kind") == "bypass"]
            for route in reversed(tun_routes):
                if self._delete_route(route):
                    try:
                        self.routes.remove(route)
                    except ValueError:
                        pass
                else:
                    self._log(f"Could not remove route {route['destination']} mask {route['mask']}.", "error")
            if self.process is not None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=3)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
                self.process = None
            for route in reversed(bypass_routes):
                if self._delete_route(route):
                    try:
                        self.routes.remove(route)
                    except ValueError:
                        pass
                else:
                    self._log(f"Could not remove bypass route {route['destination']}.", "error")
            if self.log_handle:
                try:
                    self.log_handle.close()
                except Exception:
                    pass
                self.log_handle = None
            self.started = False
            if not self.routes:
                try:
                    self.state_file.unlink(missing_ok=True)
                except OSError:
                    pass
            else:
                try:
                    self._save_state()
                    self._log("Some routes could not be confirmed removed. Run restore_network_routes.bat as Administrator.", "error")
                except Exception:
                    pass


def restore_saved_routes(state_file: Path):
    """Remove saved active routes after a crash; call only from an elevated process."""
    if os.name != "nt":
        raise RuntimeError("Route recovery runs on Windows only.")
    if not is_admin():
        raise RuntimeError("Run recovery as Administrator.")
    path = Path(state_file)
    if not path.exists():
        return 0
    data = json.loads(path.read_text(encoding="utf-8"))
    routes = data.get("routes", [])
    count = 0
    manager = FullTrafficManager(path)
    manager.routes = list(routes)
    manager.stop()
    if path.exists():
        raise RuntimeError("Some routes could not be removed; the recovery file was retained.")
    return len(routes)
