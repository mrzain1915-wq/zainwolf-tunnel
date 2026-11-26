@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title ZainWolf Tunnel - Build tun2socks from included source

echo ==============================================================
echo ZAINWOLF TUNNEL - BUILD TUN2SOCKS FROM SOURCE
echo ============================================================== 
echo.
echo This uses the included tun2socks v2.7.0 source tree; it does NOT download
echo the prebuilt GitHub release asset.
echo It requires Go 1.26.3 or newer and internet access to at least one Go module source.
echo.
if not exist "third_party\tun2socks-2.7.0\go.mod" (
  echo ERROR: Included tun2socks source or go.mod is missing.
  pause
  exit /b 1
)
where go.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: Go is not installed or go.exe is not on PATH.
  echo Install Go 1.26.3 or newer for Windows AMD64, then reopen this window.
  echo Official site: https://go.dev/dl/
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$raw=(go env GOVERSION).Trim() -replace '^go',''; try { if ([version]$raw -ge [version]'1.26.3') { exit 0 } else { Write-Host ('Go '+$raw+' is too old; version 1.26.3 or newer required.'); exit 2 } } catch { Write-Host ('Could not parse Go version: '+$raw); exit 3 }"
if errorlevel 1 (
  echo ERROR: Please update Go to version 1.26.3 or newer.
  pause
  exit /b 1
)

if not exist "tools" mkdir "tools"
set "GOOS=windows"
set "GOARCH=amd64"
set "CGO_ENABLED=0"
set "GOTOOLCHAIN=local"
rem Pipe separators make Go fall back on ANY error (including TLS timeout), not only 404/410.
set "GOPROXY=https://goproxy.io|https://proxy.golang.org|direct"
rem Keep checksum verification enabled; do not turn GOSUMDB off.
set "GOSUMDB=sum.golang.org"
set "GODEBUG=http2client=0"

echo.
echo Go version:
go version
echo Module sources in order: goproxy.io, proxy.golang.org, then direct VCS access.
echo Go module checksums remain enabled through sum.golang.org / go.sum.

echo.
echo [1/2] Downloading Go modules with proxy fallback (up to 3 attempts)...
pushd "third_party\tun2socks-2.7.0"
set "ATTEMPT=0"
:download_retry
set /a ATTEMPT+=1
echo.
echo Attempt %ATTEMPT% of 3: go mod download
go mod download
if not errorlevel 1 goto modules_ready
if %ATTEMPT% LSS 3 (
  echo Module download failed. Waiting 4 seconds, then retrying all configured sources...
  timeout /t 4 /nobreak >nul
  goto download_retry
)
echo.
echo ERROR: Go modules could not be downloaded from any configured source.
echo This is a network/proxy issue, not a missing Go installation.
echo Try a mobile hotspot or a network that permits HTTPS access to Go module proxies.
echo If you use a browser-only proxy/VPN, Go may not inherit that browser connection.
echo For a network proxy, set HTTPS_PROXY and HTTP_PROXY in this Command Prompt, then rerun.
popd
pause
exit /b 1

:modules_ready
echo.
echo [2/2] Compiling Windows AMD64 tun2socks.exe from bundled source...
go build -trimpath -ldflags "-s -w" -o "%~dp0tools\tun2socks.exe" .
set "BUILD_RESULT=%ERRORLEVEL%"
popd
if not "%BUILD_RESULT%"=="0" (
  echo.
  echo ERROR: Go build failed even after module download succeeded.
  pause
  exit /b %BUILD_RESULT%
)
if not exist "tools\tun2socks.exe" (
  echo ERROR: Build reported success but tools\tun2socks.exe was not created.
  pause
  exit /b 1
)
echo.
echo SUCCESS: tools\tun2socks.exe created.
for /f "tokens=*" %%H in ('certutil -hashfile "tools\tun2socks.exe" SHA256 ^| findstr /R /V "hash CertUtil"') do echo SHA256: %%H
echo.
echo Next: run build_windows_exe.bat to bundle both helpers into ZainWolfTunnel.exe.
pause
exit /b 0
