@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title ZainWolf Tunnel - Check Go module network

echo ==============================================================
echo CHECKING GO MODULE NETWORK ACCESS
echo ============================================================== 
echo.
where go.exe >nul 2>nul
if errorlevel 1 (
  echo Go was not found on PATH. Install Go and reopen this window.
  pause
  exit /b 1
)
go version
echo.
echo Testing DNS for common Go module hosts...
nslookup goproxy.io
echo.
nslookup proxy.golang.org
echo.
echo Testing actual Go module download endpoints using fallback sources...
set "GOPROXY=https://goproxy.io|https://proxy.golang.org|direct"
set "GOSUMDB=sum.golang.org"
set "GOTOOLCHAIN=local"
set "GODEBUG=http2client=0"
pushd "third_party\tun2socks-2.7.0"
go mod download
set "RESULT=%ERRORLEVEL%"
popd
if "%RESULT%"=="0" (
  echo.
  echo SUCCESS: Go dependencies downloaded and verified.
) else (
  echo.
  echo FAILED: This PC/network cannot currently reach a usable Go module source.
  echo Try a mobile hotspot or configure HTTPS_PROXY/HTTP_PROXY if your network requires one.
  echo Do not disable Go checksum verification to work around this problem.
)
echo.
pause
exit /b %RESULT%
