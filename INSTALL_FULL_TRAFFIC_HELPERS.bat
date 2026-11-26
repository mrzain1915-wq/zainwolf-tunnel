@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title ZainWolf Tunnel - Install Full Traffic Helpers

echo ==============================================================
echo ZAINWOLF TUNNEL - PREPARE FULL TRAFFIC HELPERS
echo ==============================================================
echo.
echo Wintun AMD64 DLL is already bundled in tools\wintun.dll.
echo tun2socks is compiled from the included source tree; no GitHub release
echo executable download is used.
echo.
if not exist "tools\wintun.dll" (
  echo ERROR: tools\wintun.dll is missing from this package.
  pause
  exit /b 1
)
if not exist "tools\tun2socks.exe" (
  call "%~dp0BUILD_TUN2SOCKS_FROM_SOURCE.bat"
  if errorlevel 1 (
    echo.
    echo Could not compile tun2socks. Install Go 1.26.3+ and ensure Go module downloads work.
    pause
    exit /b 1
  )
)
if not exist "tools\tun2socks.exe" (
  echo ERROR: tun2socks.exe is still missing.
  pause
  exit /b 1
)
echo.
echo Both helpers are present:
echo   tools\tun2socks.exe
echo   tools\wintun.dll
echo.
echo Now run build_windows_exe.bat to package Full Traffic mode.
pause
exit /b 0
