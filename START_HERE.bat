@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title ZainWolf Tunnel - Windows Build Kit

echo ==============================================================
echo ZAINWOLF TUNNEL - WINDOWS BUILD KIT
echo ==============================================================
echo.
echo   1. Build standard SSH/payload/local-proxy EXE
 echo  2. Build tun2socks and Full Traffic helper, then build EXE
echo   3. Install Xray Core from the official ZIP, then rebuild EXE
echo.
echo Notes:
echo - Option 1 does not need Go; imported VLESS/VMess/Trojan profiles need xray.exe.
echo - Option 2 needs Go and access to Go modules if dependencies are not cached.
echo - Option 3: first download Xray-windows-64.zip from the official page opened by the installer,
echo   save it beside INSTALL_XRAY_CORE.bat, then select option 3 again.
echo.
set /p "MODE=Choose 1, 2, or 3 (default 1): "
if "%MODE%"=="2" goto full
if "%MODE%"=="3" goto xray
call "%~dp0build_windows_exe.bat"
exit /b %ERRORLEVEL%
:full
call "%~dp0INSTALL_FULL_TRAFFIC_HELPERS.bat"
if errorlevel 1 exit /b 1
call "%~dp0build_windows_exe.bat"
exit /b %ERRORLEVEL%
:xray
call "%~dp0INSTALL_XRAY_CORE.bat"
if errorlevel 1 exit /b 1
call "%~dp0build_windows_exe.bat"
exit /b %ERRORLEVEL%
