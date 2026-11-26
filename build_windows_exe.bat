@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title ZainWolf Tunnel - Windows EXE Builder

where py >nul 2>nul
if errorlevel 1 (
  echo Python 3 is required to build the executable.
  echo Install Python 3.10 or newer: https://www.python.org/downloads/windows/
  pause
  exit /b 1
)
py -3 --version
if errorlevel 1 (
  echo Python was not found. Install Python 3.10 or newer first.
  pause
  exit /b 1
)

echo.
echo [1/4] Installing Python build requirements...
echo This step needs access to your configured Python package index.
py -3 -m pip install --disable-pip-version-check -r requirements.txt pyinstaller
if errorlevel 1 goto :failed

echo.
echo [2/4] Running automated tests...
py -3 -m unittest -v test_config_import.py test_xray_backend.py test_noway_core.py test_windows_tun.py test_setup_script.py test_full_traffic_fallback.py
if errorlevel 1 goto :failed

echo.
echo [3/4] Checking optional tunnel helper files...
set "XRAY_FLAG="
if exist "tools\xray.exe" set XRAY_FLAG=--add-binary "tools\xray.exe;tools"
if exist "tools\tun2socks.exe" if exist "tools\wintun.dll" goto :build_full

echo WARNING: tools\tun2socks.exe is missing (the Wintun DLL is bundled).
echo The standard SSH, HTTP payload, local SOCKS5, and local HTTP proxy features
echo will still be packaged. Full Traffic mode will report that its helpers are missing.
echo The build will NOT try to download GitHub/Wintun files automatically.
echo Run INSTALL_FULL_TRAFFIC_HELPERS.bat to compile tun2socks from included source.
echo This needs Go 1.26.3+ and may need access to proxy.golang.org for Go modules.
echo Then run this builder again to bundle Full Traffic support.
echo.
goto :build_standard

:build_full
echo Both helper files found. Building with optional Full Traffic support.
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name ZainWolfTunnel --collect-all paramiko --collect-all cryptography --collect-all bcrypt --collect-all nacl --add-binary "tools\tun2socks.exe;." --add-binary "tools\wintun.dll;." %XRAY_FLAG% ZainWolfTunnel.py
if errorlevel 1 goto :failed
goto :copy_notices

:build_standard
echo Building standard local-proxy version (without Full Traffic helper binaries)...
py -3 -m PyInstaller --noconfirm --clean --onefile --windowed --name ZainWolfTunnel --collect-all paramiko --collect-all cryptography --collect-all bcrypt --collect-all nacl %XRAY_FLAG% ZainWolfTunnel.py
if errorlevel 1 goto :failed

:copy_notices
echo.
echo [4/4] Copying third-party notices...
if not exist "dist\licenses" mkdir "dist\licenses"
if exist "tools\licenses\*" copy /Y "tools\licenses\*" "dist\licenses\" >nul
if exist "tools\THIRD_PARTY_NOTICES.txt" copy /Y "tools\THIRD_PARTY_NOTICES.txt" "dist\THIRD_PARTY_NOTICES.txt" >nul
echo.
echo ==============================================================
echo BUILD COMPLETE: %CD%\dist\ZainWolfTunnel.exe
echo ==============================================================
if not exist "tools\tun2socks.exe" echo NOTE: Full Traffic mode is not included until its helper files are installed.
echo.
echo Run the EXE to use SSH and local proxy modes.
echo VLESS/VMess/Trojan imports connect through Xray Core when xray.exe is installed.
if not exist "tools\xray.exe" echo If the Xray engine is missing, run INSTALL_XRAY_CORE.bat and rebuild.
echo If temporary routes were left after an earlier Full Traffic test, run restore_network_routes.bat as Administrator.
pause
endlocal
exit /b 0

:failed
echo.
echo Build failed. Review the error above.
echo If the failure happened while installing Python packages, check Python/package-index internet access.
pause
endlocal
exit /b 1
