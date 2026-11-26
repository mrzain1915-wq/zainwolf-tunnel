@echo off
setlocal
cd /d "%~dp0"
echo ======================================
echo          ZAINWOLF TUNNEL SETUP
echo ======================================
where py >nul 2>nul
if errorlevel 1 (
  echo Python Launcher not found.
  echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
  echo During setup, enable the Python Launcher and Add Python to PATH.
  pause
  exit /b 1
)
py -3 --version
if errorlevel 1 (
  echo Python 3 was not found. Install Python 3.10 or newer first.
  pause
  exit /b 1
)
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your internet connection and try again.
  pause
  exit /b 1
)
py -3 ZainWolfTunnel.py
if errorlevel 1 pause
endlocal
