@echo off
:: ============================================================
:: IDS Victim Agent - Auto Launcher
:: ============================================================
:: Copy this file + agent.py to the victim PC (e.g. C:\IDS_Agent\)
:: Before running, edit agent.py and set:
::   MONITOR_PC_IP = "<your monitoring PC IP>"
::   VICTIM_NAME   = "<this PC's name>"
:: ============================================================

:: Change to the folder where agent.py lives
cd /d "%~dp0"

:: Check Python is installed
where pythonw >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python from https://python.org and try again.
    pause
    exit /b 1
)

:: Launch agent silently in background (no console window)
echo [IDS] Starting Victim Agent in background...
start "" /B pythonw "%~dp0agent.py"

echo [IDS] Agent is now running silently.
echo [IDS] Check your IDS Dashboard to confirm this PC appears.
timeout /t 3 >nul
exit
