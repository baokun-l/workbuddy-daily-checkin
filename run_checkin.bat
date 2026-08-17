@echo off
REM ============================================================
REM  WorkBuddy Daily Check-in - Windows batch launcher
REM  Called by Windows Task Scheduler
REM ============================================================

REM Change to the directory of this script
cd /d "%~dp0"

REM Python path: prefer WorkBuddy managed Python, else system python
set "WB_PYTHON=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe"
set "SYS_PYTHON=python"

if exist "%WB_PYTHON%" (
    set "PYTHON_CMD=%WB_PYTHON%"
) else (
    set "PYTHON_CMD=%SYS_PYTHON%"
)

REM Run the check-in script, append output to log
"%PYTHON_CMD%" workbuddy_checkin.py

REM Pass exit code to Task Scheduler
exit /b %ERRORLEVEL%
