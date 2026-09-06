@echo off
chcp 65001 > nul
REM release-gui-py.bat - double-click launches release_gui.py.
REM Console window stays open on purpose - git/gh sometimes ask something
REM interactively (SSH key confirmation, gh login), this window is for that.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Python not found in PATH. Install it from https://python.org
    echo ^(during install, check "Add python.exe to PATH"^) and run this again.
    pause
    exit /b 1
)

python "%~dp0release_gui.py"

echo.
echo Press any key to close this window...
pause >nul
