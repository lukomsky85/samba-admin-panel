@echo off
chcp 65001 > nul
REM release-gui.bat - double-click launches release-gui.ps1 with the right
REM execution policy (Windows blocks .ps1 scripts by default).
REM Console window stays open on purpose - git/gh sometimes ask something
REM interactively (SSH key confirmation, gh login), this window is for that.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0release-gui.ps1"

echo.
echo Press any key to close this window...
pause >nul
