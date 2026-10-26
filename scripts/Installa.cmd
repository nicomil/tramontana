@echo off
rem Installs WinCleaner from this folder into Program Files (asks for administrator rights).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Source "%~dp0app"
pause
