@echo off
setlocal
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0vault.ps1" %*
exit /b %ERRORLEVEL%
