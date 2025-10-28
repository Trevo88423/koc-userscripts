@echo off
REM Quick backup script for KoC userscripts
REM Double-click this file to create backups

echo.
echo ================================
echo   KoC Userscripts Backup
echo ================================
echo.

cd /d "%~dp0"
node backup-script.js

echo.
echo ================================
echo   Backup Complete!
echo ================================
echo.
pause
