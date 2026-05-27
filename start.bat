@echo off
echo Starting server...
start "Cloud Server" cmd /k "cd /d D:\WEB && node server.js"
echo Server window opened
timeout /t 2 >nul