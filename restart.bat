@echo off
echo Restarting server...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3000"') do (
    taskkill /f /pid %%a 2>nul
)
timeout /t 1 >nul
start "Cloud Server" cmd /k "cd /d D:\WEB && node server.js"
echo Server restarted
timeout /t 2 >nul