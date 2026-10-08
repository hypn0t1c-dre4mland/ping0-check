@echo off
chcp 65001 >nul
title Ping0 Background Service - Stop
setlocal

set "TARGET_DIR="
if exist "%~dp0server.js" (
    set "TARGET_DIR=%~dp0"
) else if exist "%~dp0ping0\server.js" (
    set "TARGET_DIR=%~dp0ping0"
) else if exist "%USERPROFILE%\Desktop\ping0\server.js" (
    set "TARGET_DIR=%USERPROFILE%\Desktop\ping0"
) else if exist "c:\Users\zct\Desktop\ping0\server.js" (
    set "TARGET_DIR=c:\Users\zct\Desktop\ping0"
)

if not defined TARGET_DIR (
    echo [ERROR] 无法定位服务脚本 server.js！
    pause
    exit /b 1
)
if "%TARGET_DIR:~-1%"=="\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"
cd /d "%TARGET_DIR%"

echo [Ping0 Service] Stopping background server...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":39088" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a
    echo [Ping0 Service] Stopped process PID %%a
)
echo [Ping0 Service] Done.
pause
