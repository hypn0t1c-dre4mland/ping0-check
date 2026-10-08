@echo off
chcp 65001 >nul
title Clash Verge - IP Risk Checker

REM 智能自适应定位 ping0 项目根目录
set "TARGET_DIR="

if exist "%~dp0check_cli.js" (
    set "TARGET_DIR=%~dp0"
) else if exist "%~dp0ping0\check_cli.js" (
    set "TARGET_DIR=%~dp0ping0"
) else if exist "%USERPROFILE%\Desktop\ping0\check_cli.js" (
    set "TARGET_DIR=%USERPROFILE%\Desktop\ping0"
) else if exist "c:\Users\zct\Desktop\ping0\check_cli.js" (
    set "TARGET_DIR=c:\Users\zct\Desktop\ping0"
)

if not defined TARGET_DIR (
    echo [ERROR] 无法定位检测脚本 check_cli.js！
    echo 请确认 ping0 文件夹与本脚本在同一目录下，或位于桌面。
    pause
    exit /b 1
)

REM 规范化路径：若末尾存在反斜杠则移除
if "%TARGET_DIR:~-1%"=="\" set "TARGET_DIR=%TARGET_DIR:~0,-1%"

REM 切换到项目根目录，确保相对模块与资源加载正确
cd /d "%TARGET_DIR%"

REM 检查 Node.js 环境，优先运行 CLI 全功能检测，缺失时自动降级到 PowerShell
set "NODE_CMD="
where node >nul 2>&1 && set "NODE_CMD=node"
if not defined NODE_CMD if exist "%ProgramFiles%\nodejs\node.exe" set "NODE_CMD=%ProgramFiles%\nodejs\node.exe"
if not defined NODE_CMD if exist "%ProgramFiles(x86)%\nodejs\node.exe" set "NODE_CMD=%ProgramFiles(x86)%\nodejs\node.exe"
if not defined NODE_CMD if exist "%LOCALAPPDATA%\Programs\node\node.exe" set "NODE_CMD=%LOCALAPPDATA%\Programs\node\node.exe"

if defined NODE_CMD (
    "%NODE_CMD%" "%TARGET_DIR%\check_cli.js" %*
) else (
    echo [WARN] 未检测到 Node.js 环境，正在切换至 PowerShell 备用检测引擎...
    if exist "%TARGET_DIR%\check.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%TARGET_DIR%\check.ps1" %*
    ) else (
        echo [ERROR] 未找到 Node.js，且未找到 check.ps1，请先安装 Node.js！
    )
)

pause
