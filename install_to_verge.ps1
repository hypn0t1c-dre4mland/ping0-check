# Install Ping0 integration into Clash Verge Rev
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$vergeDir = Join-Path $env:APPDATA "io.github.clash-verge-rev.clash-verge-rev"
$vergeYaml = Join-Path $vergeDir "verge.yaml"
$vergeBak = Join-Path $vergeDir "verge.yaml.bak"

if (-not (Test-Path $vergeYaml)) {
    Write-Error "找不到 Clash Verge 配置文件: $vergeYaml"
}

# 1. Backup if not already backed up
if (-not (Test-Path $vergeBak)) {
    Copy-Item -Path $vergeYaml -Destination $vergeBak -Force
    Write-Host "[1/4] 已备份原始配置文件至 verge.yaml.bak" -ForegroundColor Cyan
} else {
    Write-Host "[1/4] 已存在历史备份 verge.yaml.bak" -ForegroundColor Gray
}

# 2. Read and modify configuration
$content = Get-Content -Path $vergeYaml -Raw -Encoding UTF8

# Modify startup_script
$hookPath = "$ScriptDir\startup_hook.ps1"
$startupLine = "startup_script: 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$hookPath`"'"
$content = $content -replace "startup_script:\s*null", $startupLine

# Modify web_ui_list
$webUiBlock = @"
web_ui_list:
  - name: "Ping0 风控检测"
    url: "http://127.0.0.1:39088"
"@

if ($content -match "web_ui_list:\s*null") {
    $content = $content -replace "web_ui_list:\s*null", $webUiBlock
    Write-Host "[2/4] 已注入 Ping0 Web UI 仪表盘配置" -ForegroundColor Cyan
} elseif ($content -notmatch "39088") {
    $content = $content -replace "web_ui_list:\s*", "`$0`r`n  - name: `"Ping0 风控检测`"`r`n    url: `"http://127.0.0.1:39088`"`r`n"
    Write-Host "[2/4] 已追加 Ping0 Web UI 到现有列表" -ForegroundColor Cyan
} else {
    Write-Host "[2/4] Ping0 Web UI 已存在于配置中" -ForegroundColor Gray
}

# 3. Save modified verge.yaml
[System.IO.File]::WriteAllText($vergeYaml, $content, [System.Text.Encoding]::UTF8)
Write-Host "[3/4] 配置文件写入成功" -ForegroundColor Green

# 4. Start background service if not running
$serverPort = 39088
$conn = Get-NetTCPConnection -LocalPort $serverPort -State Listen -ErrorAction SilentlyContinue
if (-not $conn) {
    Start-Process -FilePath "node.exe" -ArgumentList "server.js" -WorkingDirectory $ScriptDir -WindowStyle Hidden
    Write-Host "[4/4] Ping0 后台检测服务已就绪 (端口: $serverPort)" -ForegroundColor Green
} else {
    Write-Host "[4/4] Ping0 后台检测服务正在运行中" -ForegroundColor Green
}

Write-Host "============================================================" -ForegroundColor Yellow
Write-Host " 集成配置完成！" -ForegroundColor Green
Write-Host " 1. 打开或切换到 Clash Verge 窗口"
Write-Host " 2. 点击左侧导航栏的 [Web UI] 或 [订阅设置 -> Web UI]"
Write-Host " 3. 选择 [Ping0 风控检测] 即可查看实时风控大屏"
Write-Host " 4. 每次打开 Clash Verge 会自动弹窗提醒当前 IP 与风控分"
Write-Host "============================================================" -ForegroundColor Yellow
