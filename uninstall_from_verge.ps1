# Restore original Clash Verge configuration
$ErrorActionPreference = 'Stop'

$vergeDir = Join-Path $env:APPDATA "io.github.clash-verge-rev.clash-verge-rev"
$vergeYaml = Join-Path $vergeDir "verge.yaml"
$vergeBak = Join-Path $vergeDir "verge.yaml.bak"

if (Test-Path $vergeBak) {
    Copy-Item -Path $vergeBak -Destination $vergeYaml -Force
    Write-Host "已从备份恢复原始 verge.yaml 配置！" -ForegroundColor Green
} else {
    Write-Warning "未找到备份文件 verge.yaml.bak"
}
