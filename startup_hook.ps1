# Clash Verge Startup Hook (Zero background server left behind)
$ErrorActionPreference = 'SilentlyContinue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Wait for Clash mixed port (7897) to be ready
$proxyPort = 7897
$maxRetries = 15
$ready = $false
for ($i = 0; $i -lt $maxRetries; $i++) {
    $proxyConn = Get-NetTCPConnection -LocalPort $proxyPort -State Listen -ErrorAction SilentlyContinue
    if ($proxyConn) {
        $ready = $true
        break
    }
    Start-Sleep -Seconds 1
}

# 2. Run one-shot check silently and pop up toast notification, then completely exit!
if ($ready) {
    Start-Process -FilePath "node.exe" -ArgumentList "check_cli.js" -WorkingDirectory $ScriptDir -WindowStyle Hidden -Wait
}
