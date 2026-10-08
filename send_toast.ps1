[CmdletBinding()]
param(
    [string]$Title = "Clash Verge - IP Risk Monitor",
    [string]$Message = "IP: 154.12.39.12 | Ping0 Score: 21% (Clean) | Los Angeles"
)

try {
    Add-Type -AssemblyName System.Windows.Forms
    $global:balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Shield
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipTitle = $Title
    $balloon.BalloonTipText = $Message
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(4000)
    Start-Sleep -Milliseconds 800
    Write-Output "OK"
} catch {
    Write-Warning "Notification error: $_"
}
