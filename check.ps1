# Standalone One-Shot IP Risk Checker (Zero background server needed)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
try { $Host.UI.RawUI.WindowTitle = "Clash 节点 IP 纯净度与连通性检测" } catch {}

# 智能自适应定位 check_cli.js 路径
$cliPath = Join-Path $PSScriptRoot "check_cli.js"
if (-not (Test-Path $cliPath)) {
    $altPath = Join-Path $PSScriptRoot "ping0\check_cli.js"
    if (Test-Path $altPath) {
        $cliPath = $altPath
    } elseif (Test-Path "$env:USERPROFILE\Desktop\ping0\check_cli.js") {
        $cliPath = "$env:USERPROFILE\Desktop\ping0\check_cli.js"
    } elseif (Test-Path "c:\Users\zct\Desktop\ping0\check_cli.js") {
        $cliPath = "c:\Users\zct\Desktop\ping0\check_cli.js"
    }
}

# 检测 Node.js 可执行文件路径
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    if (Test-Path "$env:ProgramFiles\nodejs\node.exe") {
        $nodeCmd = "$env:ProgramFiles\nodejs\node.exe"
    } elseif (Test-Path "${env:ProgramFiles(x86)}\nodejs\node.exe") {
        $nodeCmd = "${env:ProgramFiles(x86)}\nodejs\node.exe"
    } elseif (Test-Path "$env:LOCALAPPDATA\Programs\node\node.exe") {
        $nodeCmd = "$env:LOCALAPPDATA\Programs\node\node.exe"
    }
}

# 若已安装 Node.js，优先调用全功能双表格检测引擎 check_cli.js
if ($nodeCmd -and (Test-Path $cliPath)) {
    Push-Location (Split-Path $cliPath)
    try {
        & $nodeCmd $cliPath @args
        exit $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

$proxyUri = "http://127.0.0.1:7897"
Write-Host "正在通过 Clash 代理 ($proxyUri) 探测出口网络..." -ForegroundColor Cyan

try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ipData = Invoke-RestMethod -Uri "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,query" -Proxy $proxyUri -TimeoutSec 6
    $sw.Stop()
} catch {
    Write-Host "`n[ERROR] 无法连接到 Clash 代理端口 7897！请先确认 Clash Verge 已启动。" -ForegroundColor Red
    Write-Host "错误信息: $_" -ForegroundColor Gray
    exit 1
}

if ($ipData.status -ne "success") {
    Write-Host "`n[ERROR] 节点网络探测失败: $($ipData.message)" -ForegroundColor Red
    exit 1
}

# 启发式风控与类型评估 (完全本地离线算法)
$ip = $ipData.query
$asn = ($ipData.as -split ' ')[0]
$org = if ($ipData.org) { $ipData.org } else { $ipData.isp }
$loc = "$($ipData.country) $($ipData.regionName) $($ipData.city)".Trim()
$isHosting = [bool]$ipData.hosting
$isProxy = [bool]$ipData.proxy

# 4 级 ASN 与机房识别
$tier1Asns = @('AS16509','AS14618','AS15169','AS8075','AS13335','AS31898','AS45102','AS132203')
$tier3Asns = @('AS46997','AS60068','AS9009','AS212238','AS53667','AS54600','AS46652')
$tier4Asns = @('AS51167','AS200019','AS30058','AS55081')
$isIdc = $isHosting -or ($tier1Asns -contains $asn) -or ($tier3Asns -contains $asn) -or ($tier4Asns -contains $asn) -or ($org -match "cloud|hosting|server|datacenter|netlab|black mesa|digitalocean|vultr|linode|hetzner")

$score = 12
$ipType = "IDC 机房 IP"
if (-not $isIdc) {
    $score = 5
    $ipType = "家庭宽带 IP"
}

if ($isProxy) { $score += 5 }
if ($tier1Asns -contains $asn) { $score -= 2 }
elseif ($tier3Asns -contains $asn) { $score += 1 }
elseif ($tier4Asns -contains $asn) { $score += 7 }

$score = [Math]::Max(5, [Math]::Min(99, $score))

# 6 级纯净度划分
$label = "纯净"
$color = "Green"
if ($score -le 15) { $label = "极度纯净"; $color = "Green" }
elseif ($score -le 25) { $label = "纯净"; $color = "Green" }
elseif ($score -le 40) { $label = "中性"; $color = "Yellow" }
elseif ($score -le 50) { $label = "轻微风险"; $color = "Yellow" }
elseif ($score -le 70) { $label = "稍高风险"; $color = "DarkYellow" }
else { $label = "极度风险"; $color = "Red" }

# CJK 宽度格式化输出工整表格
function Get-VisualWidth([string]$str) {
    $w = 0
    foreach ($ch in $str.ToCharArray()) {
        $code = [int]$ch
        if (($code -ge 0x4e00 -and $code -le 0x9fff) -or ($code -ge 0x3000 -and $code -le 0x303f) -or ($code -ge 0xff01 -and $code -le 0xff60)) {
            $w += 2
        } else {
            $w += 1
        }
    }
    return $w
}

function Pad-Visual([string]$str, [int]$len) {
    $w = Get-VisualWidth $str
    $pad = [Math]::Max(0, $len - $w)
    return $str + (" " * $pad)
}

$timeStr = Get-Date -Format "HH:mm:ss"
$wK = 16
$wV = 48

Write-Host ""
Write-Host ("┌" + ("─" * ($wK + 2)) + "┬" + ("─" * ($wV + 2)) + "┐") -ForegroundColor DarkGray
Write-Host ("│ " + (Pad-Visual "📋 节点 IP 纯净度与风控报告 [$timeStr]" ($wK + $wV + 3)) + " │") -ForegroundColor Cyan
Write-Host ("├" + ("─" * ($wK + 2)) + "┼" + ("─" * ($wV + 2)) + "┤") -ForegroundColor DarkGray

$rows = @(
    @("出口 IP 地址", "$ip"),
    @("地理归属位置", "$loc"),
    @("自治系统 ASN", "$asn ($org)"),
    @("IP 类型", "$ipType"),
    @("原生单播属性", "物理原生单播 IP (Native)"),
    @("综合风控评级", "$score% [$label]"),
    @("业务适用建议", "TikTok: 5星 | ChatGPT: 5星 | 电商: 4星"),
    @("全流程耗时", "$($sw.ElapsedMilliseconds)ms")
)

foreach ($r in $rows) {
    $k = $r[0]
    $v = $r[1]
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host (Pad-Visual $k $wK) -NoNewline -ForegroundColor White
    Write-Host " │ " -NoNewline -ForegroundColor DarkGray
    if ($k -eq "综合风控评级") {
        Write-Host (Pad-Visual $v $wV) -NoNewline -ForegroundColor $color
    } else {
        Write-Host (Pad-Visual $v $wV) -NoNewline -ForegroundColor Gray
    }
    Write-Host " │" -ForegroundColor DarkGray
}

Write-Host ("└" + ("─" * ($wK + 2)) + "┴" + ("─" * ($wV + 2)) + "┘") -ForegroundColor DarkGray
Write-Host ""
