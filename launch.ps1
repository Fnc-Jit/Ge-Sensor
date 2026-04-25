#Requires -Version 5.1
<#
.SYNOPSIS
  God's Eye — ge-sensor launcher for Windows (Npcap + WinPcap API).

.DESCRIPTION
  Builds ge-sensor, lists libpcap devices (same names the daemon uses), then runs
  with Administrator privileges recommended for live capture.

.PARAMETER Port
  HTTP dashboard / metrics bind port (default 9090).

.PARAMETER Config
  Path to ge-sensor YAML (default configs\ge-sensor.yml).

.EXAMPLE
  # Run from elevated PowerShell:
  cd Sensor\ge-sensor
  .\launch.ps1
#>
[CmdletBinding()]
param(
    [int] $Port = 9090,
    [string] $Config = "configs\ge-sensor.yml"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Get-Ipv4ForNpcapDevice {
    param([string]$NpcapName)
    if ($NpcapName -notmatch '\{([A-Fa-f0-9\-]{36})\}') { return $null }
    $g = $Matches[1]
    try {
        $ad = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceGuid -eq $g } | Select-Object -First 1
        if (-not $ad) { return $null }
        $ip = Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' } |
            Select-Object -ExpandProperty IPAddress -First 1
        return $ip
    } catch { return $null }
}

function Test-SkipForRecommend {
    param([string]$Name, [string]$Desc)
    if ($Name -match 'Loopback|NPF_Lo') { return $true }
    if ($Desc -match '[Ll]oopback') { return $true }
    return $false
}

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║           GOD'S EYE — ge-sensor              ║" -ForegroundColor Cyan
Write-Host "  ║    Network Capture & IDS/IPS Daemon          ║" -ForegroundColor Cyan
Write-Host "  ║              Windows · Npcap               ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "Building ge-sensor..." -ForegroundColor DarkGray
cargo build -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$bin = Join-Path $PSScriptRoot "target\debug\ge-sensor.exe"
if (-not (Test-Path -LiteralPath $bin)) {
    Write-Error "Missing $bin after build."
}

$listOut = & $bin --list-interfaces 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $listOut
    Write-Error "Install Npcap (https://npcap.com/) with 'WinPcap API-compatible Mode' and retry."
}

$lines = @(
    $listOut | ForEach-Object { $_.ToString() } | Where-Object { $_.Trim() -ne "" }
)
if ($lines.Count -eq 0) {
    Write-Error "No capture devices returned. Install Npcap and ensure drivers are loaded."
}

Write-Host "Available capture devices:" -ForegroundColor White
Write-Host "────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ("  {0,2}  {1,-12}  {2,-18}  {3}" -f "#", "interface", "IPv4 address", "note") -ForegroundColor DarkGray
Write-Host "────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

$rows = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($line in $lines) {
    $i++
    $parts = $line -split "`t", 3
    $name = $parts[1]
    $desc = if ($parts.Count -gt 2) { $parts[2] } else { "" }
    $ip = Get-Ipv4ForNpcapDevice -NpcapName $name
    if (-not $ip) { $ip = "—" }
    [void]$rows.Add([pscustomobject]@{ Num = $i; Name = $name; Desc = $desc; Ip = $ip })
}

$defaultNum = 1
$reason = "first device in list"
for ($k = 0; $k -lt $rows.Count; $k++) {
    $r = $rows[$k]
    if (Test-SkipForRecommend -Name $r.Name -Desc $r.Desc) { continue }
    if ($r.Ip -ne "—" -and ($r.Desc -match "Ethernet|Wi-?Fi|Wireless|WLAN" -or $r.Name -match "Ethernet")) {
        $defaultNum = $r.Num
        $reason = "adapter with IPv4 and Ethernet/Wi-Fi role"
        break
    }
}
if ($reason -eq "first device in list") {
    for ($k = 0; $k -lt $rows.Count; $k++) {
        $r = $rows[$k]
        if (Test-SkipForRecommend -Name $r.Name -Desc $r.Desc) { continue }
        if ($r.Ip -ne "—") {
            $defaultNum = $r.Num
            $reason = "first non-loopback interface with IPv4"
            break
        }
    }
}
if ($reason -eq "first device in list") {
    for ($k = 0; $k -lt $rows.Count; $k++) {
        $r = $rows[$k]
        if (-not (Test-SkipForRecommend -Name $r.Name -Desc $r.Desc)) {
            $defaultNum = $r.Num
            $reason = "first non-loopback interface in list"
            break
        }
    }
}

foreach ($r in $rows) {
    $rec = ""
    if ($r.Num -eq $defaultNum) { $rec = "★ recommended" }
    Write-Host ("  {0,2})  {1,-12}  {2,-18}  {3}" -f $r.Num, $r.Name, $r.Ip, $rec) -ForegroundColor White
    if ($r.Desc) {
        Write-Host ("      {0}" -f $r.Desc) -ForegroundColor DarkGray
    }
}
Write-Host "────────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host ("Recommended: #{0} {1} — {2}" -f $defaultNum, $rows[$defaultNum - 1].Name, $reason) -ForegroundColor Yellow
Write-Host ""

$sel = Read-Host "Select device # [$defaultNum]"
if ([string]::IsNullOrWhiteSpace($sel)) { $sel = "$defaultNum" }
if ($sel -notmatch '^\d+$') {
    Write-Error "Enter a number from the list."
}
$idx = [int]$sel
if ($idx -lt 1 -or $idx -gt $names.Count) {
    Write-Error "Invalid selection."
}
$selected = $names[$idx - 1]

Write-Host ""
Write-Host "Selected: $selected" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:  http://localhost:$Port" -ForegroundColor Cyan
Write-Host "  API state:  http://localhost:$Port/api/state" -ForegroundColor Cyan
Write-Host "  Metrics:    http://localhost:$Port/metrics" -ForegroundColor Cyan
Write-Host "  Config:     $Config" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Run PowerShell as Administrator if capture fails." -ForegroundColor Yellow
Write-Host ""

& $bin --config $Config --metrics-addr "0.0.0.0:$Port" --interface $selected
