# Prepares a Windows laptop so that UVPN running in WSL can accept connections
# (the server, or the listening peer). Run as administrator; safe to run again.
# Easiest: double-click scripts\windows-setup.bat, which asks for administrator rights.

$ErrorActionPreference = 'Stop'
$port = 51820
$wslVmCreatorId = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Host '[-] Run this as administrator (double-click windows-setup.bat).'
    exit 1
}
if (-not (Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue)) {
    Write-Host '[-] This Windows has no Hyper-V firewall: mirrored WSL networking needs Windows 11 22H2 or newer.'
    exit 1
}

# 1. Hyper-V firewall: filters traffic into WSL in mirrored mode.
if (Get-NetFirewallHyperVRule -Name UVPN -ErrorAction SilentlyContinue) {
    Write-Host '[ok] Hyper-V firewall rule UVPN already exists'
} else {
    New-NetFirewallHyperVRule -Name UVPN -DisplayName UVPN -Direction Inbound -VMCreatorId $wslVmCreatorId `
        -Protocol UDP -LocalPorts $port | Out-Null
    Write-Host "[+] Hyper-V firewall: inbound UDP $port allowed into WSL"
}

# 2. Windows Defender Firewall.
if (Get-NetFirewallRule -DisplayName UVPN -ErrorAction SilentlyContinue) {
    Write-Host '[ok] Windows Defender Firewall rule UVPN already exists'
} else {
    New-NetFirewallRule -DisplayName UVPN -Direction Inbound -Protocol UDP -LocalPort $port -Action Allow | Out-Null
    Write-Host "[+] Windows Defender Firewall: inbound UDP $port allowed"
}

# 3. Mirrored networking: WSL gets the laptop's own Wi-Fi address instead of a private NAT one.
$cfg = Join-Path $env:USERPROFILE '.wslconfig'
$lines = New-Object System.Collections.Generic.List[string]
if (Test-Path $cfg) { foreach ($line in @(Get-Content $cfg)) { $lines.Add($line) } }
$mode = $lines | Where-Object { $_ -match '^\s*networkingMode\s*=' } | Select-Object -First 1
if ($mode -match '=\s*mirrored\s*$') {
    Write-Host "[ok] $cfg already sets networkingMode=mirrored"
} elseif ($mode) {
    Write-Host "[!] $cfg sets '$($mode.Trim())': change it to networkingMode=mirrored by hand"
} else {
    $section = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*\[wsl2\]\s*$') { $section = $i; break }
    }
    if ($section -ge 0) {
        $lines.Insert($section + 1, 'networkingMode=mirrored')
    } else {
        $lines.Add('[wsl2]')
        $lines.Add('networkingMode=mirrored')
    }
    $backup = ''
    if (Test-Path $cfg) { Copy-Item $cfg "$cfg.bak" -Force; $backup = " (old copy: $cfg.bak)" }
    [IO.File]::WriteAllLines($cfg, $lines)
    Write-Host "[+] Added networkingMode=mirrored to $cfg$backup"
    Write-Host '[!] Restart WSL to apply it: run  wsl --shutdown  then open Ubuntu again (closes all WSL windows)'
}

# 4. The addresses the other machine can connect to.
Write-Host ''
Write-Host 'This laptop''s addresses (give the Wi-Fi one to the other machine):'
Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -notmatch 'Loopback|vEthernet' -and $_.IPAddress -notlike '169.254.*' } |
    ForEach-Object { Write-Host ("    {0,-28} {1}" -f $_.InterfaceAlias, $_.IPAddress) }
