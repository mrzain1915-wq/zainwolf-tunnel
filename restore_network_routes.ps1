param([switch]$NonInteractive)
$ErrorActionPreference = 'Continue'
$state = Join-Path $env:APPDATA 'ZainWolfTunnel\full_traffic_routes.json'
if (-not (Test-Path -LiteralPath $state)) {
    Write-Host 'No saved ZainWolf Tunnel route recovery file exists. Nothing to do.' -ForegroundColor Green
    exit 0
}
try {
    $data = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
    $routes = @($data.routes)
    [array]::Reverse($routes)
    $failed = @()
    foreach ($r in $routes) {
        Write-Host "Removing route $($r.destination) mask $($r.mask) via $($r.gateway)"
        & route.exe DELETE $r.destination MASK $r.mask $r.gateway IF ([string]$r.interface) | Out-Host
        $prefixLength = switch ([string]$r.mask) {
            '255.255.255.255' { 32 }
            '128.0.0.0' { 1 }
            default { 0 }
        }
        $prefix = "$($r.destination)/$prefixLength"
        $left = Get-NetRoute -DestinationPrefix $prefix -AddressFamily IPv4 -ErrorAction SilentlyContinue |
          Where-Object { $_.InterfaceIndex -eq [int]$r.interface -and $_.NextHop -eq [string]$r.gateway }
        if ($left) { $failed += "$prefix via $($r.gateway) (interface $($r.interface))" }
    }
    if ($failed.Count -gt 0) {
        Write-Host 'Some routes remain; recovery state file has been kept:' -ForegroundColor Red
        $failed | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
        exit 1
    }
    Remove-Item -LiteralPath $state -Force
    Write-Host 'Route recovery completed. Try your internet connection again.' -ForegroundColor Green
}
catch {
    Write-Host "Recovery failed: $_" -ForegroundColor Red
    Write-Host "Keep this file for diagnosis: $state"
    exit 1
}
if (-not $NonInteractive) { Read-Host 'Press Enter to close' }
