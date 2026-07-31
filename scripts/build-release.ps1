# Build Devil Eye release with live capture (Npcap) enabled.
# Prereq: install Npcap runtime from https://npcap.com/
# Optional: Npcap SDK — this script downloads the SDK into .npcap-sdk if missing.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$sdkRoot = Join-Path (Get-Location) ".npcap-sdk"
$libDir = Join-Path $sdkRoot "Lib\x64"
if (-not (Test-Path (Join-Path $libDir "wpcap.lib"))) {
    Write-Host "Downloading Npcap SDK 1.13..."
    $zip = Join-Path $env:TEMP "npcap-sdk-1.13.zip"
    Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-sdk-1.13.zip" -OutFile $zip
    if (Test-Path $sdkRoot) { Remove-Item -Recurse -Force $sdkRoot }
    Expand-Archive -Path $zip -DestinationPath $sdkRoot
}

$env:LIB = "$libDir;$env:LIB"
Write-Host "LIB=$env:LIB"
cargo build --release
Write-Host ""
Write-Host "Built: .\target\release\devil-eye.exe (live capture enabled)"
Write-Host "Install Npcap runtime, then run elevated for live -i / -D."
