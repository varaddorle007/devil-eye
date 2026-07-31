# Package a local Windows release zip (offline / default features).
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1
# Optional live build (requires Npcap SDK on LIB):
#   powershell -ExecutionPolicy Bypass -File scripts\package-windows.ps1 -Live

param(
    [switch]$Live
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$OutDir = Join-Path $Root "dist\windows"
$ZipName = "devil-eye-$Version-windows-x86_64.zip"

Write-Host "Building devil-eye $Version (Live=$Live)..."

if ($Live) {
    if (-not $env:LIB) {
        $sdk = Join-Path $env:USERPROFILE "npcap-sdk\Lib\x64"
        if (Test-Path $sdk) {
            $env:LIB = "$sdk;$env:LIB"
        }
    }
    cargo build --release --features live
} else {
    cargo build --release
}

if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Copy-Item "target\release\devil-eye.exe" $OutDir
Copy-Item "README.md", "LICENSE", "CHANGELOG.md", "examples\scope.lab.json" $OutDir

$ZipPath = Join-Path $Root "dist\$ZipName"
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path (Join-Path $OutDir "*") -DestinationPath $ZipPath

Write-Host "Packed: $ZipPath"
Get-Item $ZipPath | Format-List Name, Length, FullName
