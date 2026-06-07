# Native Windows release build for smoke testing (run from WSL via powershell.exe).
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

& (Join-Path $RepoRoot "scripts/sync-win-smoke-build.ps1")

$dest = Join-Path $env:USERPROFILE "guardian-smoke-build"
$llvm = "C:\Program Files\LLVM\bin"
$perl = "C:\Strawberry\perl\bin"
$env:Path = "$perl;$llvm;" + $env:Path
$env:LIBCLANG_PATH = $llvm

Set-Location $dest
Write-Host "Building guardian.exe in $dest"
cargo build --release
$out = Join-Path $dest "target\release\guardian.exe"
if (-not (Test-Path -LiteralPath $out)) { throw "missing $out" }

# Stage frida-core.dll beside the exe when the devkit provides it.
$buildRoot = Join-Path $dest "target\release\build"
Get-ChildItem -Path $buildRoot -Recurse -Filter "frida-core.dll" -ErrorAction SilentlyContinue |
    Select-Object -First 1 |
    ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $dest "target\release\frida-core.dll") -Force
        Write-Host "Staged frida-core.dll -> target\release\"
    }

Write-Host "Windows smoke artifact: $out"
