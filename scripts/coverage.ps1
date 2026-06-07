# Line coverage via cargo-llvm-cov on real integration tests (native Windows MSVC).

$ErrorActionPreference = "Stop"
$ScriptDir = $PSScriptRoot
$RepoRoot = Split-Path -Parent $ScriptDir

# When invoked from WSL, sync and measure on the native NTFS build tree.
if ($RepoRoot -match '^\\\\wsl\.') {
    & (Join-Path $ScriptDir "sync-win-smoke-build.ps1")
    $RepoRoot = Join-Path $env:USERPROFILE "guardian-smoke-build"
}

Set-Location $RepoRoot

. (Join-Path $ScriptDir "lib\win-msvc-env.ps1")

if (-not (Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue)) {
    throw "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview"
}

function Ensure-PortableJdk {
    $jdkDir = Join-Path $RepoRoot ".cache\jdk-17"
    if (Test-Path (Join-Path $jdkDir "bin\keytool.exe")) { return }
    Write-Host "Downloading portable JDK 17 for java truststore integration coverage..."
    $cache = Join-Path $RepoRoot ".cache"
    New-Item -ItemType Directory -Force -Path $cache | Out-Null
    $zip = Join-Path $cache "temurin17-jdk.zip"
    $url = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_windows_hotspot_17.0.15_6.zip"
    Invoke-WebRequest -Uri $url -OutFile $zip
    $extractRoot = Join-Path $cache "jdk-extract"
    if (Test-Path $extractRoot) { Remove-Item -Recurse -Force $extractRoot }
    Expand-Archive -Path $zip -DestinationPath $extractRoot -Force
    Remove-Item -Force $zip
    $extracted = Get-ChildItem -Path $extractRoot -Directory | Where-Object { $_.Name -like "jdk-17*" } | Select-Object -First 1
    if (-not $extracted) { throw "JDK extract failed" }
    if (Test-Path $jdkDir) { Remove-Item -Recurse -Force $jdkDir }
    Move-Item -LiteralPath $extracted.FullName -Destination $jdkDir
    Remove-Item -Recurse -Force $extractRoot
}

Ensure-PortableJdk
$env:JAVA_HOME = Join-Path $RepoRoot ".cache\jdk-17"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

cargo llvm-cov clean
cargo llvm-cov --features ws-smoke --fail-under-lines 90
