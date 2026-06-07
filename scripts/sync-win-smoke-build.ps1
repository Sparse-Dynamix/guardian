# Sync WSL repo to a native NTFS build tree for Windows cargo (OpenSSL/Frida bindgen).
$ErrorActionPreference = "Stop"

$src = if ($env:GUARDIAN_WSL_SRC) {
    $env:GUARDIAN_WSL_SRC
} else {
    "\\wsl.localhost\Ubuntu-24.04\home\sep\repos\guardian"
}
$dest = Join-Path $env:USERPROFILE "guardian-smoke-build"

Write-Host "Syncing $src -> $dest"
if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
New-Item -ItemType Directory -Path $dest | Out-Null
robocopy $src $dest /E /XD target .git .cache /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed: $LASTEXITCODE" }
Write-Host "Sync complete."
