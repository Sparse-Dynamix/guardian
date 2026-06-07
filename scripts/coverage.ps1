# Line coverage via cargo-llvm-cov on real integration tests (native Windows MSVC).

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not (Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue)) {
    throw "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov; rustup component add llvm-tools-preview"
}

cargo llvm-cov clean
cargo llvm-cov --features ws-smoke --fail-under-lines 90
