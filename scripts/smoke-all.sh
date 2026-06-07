#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${SMOKE_SKIP_BUILD:-}" != "1" ]]; then
    ./scripts/build-smoke.sh
    if command -v powershell.exe >/dev/null 2>&1; then
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/build-win-smoke.ps1
    fi
fi

export SMOKE_PLATFORM=linux
./scripts/smoke/run.sh

LINUX_BIN="target/x86_64-unknown-linux-gnu/release/guardian"
WIN_BIN_WIN="$(
    powershell.exe -NoProfile -Command "Join-Path \$env:USERPROFILE 'guardian-smoke-build\\target\\release\\guardian.exe'" 2>/dev/null | tr -d '\r'
)"

if [[ ! -f "$LINUX_BIN" ]]; then
    echo "missing Linux artifact: $LINUX_BIN" >&2
    exit 1
fi

if command -v powershell.exe >/dev/null 2>&1; then
    WIN_BIN_WSL=$(wslpath -u "$WIN_BIN_WIN")
    if [[ ! -f "$WIN_BIN_WSL" ]]; then
        echo "missing Windows artifact: $WIN_BIN_WIN (run scripts/build-win-smoke.ps1)" >&2
        exit 1
    fi
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/smoke/run.ps1 -GuardianBin "$WIN_BIN_WIN"
else
    echo "powershell.exe not found; skipping Windows smoke" >&2
fi

echo "smoke-all complete."
