#!/usr/bin/env bash
# Cross-build Linux release artifact for smoke testing.
# Windows smoke uses native MSVC build via scripts/build-win-smoke.ps1 (powershell.exe).

set -euo pipefail
cd "$(dirname "$0")/.."

SMOKE_TARGETS=(
    x86_64-unknown-linux-gnu
)

stage_runtime() {
    local target=$1
    local out_dir="target/${target}/release"
    mkdir -p "$out_dir"

    local so=""
    while IFS= read -r -d '' path; do
        if [[ -f "$path/libfrida-core.so" ]]; then
            so="$path/libfrida-core.so"
            break
        fi
    done < <(find target -path "*${target}*/build/frida-sys-*/out" -type d -print0 2>/dev/null)
    if [[ -n "$so" ]]; then
        cp -f "$so" "${out_dir}/libfrida-core.so"
        echo "  staged libfrida-core.so -> ${out_dir}/"
    else
        echo "  note: libfrida-core.so not found for ${target} (likely statically linked)"
    fi
}

for target in "${SMOKE_TARGETS[@]}"; do
    echo "==> building ${target}"
    cargo zigbuild --release --target "$target"
    echo "==> staging runtime for ${target}"
    stage_runtime "$target"
done

echo "Smoke artifacts:"
echo "  target/x86_64-unknown-linux-gnu/release/guardian"
echo "  Windows: %USERPROFILE%\\guardian-smoke-build\\target\\release\\guardian.exe (build-win-smoke.ps1)"
