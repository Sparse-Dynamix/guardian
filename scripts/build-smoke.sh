#!/usr/bin/env bash
# Cross-build Linux release artifact for smoke testing.
# Windows smoke uses native MSVC build via scripts/build-win-smoke.ps1 (powershell.exe).

set -euo pipefail
cd "$(dirname "$0")/.."

SMOKE_TARGETS=(
    x86_64-unknown-linux-gnu
)

if [[ "${SMOKE_CROSS_WINDOWS:-}" == "1" ]]; then
    SMOKE_TARGETS+=(x86_64-pc-windows-msvc)
fi

stage_runtime() {
    local target=$1
    local out_dir="target/${target}/release"
    mkdir -p "$out_dir"

    case "$target" in
        *-pc-windows-msvc)
            local dll=""
            while IFS= read -r -d '' path; do
                if [[ -f "$path/frida-core.dll" ]]; then
                    dll="$path/frida-core.dll"
                    break
                fi
            done < <(find target -path "*${target}*/build/frida-sys-*/out" -type d -print0 2>/dev/null)
            if [[ -n "$dll" ]]; then
                cp -f "$dll" "${out_dir}/frida-core.dll"
                echo "  staged frida-core.dll -> ${out_dir}/"
            else
                echo "  note: frida-core.dll not found for ${target}"
            fi
            ;;
        *-linux-gnu)
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
            ;;
    esac
}

for target in "${SMOKE_TARGETS[@]}"; do
    echo "==> building ${target}"
    case "$target" in
        *-pc-windows-msvc)
            cargo xwin build --release --target "$target"
            ;;
        *)
            cargo zigbuild --release --target "$target"
            ;;
    esac
    echo "==> staging runtime for ${target}"
    stage_runtime "$target"
done

echo "Smoke artifacts:"
echo "  target/x86_64-unknown-linux-gnu/release/guardian"
if [[ "${SMOKE_CROSS_WINDOWS:-}" == "1" ]]; then
    echo "  target/x86_64-pc-windows-msvc/release/guardian.exe"
else
    echo "  Windows: run scripts/build-win-smoke.ps1 on the Windows host"
fi
