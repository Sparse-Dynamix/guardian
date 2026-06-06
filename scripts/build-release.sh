#!/usr/bin/env bash
# Local cross-compilation for guardian release binaries.
# Requires: rustup, cargo-zigbuild (Linux/macOS targets), cargo-xwin (Windows MSVC).
#
# macOS cross from Linux: use ghcr.io/rust-cross/cargo-zigbuild Docker image
# with SDKROOT preconfigured, or set SDKROOT=/path/to/MacOSX.sdk locally.
#
# Frida auto-download fetches the target-triple devkit at build time.
# Ship libfrida-core beside the binary when dynamically linked:
#   Linux:   libfrida-core.so  (rpath $ORIGIN via build.rs)
#   macOS:   libfrida-core.dylib (@loader_path)
#   Windows: frida-core.dll (same directory as guardian.exe)

set -euo pipefail
cd "$(dirname "$0")/.."

targets=(
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-gnu
    x86_64-apple-darwin
    aarch64-apple-darwin
    x86_64-pc-windows-msvc
)

for target in "${targets[@]}"; do
    echo "==> building $target"
    case "$target" in
        *-pc-windows-msvc)
            cargo xwin build --release --target "$target"
            ;;
        *)
            cargo zigbuild --release --target "$target"
            ;;
    esac
done

echo "Artifacts under target/<triple>/release/"
