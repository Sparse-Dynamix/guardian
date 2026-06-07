#!/usr/bin/env bash
# Line coverage via cargo-llvm-cov on real integration tests (Linux/WSL).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "cargo-llvm-cov not found. Install: cargo install cargo-llvm-cov" >&2
    echo "Also: rustup component add llvm-tools-preview" >&2
    exit 1
fi

ensure_portable_jdk() {
    local jdk_dir="$ROOT/.cache/jdk-17"
    if [[ -x "$jdk_dir/bin/keytool" ]]; then
        return 0
    fi
    echo "Downloading portable JDK 17 for java truststore integration coverage..."
    mkdir -p "$ROOT/.cache"
    local archive="$ROOT/.cache/temurin17-jdk.tgz"
    curl -fsSL -o "$archive" \
        "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_linux_hotspot_17.0.15_6.tar.gz"
    tar -xzf "$archive" -C "$ROOT/.cache"
    if [[ -d "$ROOT/.cache/jdk-17.0.15+6" ]]; then
        rm -rf "$jdk_dir"
        mv "$ROOT/.cache/jdk-17.0.15+6" "$jdk_dir"
    fi
    rm -f "$archive"
}

ensure_portable_jdk
export JAVA_HOME="$ROOT/.cache/jdk-17"
export PATH="$JAVA_HOME/bin:$PATH"

cargo llvm-cov clean
cargo llvm-cov --features ws-smoke --fail-under-lines 90 --target x86_64-unknown-linux-gnu
