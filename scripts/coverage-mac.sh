#!/usr/bin/env bash
# Line coverage via cargo-llvm-cov on real integration tests (native macOS).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "coverage-mac.sh must run on macOS." >&2
    exit 1
fi

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
    local archive="$ROOT/.cache/temurin17-jdk.tar.gz"
    curl -fsSL -o "$archive" \
        "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.15%2B6/OpenJDK17U-jdk_x64_mac_hotspot_17.0.15_6.tar.gz"
    tar -xzf "$archive" -C "$ROOT/.cache"
    if [[ -d "$ROOT/.cache/jdk-17.0.15+6/Contents/Home" ]]; then
        rm -rf "$jdk_dir"
        mv "$ROOT/.cache/jdk-17.0.15+6/Contents/Home" "$jdk_dir"
    elif [[ -d "$ROOT/.cache/jdk-17.0.15+6" ]]; then
        rm -rf "$jdk_dir"
        mv "$ROOT/.cache/jdk-17.0.15+6" "$jdk_dir"
    fi
    rm -f "$archive"
}

ensure_portable_jdk
export JAVA_HOME="$ROOT/.cache/jdk-17"
export PATH="$JAVA_HOME/bin:$PATH"

# shellcheck source=lib/mac-codesign.sh
source "$ROOT/scripts/lib/mac-codesign.sh"

chmod +x "$ROOT/scripts/rustc-codesign-wrapper.sh"

cargo llvm-cov clean

eval "$(cargo llvm-cov show-env --export-prefix)"
export CARGO_LLVM_COV_RUSTC_DELEGATE="${RUSTC_WRAPPER:?}"
export RUSTC_WRAPPER="$ROOT/scripts/rustc-codesign-wrapper.sh"
# Omit %m — ad-hoc codesign after link changes the module signature llvm uses for %m.
export LLVM_PROFILE_FILE="$ROOT/target/guardian-%p.profraw"
export PATH="$(prepare_mac_smoke_path "$ROOT/target/debug"):${PATH}"

cargo llvm-cov test --no-rustc-wrapper --features ws-smoke --fail-under-lines 90 -- --test-threads=1
