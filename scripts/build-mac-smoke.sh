#!/usr/bin/env bash
# Native macOS release build for smoke testing (run on a Mac host only).

set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "build-mac-smoke.sh must run on macOS (native cargo build)." >&2
    exit 1
fi

# shellcheck source=lib/mac-codesign.sh
source "$(dirname "$0")/lib/mac-codesign.sh"

echo "Building guardian in $(pwd)"
cargo build --release

out="target/release/guardian"
if [[ ! -f "$out" ]]; then
    echo "missing $out" >&2
    exit 1
fi

# Stage libfrida-core.dylib beside the binary when the devkit provides it.
dylib=""
while IFS= read -r -d '' path; do
    if [[ -f "$path/libfrida-core.dylib" ]]; then
        dylib="$path/libfrida-core.dylib"
        break
    fi
done < <(find target/release/build -path "*/frida-sys-*/out" -type d -print0 2>/dev/null)
if [[ -n "$dylib" ]]; then
    cp -f "$dylib" "target/release/libfrida-core.dylib"
    echo "  staged libfrida-core.dylib -> target/release/"
else
    echo "  note: libfrida-core.dylib not found (likely statically linked)"
fi

echo "==> ad-hoc signing guardian (get-task-allow) for Frida"
sign_guardian_bin "$out"

echo "==> staging ad-hoc signed curl for smoke child targets"
stage_signed_curl "target/release" >/dev/null
echo "  staged guardian-curl -> target/release/"

echo "==> staging ad-hoc signed sh for smoke child_spawn"
stage_signed_sh "target/release" >/dev/null
echo "  staged guardian-sh -> target/release/"

echo "==> staging ad-hoc signed env for smoke child_spawn"
stage_signed_env "target/release" >/dev/null
echo "  staged guardian-env -> target/release/"

echo "==> staging ad-hoc signed printenv for env injection tests"
stage_signed_printenv "target/release" >/dev/null
echo "  staged guardian-printenv -> target/release/"

echo "macOS smoke artifact: $out"
