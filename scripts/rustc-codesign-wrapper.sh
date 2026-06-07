#!/usr/bin/env bash
# Chain cargo-llvm-cov's RUSTC_WRAPPER and ad-hoc sign guardian binaries after link.

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/mac-codesign.sh
source "$ROOT/scripts/lib/mac-codesign.sh"

args=("$@")
out=""
for ((i = 0; i < ${#args[@]}; i++)); do
    if [[ "${args[i]}" == "-o" && $((i + 1)) -lt ${#args[@]} ]]; then
        out="${args[i+1]}"
    fi
done

delegate="${CARGO_LLVM_COV_RUSTC_DELEGATE:?set CARGO_LLVM_COV_RUSTC_DELEGATE to cargo-llvm-cov from show-env}"
"$delegate" "$@"
status=$?

if [[ $status -eq 0 && -n "$out" && -f "$out" ]]; then
    case "$(basename "$out")" in
        guardian | guardian-ws-smoke)
            sign_guardian_bin "$out"
            bin_dir="$(dirname "$out")"
            prepare_mac_smoke_path "$bin_dir" >/dev/null
            ;;
    esac
fi

exit "$status"
