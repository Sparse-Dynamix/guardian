#!/usr/bin/env bash
# Shared smoke helpers (Linux / WSL).

smoke_root() {
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
}

repo_root() {
    cd "$(smoke_root)/../.." && pwd
}

load_platform_env() {
    local platform="${SMOKE_PLATFORM:-linux}"
    local env_file
    local saved_bin="${GUARDIAN_BIN:-}"
    env_file="$(smoke_root)/platforms/${platform}.env"
    if [[ ! -f "$env_file" ]]; then
        echo "missing platform env: $env_file" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$env_file"
    if [[ -n "$saved_bin" ]]; then
        GUARDIAN_BIN="$saved_bin"
    fi
}

resolve_guardian_bin() {
    local root
    root="$(repo_root)"
    if [[ -n "${GUARDIAN_BIN:-}" ]]; then
        if [[ "$GUARDIAN_BIN" != /* ]]; then
            GUARDIAN_BIN="${root}/${GUARDIAN_BIN}"
        fi
    else
        GUARDIAN_BIN="${root}/target/x86_64-unknown-linux-gnu/release/guardian"
    fi
    if [[ ! -f "$GUARDIAN_BIN" ]]; then
        echo "guardian binary not found at ${GUARDIAN_BIN}" >&2
        echo "Run ./scripts/build-smoke.sh first." >&2
        exit 1
    fi
}

smoke_url() {
    echo "${SMOKE_URL:-http://httpbin.org/get}"
}

resolve_curl_ip() {
    local host=$1
    getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1 {print $1}'
}

resolve_shell() {
    if [[ "${CHILD_SHELL:-}" == "sh -c" ]]; then
        local sh
        sh="$(command -v sh 2>/dev/null || echo /usr/bin/sh)"
        CHILD_SHELL="$sh -c"
    fi
}

resolve_curl() {
    if [[ -n "${CURL:-}" ]] && [[ "$CURL" == /* || "$CURL" == *curl.exe ]]; then
        return
    fi
    local name="${CURL:-curl}"
    CURL="$(command -v "$name" 2>/dev/null || true)"
    if [[ -z "$CURL" ]]; then
        echo "${name} not found in PATH" >&2
        exit 1
    fi
}

preflight() {
    resolve_curl
    resolve_shell
    if [[ -r /proc/sys/kernel/yama/ptrace_scope ]]; then
        local scope
        scope=$(< /proc/sys/kernel/yama/ptrace_scope)
        if [[ "$scope" -ge 2 ]]; then
            echo "warning: ptrace_scope=${scope} may block Frida injection" >&2
        fi
    fi
}

make_ca_dir() {
    mktemp -d "${TMPDIR:-/tmp}/guardian-smoke-ca.XXXXXX"
}
