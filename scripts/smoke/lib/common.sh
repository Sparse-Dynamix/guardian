#!/usr/bin/env bash
# Shared smoke helpers (Linux / WSL / macOS).

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
        case "${SMOKE_PLATFORM:-linux}" in
            darwin) echo "Run ./scripts/build-mac-smoke.sh first." >&2 ;;
            *) echo "Run ./scripts/build-smoke.sh first." >&2 ;;
        esac
        exit 1
    fi
}

smoke_url() {
    echo "${SMOKE_URL:-http://httpbin.org/get}"
}

resolve_curl_ip() {
    local host=$1
    local ip
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1 {print $1}')"
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    ip="$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip_address:/ {print $2; exit}')"
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return
    fi
    dig +short A "$host" 2>/dev/null | awk 'NF && $1 !~ /:/ {print $1; exit}'
}

resolve_shell() {
    local root
    root="$(repo_root)"
    if [[ "${CHILD_SHELL:-}" == "sh -c" ]]; then
        local sh
        sh="$(command -v sh 2>/dev/null || echo /usr/bin/sh)"
        CHILD_SHELL="$sh -c"
    elif [[ "${CHILD_SHELL:-}" == *" -c" ]]; then
        local sh_bin="${CHILD_SHELL% -c}"
        if [[ "$sh_bin" != /* ]]; then
            sh_bin="${root}/${sh_bin}"
        fi
        if [[ ! -f "$sh_bin" ]]; then
            echo "shell binary not found at ${sh_bin}" >&2
            exit 1
        fi
        CHILD_SHELL="$sh_bin -c"
    fi
}

resolve_child_wrapper() {
    local root
    root="$(repo_root)"
    if [[ -z "${CHILD_WRAPPER:-}" ]]; then
        return
    fi
    if [[ "$CHILD_WRAPPER" != /* ]]; then
        CHILD_WRAPPER="${root}/${CHILD_WRAPPER}"
    fi
    if [[ ! -f "$CHILD_WRAPPER" ]]; then
        echo "child wrapper not found at ${CHILD_WRAPPER}" >&2
        exit 1
    fi
}

resolve_curl() {
    local root
    root="$(repo_root)"
    if [[ -n "${CURL:-}" ]]; then
        if [[ "$CURL" != /* && "$CURL" != *curl.exe ]]; then
            CURL="${root}/${CURL}"
        fi
        if [[ ! -f "$CURL" ]]; then
            echo "curl binary not found at ${CURL}" >&2
            exit 1
        fi
        return
    fi
    CURL="$(command -v curl 2>/dev/null || true)"
    if [[ -z "$CURL" ]]; then
        echo "curl not found in PATH" >&2
        exit 1
    fi
}

preflight() {
    resolve_curl
    resolve_child_wrapper
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
