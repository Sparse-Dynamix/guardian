#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/assert.sh
source "${SCRIPT_DIR}/lib/assert.sh"

load_platform_env
resolve_guardian_bin
preflight

ROOT="$(repo_root)"
cd "$ROOT"

URL="$(smoke_url)"
HOST="${URL#*://}"
HOST="${HOST%%/*}"
IP="$(resolve_curl_ip "$HOST")"
RESOLVE_ARGS=()
if [[ -n "$IP" ]]; then
    if [[ "$URL" == https://* ]]; then
        RESOLVE_ARGS=(--resolve "${HOST}:443:${IP}")
    else
        RESOLVE_ARGS=(--resolve "${HOST}:80:${IP}")
    fi
fi

LAST_EXIT=0
LAST_OUT=""
LAST_ERR=""

run_direct() {
    local silent=$1
    local ca_dir
    ca_dir="$(make_ca_dir)"
    LAST_OUT="$(mktemp)"
    LAST_ERR="$(mktemp)"
    local -a args=("$GUARDIAN_BIN")
    if [[ "$silent" == "true" ]]; then
        args+=(--silent)
    fi
    args+=(--ca-dir "$ca_dir" -- "$CURL" -sSf)
    if ((${#RESOLVE_ARGS[@]})); then
        args+=("${RESOLVE_ARGS[@]}")
    fi
    args+=("$URL")
    set +e
    "${args[@]}" >"$LAST_OUT" 2>"$LAST_ERR"
    LAST_EXIT=$?
    set -e
}

run_child() {
    local silent=$1
    local ca_dir inner
    ca_dir="$(make_ca_dir)"
    LAST_OUT="$(mktemp)"
    LAST_ERR="$(mktemp)"
    local -a args=("$GUARDIAN_BIN")
    if [[ "$silent" == "true" ]]; then
        args+=(--silent)
    fi
    args+=(--ca-dir "$ca_dir" --)
    if [[ -n "${CHILD_WRAPPER:-}" ]]; then
        args+=("$CHILD_WRAPPER" "$CURL" -sSf)
        if ((${#RESOLVE_ARGS[@]})); then
            args+=("${RESOLVE_ARGS[@]}")
        fi
        args+=("$URL")
    else
        inner="${CURL} -sSf"
        if ((${#RESOLVE_ARGS[@]})); then
            inner+=" ${RESOLVE_ARGS[*]}"
        fi
        inner+=" '${URL}'"
        # shellcheck disable=SC2206
        args+=(${CHILD_SHELL:-sh -c} "$inner")
    fi
    set +e
    "${args[@]}" >"$LAST_OUT" 2>"$LAST_ERR"
    LAST_EXIT=$?
    set -e
}

run_case() {
    local name=$1 command=$2 silent=$3 expect_exit=$4 expect_type=$5
    echo "==> smoke case: ${name}"
    case "$command" in
        direct) run_direct "$silent" ;;
        child) run_child "$silent" ;;
        *) echo "unknown command: $command" >&2; return 1 ;;
    esac
    assert_exit "$expect_exit" "$LAST_EXIT"
    assert_stdout_nonempty "$LAST_OUT"
    assert_stderr_jsonl_type "$LAST_ERR" "$expect_type"
    rm -f "$LAST_OUT" "$LAST_ERR"
    echo "    ok"
}

# Minimal TOML parse for our fixed schema (no Python; matches run.ps1 on Windows).
while IFS='|' read -r name command silent expect_exit expect_type; do
    [[ -z "$name" ]] && continue
    run_case "$name" "$command" "$silent" "$expect_exit" "$expect_type"
done < <(
    awk '
        function flush() {
            if (name != "") {
                print name "|" command "|" silent "|" expect_exit "|" expect_type
            }
        }
        /^\[\[case\]\]/ {
            flush()
            name=expect_type=""
            command="direct"
            silent="false"
            expect_exit=0
            next
        }
        /^name = "/ {
            line=$0
            sub(/^name = "/, "", line)
            sub(/"$/, "", line)
            name=line
        }
        /^command = "/ {
            line=$0
            sub(/^command = "/, "", line)
            sub(/"$/, "", line)
            command=line
        }
        /^silent = true/ { silent="true" }
        /^expect_exit = / {
            if (match($0, /[0-9]+/)) {
                expect_exit=substr($0, RSTART, RLENGTH)
            }
        }
        /^expect_jsonl_type = "/ {
            line=$0
            sub(/^expect_jsonl_type = "/, "", line)
            sub(/"$/, "", line)
            expect_type=line
        }
        END { flush() }
    ' "${SCRIPT_DIR}/cases.toml"
)

echo "All smoke cases passed."
