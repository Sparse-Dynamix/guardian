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
    inner="${CURL} -sSf"
    if ((${#RESOLVE_ARGS[@]})); then
        inner+=" ${RESOLVE_ARGS[*]}"
    fi
    inner+=" '${URL}'"
    local -a args=("$GUARDIAN_BIN")
    if [[ "$silent" == "true" ]]; then
        args+=(--silent)
    fi
    args+=(--ca-dir "$ca_dir" --)
    # shellcheck disable=SC2206
    args+=(${CHILD_SHELL:-sh -c} "$inner")
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

while IFS='|' read -r name command silent expect_exit expect_type; do
    run_case "$name" "$command" "$silent" "$expect_exit" "$expect_type"
done < <(python3 - <<'PY'
import tomllib
from pathlib import Path
cases = tomllib.loads(Path("scripts/smoke/cases.toml").read_text())["case"]
for c in cases:
    print("|".join([
        c["name"],
        c["command"],
        str(c.get("silent", False)).lower(),
        str(c["expect_exit"]),
        c.get("expect_jsonl_type", ""),
    ]))
PY
)

echo "All smoke cases passed."
