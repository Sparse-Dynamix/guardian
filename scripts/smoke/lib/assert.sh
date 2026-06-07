#!/usr/bin/env bash

assert_exit() {
    local expected=$1 actual=$2
    if [[ "$actual" -ne "$expected" ]]; then
        echo "ASSERT exit: expected ${expected}, got ${actual}" >&2
        return 1
    fi
}

assert_stdout_nonempty() {
    local file=$1
    if [[ ! -s "$file" ]]; then
        echo "ASSERT stdout: expected non-empty output" >&2
        return 1
    fi
}

assert_stderr_jsonl_type() {
    local stderr_file=$1
    local type=$2
    if [[ -z "$type" ]]; then
        if grep -qE '^\{' "$stderr_file" 2>/dev/null; then
            echo "ASSERT stderr: expected no JSONL, found JSON lines" >&2
            return 1
        fi
        return 0
    fi
    if ! grep -q "\"type\":\"${type}\"" "$stderr_file" && \
       ! grep -q "\"type\": \"${type}\"" "$stderr_file"; then
        echo "ASSERT stderr: expected JSONL type ${type}" >&2
        echo "--- stderr ---" >&2
        cat "$stderr_file" >&2
        return 1
    fi
}
