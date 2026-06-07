#!/usr/bin/env bash
# Ad-hoc codesign helpers for Frida spawn/inject on macOS (smoke + coverage).

sign_guardian_bin() {
    local bin=$1
    if [[ ! -f "$bin" ]]; then
        echo "missing binary to sign: $bin" >&2
        return 1
    fi
    local entitlements
    entitlements="$(mktemp)"
    cat > "$entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.get-task-allow</key>
  <true/>
</dict>
</plist>
EOF
    codesign -s - -f --entitlements "$entitlements" "$bin"
    rm -f "$entitlements"
}

stage_signed_curl() {
    local dest_dir=$1
    local curl_src="${2:-$(command -v curl)}"
    local dest="${dest_dir}/guardian-curl"
    cp -f "$curl_src" "$dest"
    sign_guardian_bin "$dest"
    echo "$dest"
}

stage_signed_sh() {
    local dest_dir=$1
    local sh_src="${2:-$(command -v sh)}"
    local dest="${dest_dir}/guardian-sh"
    cp -f "$sh_src" "$dest"
    sign_guardian_bin "$dest"
    echo "$dest"
}

stage_signed_env() {
    local dest_dir=$1
    local env_src="${2:-$(command -v env)}"
    local dest="${dest_dir}/guardian-env"
    cp -f "$env_src" "$dest"
    sign_guardian_bin "$dest"
    echo "$dest"
}

stage_signed_printenv() {
    local dest_dir=$1
    local src="${2:-$(command -v printenv)}"
    local dest="${dest_dir}/guardian-printenv"
    cp -f "$src" "$dest"
    sign_guardian_bin "$dest"
    echo "$dest"
}

prepare_mac_smoke_path() {
    local bin_dir=$1
    mkdir -p "$bin_dir"
    local signed
    signed="$(stage_signed_curl "$bin_dir")"
    cp -f "$signed" "${bin_dir}/curl"
    local sh_signed
    sh_signed="$(stage_signed_sh "$bin_dir")"
    cp -f "$sh_signed" "${bin_dir}/sh"
    stage_signed_env "$bin_dir" >/dev/null
    stage_signed_printenv "$bin_dir" >/dev/null
    echo "${bin_dir}:${PATH}"
}
