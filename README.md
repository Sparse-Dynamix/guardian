# Guardian

[![nightly CI](https://img.shields.io/github/actions/workflow/status/Sparse-Dynamix/guardian/nightly.yml?branch=main&label=nightly&logo=github)](https://github.com/Sparse-Dynamix/guardian/actions/workflows/nightly.yml)

| Platform | Download |
|----------|----------|
| Linux x86_64 | [`guardian-*-linux-x86_64.tar.gz`](https://github.com/Sparse-Dynamix/guardian/releases/download/nightly/guardian-1.0.0-beta-linux-x86_64.tar.gz) |
| Linux aarch64 | [`guardian-*-linux-aarch64.tar.gz`](https://github.com/Sparse-Dynamix/guardian/releases/download/nightly/guardian-1.0.0-beta-linux-aarch64.tar.gz) |
| macOS x86_64 | [`guardian-*-mac-x86_64.tar.gz`](https://github.com/Sparse-Dynamix/guardian/releases/download/nightly/guardian-1.0.0-beta-mac-x86_64.tar.gz) |
| macOS aarch64 | [`guardian-*-mac-aarch64.tar.gz`](https://github.com/Sparse-Dynamix/guardian/releases/download/nightly/guardian-1.0.0-beta-mac-aarch64.tar.gz) |
| Windows x86_64 | [`guardian-*-win-x86_64.zip`](https://github.com/Sparse-Dynamix/guardian/releases/download/nightly/guardian-1.0.0-beta-win-x86_64.zip) |

> **1.0.0-beta** — experimental hardening aid, not a safety product. Read [`guardian security-notes`](SECURITY.md) and [NOTICE.txt](NOTICE.txt) before use.

Put a safety filter between your AI agent and the outside world.

Guardian wraps the program your agent runs (Cursor, Claude Code, OpenCode, a custom script, etc.). When filtering is on, it intercepts **HTTP, HTTPS, WebSocket, and secure WebSocket (WS/WSS)** traffic from that program, sends each response to your filter for approval, and only passes through what the filter allows. It can also filter **tool-call payloads** before they reach the agent.

Without a filter URL, Guardian is a thin passthrough — useful for testing the wrapper, not for safety.

## Quick start

You need a **filter URL** (`--tpf`): a server that accepts `POST` requests and returns **HTTP 200** to allow content, or **any other status** to block it. ([Filter contract](#filter-contract) below.)

### 1. Download

Get the latest build from **[Releases → nightly](https://github.com/Sparse-Dynamix/guardian/releases/tag/nightly)**.

| OS | Arch | File | Binary |
|----|------|------|--------|
| Linux | x86_64, aarch64 | `guardian-*-linux-{arch}.tar.gz` | `guardian` |
| macOS | x86_64, aarch64 | `guardian-*-mac-{arch}.tar.gz` | `guardian` |
| Windows | x86_64 | `guardian-*-win-x86_64.zip` | `guardian.exe` |

CI builds all five targets on every push to `main` and publishes them to the [nightly](https://github.com/Sparse-Dynamix/guardian/releases/tag/nightly) release.

Each archive contains the binary, `LICENSE`, and `NOTICE.txt`. macOS builds also include `entitlements.plist` for ad-hoc signing.

**Frida is inside the binary.** Release builds statically link Frida Core via the Rust `frida` crate (`auto-download` devkit). There is no separate `libfrida-core.so`, `.dylib`, or `.dll` to install — the `guardian` executable is self-contained for MITM hooking. `mkcert` is embedded the same way for CA trust-store commands. See [NOTICE.txt](NOTICE.txt) for third-party attributions.

Extract the archive and run the binary from that folder.

### 2. Install

```bash
# Linux (pick the archive matching your CPU — x86_64 or aarch64)
mkdir -p ~/guardian && cd ~/guardian
gh release download nightly -R Sparse-Dynamix/guardian -p 'guardian-*-linux-*.tar.gz'
tar -xzf guardian-*-linux-*.tar.gz
chmod +x guardian-*-linux-*/guardian
```

```bash
# macOS (sign once so macOS will run the binary; pick x86_64 or aarch64)
mkdir -p ~/guardian && cd ~/guardian
gh release download nightly -R Sparse-Dynamix/guardian -p 'guardian-*-mac-*.tar.gz'
tar -xzf guardian-*-mac-*.tar.gz
codesign -s - -f --entitlements guardian-*-mac-*/entitlements.plist guardian-*-mac-*/guardian
```

```powershell
# Windows (PowerShell)
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\guardian" | Out-Null
Set-Location "$env:USERPROFILE\guardian"
gh release download nightly -R Sparse-Dynamix/guardian -p '*win*'
Expand-Archive -Path (Get-ChildItem guardian-*-win-x86_64.zip).Name -DestinationPath . -Force
```

No `gh` CLI? Download the matching archive from the [nightly release](https://github.com/Sparse-Dynamix/guardian/releases/tag/nightly) page and extract it manually.

Point your shell at the binary (adjust the folder name to match what you extracted):

```bash
# macOS / Linux
export GUARDIAN_BIN=~/guardian/guardian-*-*/guardian   # or guardian.exe on Windows
```

```powershell
# Windows
$env:GUARDIAN_BIN = "$env:USERPROFILE\guardian\guardian-*-win-x86_64\guardian.exe"
```

### 3. Run your agent through Guardian

```bash
$GUARDIAN_BIN --tpf https://your-filter.example/check -- your-agent-command --args
```

Examples:

```bash
$GUARDIAN_BIN --tpf https://your-filter.example/check -- opencode
$GUARDIAN_BIN --tpf https://your-filter.example/check -- cursor-agent ...
```

Set the filter once via environment variable if you prefer:

```bash
export GUARDIAN_TRYPANOPHOBE_FILTER=https://your-filter.example/check
$GUARDIAN_BIN --tpf "$GUARDIAN_TRYPANOPHOBE_FILTER" -- your-agent-command
```

**Harness notes for integrators:**

- The wrapped program should not use stdin (`stdin: 'ignore'` / `Stdio::null()`). Payload mode uses stdin instead — see below.
- **SSE streaming** (`text/event-stream`) is gated per event: each event waits for a `--tpf` round-trip (default timeout 10s) before the harness sees it.

### 4. HTTPS (encrypted traffic)

Guardian decrypts HTTPS so it can inspect responses, using a local certificate authority stored in `~/.guardian`. Pick the path that fits your setup:

**Most CLI agents (no admin)** — Guardian passes trust to the wrapped program via environment variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, etc.). Add `--skip-cert-regen` so the same CA is reused every run:

```bash
$GUARDIAN_BIN --skip-cert-regen --tpf https://your-filter.example/check -- your-agent-command
```

**Browsers, Java, or anything that only trusts the system certificate store** — install the CA once with admin rights:

```bash
sudo $GUARDIAN_BIN install-system
$GUARDIAN_BIN check-system          # should report the CA is trusted
```

```powershell
# Windows (Administrator PowerShell)
& $env:GUARDIAN_BIN install-system
& $env:GUARDIAN_BIN check-system
```

Remove when done: `guardian remove-system` or `sudo guardian clean`.

### 5. Verify

```bash
$GUARDIAN_BIN --version
$GUARDIAN_BIN --skip-cert-regen --tpf https://your-filter.example/check -- curl -s https://httpbin.org/get
```

If the filter returns non-200, the response is blocked and the agent never sees it.

## Payload mode (tool calls)

Filter a tool-call payload directly instead of wrapping a child process:

```bash
$GUARDIAN_BIN --tpf https://your-filter.example/check --payload '{"tool":"read_file","path":"..."}'
echo '{"tool":"read_file"}' | $GUARDIAN_BIN --tpf https://your-filter.example/check
```

Do not pass a child program after `--` in payload mode.

## Agent setup checklist

If you are an AI agent installing Guardian for a user, follow these steps in order:

1. **Detect OS and CPU** (Linux, macOS, or Windows; on Linux/macOS pick x86_64 or aarch64).
2. **Download** the matching `guardian-*-{platform}-{arch}` archive from [nightly](https://github.com/Sparse-Dynamix/guardian/releases/tag/nightly).
3. **Extract** to a stable path (e.g. `~/guardian` or `%USERPROFILE%\guardian`).
4. **macOS only:** run `codesign` with the bundled `entitlements.plist` (see step 2 above).
5. **Set `GUARDIAN_BIN`** to the full path of `guardian` / `guardian.exe`. No separate Frida install is required — it is linked into the binary.
6. **Ask the user for their filter URL** (`--tpf`) or read `GUARDIAN_TRYPANOPHOBE_FILTER` if already set.
7. **Wrap the user's agent command:** `guardian --skip-cert-regen --tpf <URL> -- <their-agent-cmd>`.
8. **If HTTPS fails** with certificate errors, run `install-system` + `check-system` (requires user approval for admin).
9. **Confirm** with `guardian --version` and a test request through the filter.

Common flags: `--tps` replaces allowed content with the filter's response body; `--ca-dir` changes where the CA is stored; `guardian --help` for the full list.

## Filter contract

Guardian targets the [trypanophobe](https://github.com/Sparse-Dynamix/trypanophobe) filter API. Set `--tpf` to the full path (e.g. `http://127.0.0.1:8080/api/filter` or `GUARDIAN_TRYPANOPHOBE_FILTER`).

Your filter receives `POST` with **raw bytes** as the body and:

- **`url` query (required)** — source URL for blocklist checks and format hints
- **`format=md`** when `--tps` is set (default `og` otherwise)
- **`Content-Type`** when known (upstream response type or payload type)

Responses:

- **`200`** → allow (forward to the agent)
- **`206`** → partial safe markdown (`--tps` + `format=md` only)
- **`406`** → block; Guardian surfaces the filter `reason`, `stage`, and `detail` in a clear message
- **Other statuses** → block with the configured fallback message (`block_message`)

With `--tps`, allowed `200`/`206` response bodies and headers **replace** what the agent would have seen.

WebSocket server→client text and binary frames are checked the same way.

## Modes at a glance

![Wrapper mode](assets/wrapper-mode.png)

Wrap a child process — intercepts HTTP(S) and WS(S) from that process when `--tpf` is set.

![Payload mode](assets/payload-mode.png)

Filter tool-call JSON via `--payload` or piped stdin.

## Limitations

Guardian filters **hooked HTTP/HTTPS/WS/WSS** and optional tool payloads — not all traffic from the child process.

- **Loopback** (`127.0.0.0/8`, `::1`, etc.) bypasses the connect hook; local services are not sent to `--tpf`.
- **Default `ignored_ports`** leave SSH, mail, databases, LDAP, RDP, and similar TCP unhooked unless you customize `--filter` or `--ignored-ports` (see `config/guardian.toml`).
- **Non-HTTP TCP** on hooked ports is tunneled through the proxy without content filtering.
- **QUIC/UDP** is not intercepted.
- **Certificate pinning** in the child blocks MITM; see [SECURITY.md](SECURITY.md).

Full threat model and transport guidance: run `guardian security-notes` or read [SECURITY.md](SECURITY.md).

## Build from source

See [AGENTS.md](AGENTS.md#build).

## License

GPL-3.0 — [LICENSE](LICENSE). Third-party notices: [NOTICE.txt](NOTICE.txt).
