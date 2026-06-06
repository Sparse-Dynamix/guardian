# guardian

Cross-platform CLI that wraps a subcommand under Frida `connect()` hooking and MITM-intercepts HTTP, HTTPS, WS, and WSS via an embedded [Proxelar](https://github.com/emanuele-em/proxelar) forward proxy. Captured traffic is streamed as JSONL on stderr.

```bash
guardian -- curl https://httpbin.org/get
guardian -- sh -c 'curl https://httpbin.org/get'
```

See [PLAN.md](PLAN.md) for architecture and design details.

## Build

**Prerequisites (Linux)**

- Rust stable (see `rust-toolchain.toml`)
- `libclang-dev` (for `frida-sys` / bindgen)

```bash
# Debian/Ubuntu
sudo apt install libclang-dev

export LIBCLANG_PATH=/usr/lib/llvm-18/lib   # adjust llvm version if needed

cargo build --release
```

The binary is `target/release/guardian`. When dynamically linked against Frida, ship `libfrida-core.so` beside the binary (`build.rs` sets `rpath $ORIGIN` on Linux).

Cross-compilation: `scripts/build-release.sh` (requires `cargo-zigbuild`, `cargo-xwin`, and a macOS SDK for darwin targets).

## Usage

```text
guardian [OPTIONS] -- <PROGRAM> [ARGS]...
```

| Flag | Description |
|------|-------------|
| `--silent` | Suppress JSONL network logs on stderr |
| `-p, --port` | Proxy listen port (default: PID-based auto in 1024–65535) |
| `-b, --bind` | Proxy bind IPv4 address (default: `127.0.0.1`) |
| `--ca-dir` | Proxelar CA directory (default: `~/.proxelar`) |
| `--body-limit` | Max captured body/frame preview bytes (default: 256) |
| `--filter` | JS filter for connect hook (platform default if unset) |
| `-v` / `RUST_LOG` | Internal diagnostics (prefixed `guardian:` on stderr) |

JSONL lines start with `{`. Child stdout is not used for logs, so piping app output still works:

```bash
guardian -- curl -s https://httpbin.org/get | jq .
guardian -- curl -s https://httpbin.org/get 2> traffic.jsonl
```

## Permissions

Frida injection may require:

- **Linux**: `kernel.yama.ptrace_scope=0` or equivalent for some targets
- **macOS**: codesign / SIP considerations for unsigned binaries
- **Windows**: administrator for elevated targets

## License

GPL-3.0 — see [LICENSE](LICENSE).
