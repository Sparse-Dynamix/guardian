# guardian

Run any command under transparent network interception. Guardian wraps a program with Frida hooking and a local MITM proxy, then streams captured HTTP, HTTPS, WebSocket, and secure WebSocket traffic as JSON on stderr — while the program’s own output on stdout stays clean for piping.

```bash
guardian -- curl https://httpbin.org/get
guardian -- sh -c 'curl https://httpbin.org/get'
```

## Getting guardian

Download a release binary when available, or build from source — see [AGENTS.md](AGENTS.md#build).

When using a dynamically linked build, ship the Frida runtime library beside the `guardian` binary (see AGENTS.md).

## Usage

```text
guardian [OPTIONS] -- <PROGRAM> [ARGS]...
```

| Flag | Description |
|------|-------------|
| `--silent` | Suppress JSONL network logs on stderr |
| `-p, --port` | Proxy listen port (default: auto free port in 1024–65535) |
| `-b, --bind` | Proxy bind IPv4 address (default: `127.0.0.1`) |
| `--ca-dir` | CA certificate directory (default: `~/.proxelar`) |
| `--body-limit` | Max captured body/frame preview bytes in logs (default: 256) |
| `--filter` | Connect-hook filter expression (platform default if unset) |
| `-v` / `RUST_LOG` | Internal diagnostics on stderr |
| `--config` | Path to an additional config file |

Configuration defaults live in the shipped `config/guardian.toml`. Override them in `~/.config/guardian/guardian.toml`, with `GUARDIAN_*` environment variables, or with CLI flags. See [AGENTS.md](AGENTS.md#configuration-reference) for the full list.

## Capturing traffic

Network events are written as JSON Lines on stderr (one object per line, each starting with `{`). Child stdout is not used for logs:

```bash
guardian -- curl -s https://httpbin.org/get | jq .
guardian -- curl -s https://httpbin.org/get 2> traffic.jsonl
```

Use `--silent` to run guardian without network logging.

## Permissions

Guardian uses Frida **spawn** (not attach-to-existing). Requirements below are per OS.

### Linux

Frida injects via `ptrace`. On a normal host, spawning a same-user program works with the default Yama setting (`kernel.yama.ptrace_scope=1` on Ubuntu/Debian).

| Condition | What happens |
|-----------|--------------|
| Spawn same-user child (guardian’s normal path) | Works at `ptrace_scope` **1** (parent→descendant is allowed) |
| `ptrace_scope` **0** | Any same-uid, dumpable process can be attached |
| `ptrace_scope` **2** | Only root (`CAP_SYS_PTRACE`) can ptrace — run guardian as root, or temporarily `sudo sysctl kernel.yama.ptrace_scope=0` |
| `ptrace_scope` **3** | Ptrace disabled system-wide (cannot be changed back) |
| Target is another user’s process | Root required |
| Target exec’d a setuid/setgid binary (or dropped privs via `setuid`) | Process is non-dumpable; ptrace fails unless root or the target calls `prctl(PR_SET_DUMPABLE, 1)` |
| Inside Docker/Podman with default seccomp | `ptrace` is blocked — start the container with `--security-opt seccomp=unconfined` (see [Frida Linux/Docker docs](https://frida.re/docs/examples/linux/)) |

Check current value: `sysctl kernel.yama.ptrace_scope` or `cat /proc/sys/kernel/yama/ptrace_scope`.

### macOS

Frida needs `task_for_pid` to spawn/inject. **Root is not required** for normal user binaries.

| Condition | What happens |
|-----------|--------------|
| First run from Terminal.app | `taskgate` prompts to allow debugging — approve once per guardian binary |
| Headless / SSH (no prompt) | `sudo security authorizationdb write system.privilege.taskport allow` (weakens security; see [Frida troubleshooting](https://frida.re/docs/troubleshooting/)) |
| Target in SIP-protected paths (`/System`, `/usr` except `/usr/local`, platform binaries) | Blocked while SIP is enabled — not typical for `curl`/`sh` in `$PATH` |
| Target has **Hardened Runtime** + library validation (most App Store / notarized apps) | Frida’s agent cannot load unless the target has `com.apple.security.cs.disable-library-validation` |
| Release-signed target without `com.apple.security.get-task-allow` | Spawn/attach denied — re-sign the target with that entitlement, or use a debug build |

Prebuilt `libfrida-core` from Frida releases is already codesigned.

### Windows

Injection requires the **same or higher integrity level** as the target. Guardian does not need admin for normal (medium-IL) programs.

| Condition | What happens |
|-----------|--------------|
| Guardian and target both non-elevated (medium IL) | Works out of the box |
| Target is elevated (high IL, “Run as administrator”) | Run guardian elevated too |
| Target is **Protected Process Light** (PPL) or anti-malware protected | Injection blocked regardless of admin |
| Third-party AV/EDR | May block DLL injection into the child |

## License

GPL-3.0 — see [LICENSE](LICENSE).
