# Guardian

Run any command and see its network traffic. Guardian intercepts HTTP, HTTPS, WebSocket, and secure WebSocket connections from the wrapped program, then streams each event as JSON on stderr. The child process keeps stdout clean for piping.

```bash
guardian -- curl https://httpbin.org/get
guardian -- sh -c 'curl https://httpbin.org/get'
```

## Quick start

1. **Build or install** — see [AGENTS.md](AGENTS.md#build).
2. **Optional — trust the Guardian CA system-wide** (improves HTTPS interception for browsers and apps that ignore injected env vars):

   ```bash
   sudo guardian install-system   # Linux/macOS; Administrator on Windows
   guardian check-system          # verify without admin
   ```

3. **Run a command under interception:**

   ```bash
   guardian -- curl -s https://httpbin.org/get
   ```

Guardian stores its CA and config under `~/.guardian` by default.

## Usage

```text
guardian [OPTIONS] -- <PROGRAM> [ARGS]...
guardian install-system [--stores system,nss,java]
guardian remove-system  [--stores system,nss,java]
guardian check-system     [--stores system,nss,java]
```

| Flag | Description |
|------|-------------|
| `--silent` | Suppress JSONL network logs on stderr |
| `-p, --port` | Proxy listen port (default: auto free port in 1024–65535) |
| `-b, --bind` | Proxy bind IPv4 address (default: `127.0.0.1`) |
| `--ca-dir` | Guardian data directory (default: `~/.guardian`) |
| `--body-limit` | Max captured body/frame preview bytes in logs (default: 256) |
| `--filter` | Connect-hook filter expression (platform default if unset) |
| `--no-color` | Disable colored Guardian messages and JSONL on stderr |
| `-v` / `RUST_LOG` | Internal diagnostics on stderr |
| `--config` | Path to an additional config file |

Configuration defaults ship in `config/guardian.toml`. Override in `~/.guardian/guardian.toml`, with `GUARDIAN_*` environment variables, or CLI flags. See [AGENTS.md](AGENTS.md#configuration-reference) for the full list.

## Capturing traffic

Network events are JSON Lines on stderr (one object per line). Child stdout is not used for logs:

```bash
guardian -- curl -s https://httpbin.org/get | jq .
guardian -- curl -s https://httpbin.org/get 2> traffic.jsonl
```

Use `--silent` to run without network logging. Guardian-owned stderr lines are colorized by default (light blue JSONL, yellow warnings); pass `--no-color` to disable.

On each run, Guardian prints a short notice that not all traffic may be captured, and suggests `install-system` when the CA is not yet trusted system-wide.

## System CA trust

| Command | Admin required | Purpose |
|---------|----------------|---------|
| `install-system` | Yes | Register the Guardian CA in OS / browser / Java trust stores |
| `remove-system` | Yes | Remove the Guardian CA from those stores |
| `check-system` | No | Report whether the CA is already trusted |

`install-system` and `remove-system` fail immediately with a clear message if not run with administrator privileges (`sudo` on Linux/macOS, elevated terminal on Windows).

## Permissions

Guardian needs permission to inject into the child process it spawns. Requirements vary by OS — see [AGENTS.md](AGENTS.md#permissions).

## License

GPL-3.0 — see [LICENSE](LICENSE).
