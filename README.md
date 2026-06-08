# Guardian

Harden AI harnesses by filtering web traffic and tool-call payloads through a Trypanophobe-compatible endpoint.

## Modes

**MITM mode** — wrap a child process:

```bash
guardian --tpf http://filter.example/check -- opencode
guardian -- curl https://httpbin.org/get   # passthrough when --tpf is omitted
```

**Payload mode** — filter tool-call payloads:

```bash
guardian --tpf http://filter.example/check --payload '{"tool":"read_file"}'
echo '{"tool":"read_file"}' | guardian --tpf http://filter.example/check
```

Without `--tpf`, MITM mode runs the child directly and payload mode echoes stdin/`--payload` to stdout.

## Quick start

1. **Build** — see [AGENTS.md](AGENTS.md#build).
2. **Optional — trust the Guardian CA** (MITM mode with `--tpf` only):

   ```bash
   sudo guardian install-system
   guardian check-system
   ```

3. **Run with filtering:**

   ```bash
   guardian --tpf http://127.0.0.1:3000/pass -- curl -s https://httpbin.org/get
   ```

Guardian stores its CA and config under `~/.guardian` by default.

## Usage

```text
guardian [OPTIONS] -- <PROGRAM> [ARGS]...     # MITM mode
guardian [OPTIONS] --payload <TEXT>           # payload mode
echo <payload> | guardian [OPTIONS] --tpf URL # payload mode (piped stdin)
```

| Flag | Description |
|------|-------------|
| `--tpf`, `--trypanophobe-filter` | Trypanophobe POST endpoint (`200` = safe, non-`200` = block) |
| `--payload` | Explicit payload string (payload mode) |
| `-p, --port` | Proxy listen port (MITM + `--tpf`; default: auto) |
| `-b, --bind` | Proxy bind IPv4 (default: `127.0.0.1`) |
| `--ca-dir` | Guardian data directory (default: `~/.guardian`) |
| `--filter` | Connect-hook filter expression |
| `--no-color` | Disable colored stderr messages |
| `-v` / `RUST_LOG` | Internal diagnostics on stderr |
| `--config` | Extra config file path |

## Trypanophobe filter API (v1 PoC)

`POST <tpf_url>` with JSON body:

```json
{
  "kind": "http_response | ws_frame | tool_payload",
  "payload": "<base64>",
  "metadata": { }
}
```

- **HTTP 200** — content is safe; forwarded to the harness (or filter response body printed in payload mode).
- **Non-200** — blocked; Guardian substitutes `Blocked by Guardian: content failed safety check` (configurable via `block_message`).

## System CA trust

| Command | Admin required | Purpose |
|---------|----------------|---------|
| `install-system` | Yes | Register the Guardian CA in OS / browser / Java trust stores |
| `remove-system` | Yes | Remove the Guardian CA |
| `check-system` | No | Report whether the CA is trusted |

## License

GPL-3.0 — see [LICENSE](LICENSE).
