# Guardian

Harden AI harnesses by filtering web traffic and tool-call payloads through a Trypanophobe-compatible endpoint.

## Modes

![Wrapper mode diagram](assets/wrapper-mode.png)

**Wrapper mode** — wrap a child process:

```bash
guardian --tpf https://filter.example/check -- opencode
guardian -- curl https://httpbin.org/get   # passthrough when --tpf is omitted
```

**Payload mode** — filter tool-call payloads:

![Payload mode diagram](assets/payload-mode.png)

```bash
guardian --tpf https://filter.example/check --payload '{"tool":"read_file"}'
echo '{"tool":"read_file"}' | guardian --tpf https://filter.example/check
```

Without `--tpf`, Wrapper mode runs the child directly and payload mode echoes stdin/`--payload` to stdout.

## Quick start

**Downloaded a release?** See [Release binaries (`--tpf`)](#release-binaries-tpf).

**Building from source:**

1. Build — see [AGENTS.md](AGENTS.md#build).
2. Trust the Guardian CA (recommended for HTTPS in browsers and system cert stores):

   ```bash
   sudo guardian install-system
   guardian check-system
   ```

3. Run with filtering:

   ```bash
   guardian --tpf http://127.0.0.1:3000/pass -- your-program --args
   ```

Guardian stores its CA and config under `~/.guardian` by default.

## Release binaries (`--tpf`)

From [GitHub Releases](https://github.com/Sparse-Dynamix/guardian/releases): `guardian` (macOS) or `guardian.exe` (Windows; keep `frida-core.dll` beside it if included).

```bash
guardian --tpf https://filter.example/check -- your-program --args
```

### Without elevation

**macOS (once, no `sudo`):** `codesign -s - -f --entitlements <plist> ./guardian` with `com.apple.security.get-task-allow` in the plist.

**Windows:** allow SmartScreen/AV if prompted.

Guardian injects CA trust into the **wrapped child** (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, etc.). Use `--skip-cert-regen` to reuse the same `~/.guardian` CA. Works for CLI tools and runtimes that honor those env vars; not for browsers or other apps using only the system cert store.

### With elevation (`sudo` / Administrator)

System-wide CA trust (browsers, OS/Java stores):

```bash
sudo guardian install-system && guardian check-system
```

```powershell
.\guardian.exe install-system; .\guardian.exe check-system
```

Remove when done: `guardian remove-system` or `guardian clean` (elevated).

## Usage

```text
guardian [OPTIONS] -- <PROGRAM> [ARGS]...     # Wrapper mode
guardian [OPTIONS] --payload <TEXT>           # payload mode
echo <payload> | guardian [OPTIONS] --tpf URL # payload mode (piped stdin)
```

| Flag | Description |
|------|-------------|
| `--tpf`, `--trypanophobe-filter` | Trypanophobe filter endpoint (`200` = allow, non-`200` = block) |
| `--tps`, `--trypanophobe-swap` | On `200`, replace harness-visible body/headers with the TPF response (requires `--tpf`) |
| `--payload` | Explicit payload string (payload mode) |
| `-p, --port` | Proxy listen port (MITM + `--tpf`; default: auto) |
| `-b, --bind` | Proxy bind IPv4 (default: `127.0.0.1`) |
| `--ca-dir` | Guardian data directory (default: `~/.guardian`) |
| `--skip-cert-regen` | Reuse existing on-disk CA instead of rotating each MITM run |
| `--filter` | Connect-hook JS expression (`sa_family`, `addr`, `port`, `host`) |
| `--ignored-ports` | TCP ports to leave unhooked when `--filter` is unset (comma-separated) |
| `--config` | Extra config file path |

Document subcommands (print to stdout): `legal-notes` ([NOTICE.txt](NOTICE.txt)), `license-notes` ([LICENSE](LICENSE)), `security-notes` ([SECURITY.md](SECURITY.md)).

## Trypanophobe filter API

`POST <tpf_url>` with the **raw response bytes** as the body (never truncated).

- HTTP responses also include `?url=<request-url>` on the query string.
- **HTTP 200** — allow; without `--tps`, the original content is forwarded. With `--tps`, Guardian swaps in the TPF response body and headers.
- **Non-200** — block; Guardian substitutes `Blocked by Guardian: content failed safety check` (configurable via `block_message`).

## System CA trust

| Command | Admin required | Purpose |
|---------|----------------|---------|
| `install-system` | Yes | Register the Guardian CA in OS / browser / Java trust stores |
| `remove-system` | Yes | Remove the Guardian CA from system trust stores |
| `clean` | Partial | Delete local artifacts; system trust removal when run as administrator |
| `check-system` | No | Report whether the CA is trusted |
| `legal-notes` | No | Print legal notice and third-party attributions |
| `license-notes` | No | Print GPL license text |
| `security-notes` | No | Print security model |

## License

GPL-3.0 — see [LICENSE](LICENSE). Legal notice, disclaimers, and third-party licenses: [NOTICE.txt](NOTICE.txt).
