# Guardian — agent and contributor guide

Cross-platform Rust CLI that hardens AI harnesses: optional Frida `connect()` hooking + embedded [Proxelar](https://github.com/emanuele-em/proxelar) MITM when `--tpf` is set, and direct payload filtering for tool calls.

## Modes

| Mode | Invocation | `--tpf` absent | `--tpf` present |
|------|------------|----------------|-----------------|
| MITM | `guardian -- <program>` | Passthrough exec (no Frida/proxy) | Frida hook + proxy + response/frame filter |
| Payload | `--payload` or piped stdin | Echo payload to stdout | POST to filter; print response or block |

Piped stdin selects payload mode only when no child program follows `--` (or use `--payload` explicitly). `echo data | guardian --tpf URL` filters the pipe; `guardian --tpf URL -- curl` stays MITM even if the parent has a piped stdin.

## Goal

`guardian --tpf URL -- curl https://httpbin.org/get` should MITM-intercept HTTP/HTTPS/WS/WSS, POST each response (or server→client WS frame) to the filter URL, and block unsafe content before it reaches the harness.

## Protocol interception (MITM + `--tpf` only)

Two-layer design; scheme names are not parsed by Frida — interception is driven by TCP destinations, then protocol decoding in Proxelar.

```mermaid
flowchart TB
    subgraph child [Child process]
        App[App libraries]
    end
    subgraph layer1 [Layer 1 - Frida TCP hook]
        Connect[connect host:port]
        Redirect[Redirect to bind_ip:proxy_port]
        SyntheticCONNECT["Send CONNECT host:port HTTP/1.0"]
    end
    subgraph layer2 [Layer 2 - Proxelar forward MITM]
        Forward[Accept CONNECT tunnel]
        Cleartext[Cleartext HTTP / WS upgrade]
        TLS[TLS terminate with local CA]
        Filter[ContentFilter POST to --tpf]
    end
    App --> Connect --> Redirect --> SyntheticCONNECT --> Forward
    Forward --> Cleartext --> Filter
    Forward --> TLS --> Filter
```

**Layer 1** — hook `connect()` / `WSAConnect` for **TCP only**; redirect to `bind_ip:proxy_port`; synthetic `CONNECT`. Default filter: IPv4 TCP except `ignored_ports`.

**Layer 2** — `ProxyMode::Forward`, `content_filter: TrypanophobeClient`, `event_tx: None`. HTTP/HTTPS responses buffered and checked; server→client WS `Text`/`Binary` frames checked.

## Startup lifecycle (MITM + `--tpf`)

```text
main (tokio)
 ├─ resolve Settings
 ├─ CaTrust + Ssl::load_or_generate
 ├─ spawn_blocking: frida spawn → port → proxy ready → instrument → wait
 ├─ proxy with ContentFilter (no JSONL)
 └─ exit(normalize_exit_code)
```

Payload mode: `trypanophobe::run_payload` — read stdin/`--payload`, optional POST to `--tpf`.

## Repository layout

```
guardian/
  src/
    main.rs           # mode dispatch
    trypanophobe.rs   # filter client + payload runner
    proxy.rs          # Proxelar embed + ContentFilter
    injector.rs       # Frida
    ca.rs
  patches/proxyapi+0.4.5.patch   # SNI cert, Connection: close, ContentFilter
  scripts/smoke/
    tpf-mock-server.ts   # Express /pass (200) + /reject (503)
    tpf-cases.ts
    run-tpf-cases.ts
```

## Trypanophobe API

POST JSON to `--tpf` URL. `200` = allow; any other status = block (fail closed). Optional `{"safe":false}` in body also blocks.

## Build

**Prerequisites:** Rust stable, Node.js (`npm install`), `libclang-dev` (Linux).

```bash
npm install
cargo run --quiet --manifest-path tools/patch-proxyapi/Cargo.toml
cargo build --release
```

## Testing

**Cargo integration** — real Frida/proxy where needed; payload echo tests without network.

**Smoke** — `npm run smoke` builds release artifact, starts Express TPF mock (`scripts/smoke/tpf-mock-server.ts`), runs passthrough + TPF cases.

```bash
npm run smoke
```

TPF mock endpoints: `POST /pass` → 200 `{"safe":true}`; `POST /reject` → 503 `{"safe":false}`.

## Configuration reference

| Key | CLI | Env | Default | Description |
|-----|-----|-----|---------|-------------|
| `trypanophobe_filter` | `--tpf` | `GUARDIAN_TRYPANOPHOBE_FILTER` | (unset) | Filter endpoint URL |
| `bind` | `-b, --bind` | `GUARDIAN_BIND` | `127.0.0.1` | Proxy bind IPv4 |
| `port` | `-p, --port` | `GUARDIAN_PORT` | (unset) | Fixed proxy port |
| `filter` | `--filter` | `GUARDIAN_FILTER` | denylist | Connect-hook JS expression |
| `ignored_ports` | `--ignored-ports` | — | see toml | Ports left unhooked |
| `ca_dir` | `--ca-dir` | `GUARDIAN_CA_DIR` | `~/.guardian` | CA directory |
| `filter_timeout_secs` | — | `GUARDIAN_FILTER_TIMEOUT_SECS` | `10` | Filter HTTP timeout |
| `filter_body_limit` | — | `GUARDIAN_FILTER_BODY_LIMIT` | `1048576` | Max bytes per filter POST |
| `block_message` | — | `GUARDIAN_BLOCK_MESSAGE` | see toml | Substitution text on block |
| `no_color` | `--no-color` | — | `false` | Disable colored stderr |

Shipped defaults: [`config/guardian.toml`](config/guardian.toml).

## Known limitations

- IPv6 `connect()` not hooked
- Certificate pinning blocks MITM
- Frida permissions required
- Non-HTTP TCP tunneled but not filtered
- QUIC/UDP not intercepted
