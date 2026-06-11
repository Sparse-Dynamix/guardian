# Security model

Guardian is a **local TLS man-in-the-middle (MITM) proxy** used to harden AI agent harnesses. When `--tpf` is set, it terminates TLS for child-process traffic, inspects content, and forwards only what a Trypanophobe-compatible filter allows. That design is powerful and invasive by nature. This text states plainly what Guardian does today, what it assumes you trust, and what may change in future releases.

Print this document anytime with `guardian security-notes`. Legal disclaimers and third-party attributions: `guardian legal-notes`.

**This is not optional behavior.** Without `--tpf`, Guardian does not install hooks, does not run the proxy, and does not decrypt TLS—it simply execs the child (MITM mode) or echoes/filters payloads (payload mode). **With `--tpf` in MITM mode, TLS interception is the core mechanism**, not an add-on.

---

## What Guardian does when `--tpf` is set (MITM mode)

1. **Frida hooks** the child’s `connect()` / `WSAConnect` for outbound TCP (IPv4 and IPv6) and redirects eligible sockets to a local forward proxy.
2. **Proxelar** accepts those connections, terminates TLS using a **Guardian-issued certificate** signed by a **local root CA**, decodes HTTP/HTTPS and WebSocket traffic, and buffers or streams response bodies as configured.
3. **Trypanophobe filter** (`--tpf`) receives **plaintext** copies of HTTP response bodies, server→client WebSocket `Text`/`Binary` frames, and (in payload mode) tool-call payloads. A non-`200` response causes Guardian to **fail closed** and substitute a block message instead of forwarding content to the harness.

Cleartext HTTP and tunneled non-HTTP TCP may also pass through the proxy; only HTTP-family content and configured payloads are sent to the filter today.

```text
Child app ──TLS──► upstream server
     │
     └── connect() hooked ──► Guardian proxy ── decrypt ──► POST plaintext ──► --tpf filter
                                    │
                                    └── re-encrypt ──► child (if allowed)
```

---

## Root CA trust and TLS decryption

### What happens to certificates

- On first use, Guardian generates (or loads) a **root CA** under `~/.guardian` by default (`--ca-dir` / `GUARDIAN_CA_DIR`).
- For each intercepted TLS connection, Guardian presents a **leaf certificate** for the target hostname, signed by that root CA.
- The child process must **trust the Guardian root CA** or TLS handshakes fail. Guardian injects trust via environment variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, Java truststore properties, etc.) and optionally via `guardian install-system`, which registers the CA in OS, browser, and Java trust stores.

### What is decrypted

When MITM mode runs with `--tpf`:

- **All TLS** on hooked TCP connections that reach the proxy is **terminated and decrypted** at the proxy.
- Response bodies (and per-event SSE payloads) are held in memory, posted to `--tpf`, and only then forwarded if allowed.
- With `--tps` / `trypanophobe_swap`, a filter `200` response can **replace** what the harness sees (body and headers).

Guardian does **not** decrypt traffic for its own filter POST beyond what `reqwest` does for the `--tpf` URL scheme (see "Filter endpoint transport and plaintext exposure" below).

### Threat model (intended use)

Guardian is meant for **controlled environments** where an operator deliberately runs an AI harness under inspection:

| Actor / asset | Assumption today |
|---------------|------------------|
| **Operator** | Trusts Guardian and the filter service; controls `--tpf`, `--ca-dir`, and child argv. |
| **Child process** | Untrusted; its outbound (and filtered inbound) web content may be malicious or exfiltrating. |
| **Upstream servers** | Untrusted content sources; Guardian does not vouch for their safety—only the filter’s verdict. |
| **Filter endpoint (`--tpf`)** | Trusted to receive **full plaintext** of inspected traffic; compromise of the filter or its transport exposes everything Guardian decrypts. |
| **Local machine** | Users with permission to read `~/.guardian` (especially `rootCA-key.pem`) can mint certificates trusted by any process that trusts the Guardian CA—effectively MITM **the entire machine** for as long as that CA remains installed. |
| **Network path to `--tpf`** | If not TLS-protected, any observer on that path sees decrypted content in cleartext. |

**Out of scope today:** Guardian does not sandbox the child, isolate the filter, audit filter behavior, or protect against a malicious filter returning `200` for harmful content. It does not intercept QUIC/UDP or reliably hook all IPv6-only socket configurations.

### Current tolerance

Full TLS decryption via a locally trusted root CA is **inherent to the MITM design** and is accepted as-is for the current CLI. Documentation may describe filtering or CA trust as optional to enable; that refers only to **whether you set** `--tpf` and run `install-system`, not to whether decryption occurs once those are in use.

### Planned / possible future changes

- **Scoped or ephemeral** CAs instead of a long-lived machine-wide root.
- **Per-harness** or **per-session** trust instead of system-wide registration.

---

## Filter endpoint transport and plaintext exposure

### What the filter receives

For every gated HTTP response, WebSocket frame, or tool payload, Guardian `POST`s the **raw bytes** of that content to `--tpf`. For HTTP responses, the request URL is appended as `?url=<request-url>`. The filter therefore sees the same plaintext the harness would have seen (modulo `--tps` substitution).

**The filter is a sensitive data processor.** Treat it like a logging pipeline with full access to agent traffic, credentials in responses, PII, API keys, and proprietary content.

### HTTP vs HTTPS for `--tpf`

Local filter examples often use `http://127.0.0.1:...` when the filter listens on loopback without TLS. That is a **convenience for local development**, not a recommendation for production.

| `--tpf` URL | Behavior today | Risk |
|-------------|----------------|------|
| `http://127.0.0.1:...` | Plaintext on loopback | Lower exposure if the filter stays on the same host; still visible to local processes. |
| `http://remote-host/...` | Plaintext over the network | **High risk**—decrypted traffic leaves the machine unencrypted. |
| `https://...` | TLS to the filter (system/default trust store via `reqwest`) | Protects data in transit; you must trust the filter host’s certificate and the CA that signed it. |

**Recommendation:** Use **`https://`** for any remote or shared filter. Prefer loopback HTTP only for local development. Pin or otherwise constrain filter TLS trust in high-assurance deployments (not supported as a first-class Guardian flag today).

Guardian does **not** currently:

- Reject `http://` filter URLs when the host is non-loopback.
- Require mutual TLS or filter endpoint certificate pinning.
- Redact or minimize fields before POST (full bodies are sent).

### Current tolerance

Guardian accepts any valid `--tpf` URL scheme and uses standard HTTPS when you provide `https://`. Operators are responsible for choosing safe filter placement and transport.

### Planned / possible future changes

- Documentation and CLI **warnings** when `--tpf` uses cleartext to a non-loopback host.
- Optional **enforcement** of HTTPS for `--tpf`.
- Configurable **TLS trust** for the filter client (custom CA, mTLS).
- **Payload size limits**, sampling, or redaction before POST (would change the threat model and filter contract).

---

## Certificate pinning and interception failures

### The limitation

Many modern HTTP clients, mobile SDKs, and agent runtimes implement **certificate pinning** or **public key pinning**. They validate the server certificate against an expected SPKI hash or baked-in trust anchor and **reject** connections where a local MITM CA replaces the chain—even if that CA is trusted by the OS.

When pinning is in effect, Guardian’s MITM typically manifests as:

- TLS handshake failures or hung connections.
- Timeouts waiting for responses that never complete filtering.
- Opaque errors inside the child (library-specific), not Guardian-branded messages.

Certificate pinning is a **known limitation** of MITM tooling. **There is no reliable universal bypass** without modifying the child binary or its trust store in ways pinning explicitly prevents.

### Common situations in AI harnesses

- Language runtimes using **custom TLS stacks** with embedded roots.
- **Electron / Chromium** apps with network service pinning or CT policies.
- **Mobile or embedded** agents (not primary targets today, but the same constraint applies).
- Libraries that pin **specific API hosts** (common for payment, auth, and some LLM provider SDKs).

Guardian may still intercept **other** traffic from the same process while pinned hosts fail silently or fail the whole session, depending on the client.

### Current tolerance

Pinning failures are **accepted as an environmental constraint**. Guardian does not detect pinning today and does not emit a dedicated diagnostic. Operators must infer pinning from child logs, tcpdump, or trial runs without `--tpf`.

### Planned / possible future changes

- **Heuristic detection** (e.g. repeated TLS handshake failures to hooked destinations) with a clear message such as: *this client appears to pin certificates; Guardian cannot intercept that traffic*.
- Per-host **bypass documentation** or connect-hook `--filter` recipes to skip known-pinned destinations (traffic would reach the harness **unfiltered**—a deliberate tradeoff).
- Integration guides for harness authors: disable pinning in test harnesses, or use payload-only filtering instead of MITM.

Until such tooling exists, treat pinning-related failures as **expected** for a subset of real-world agents, not as Guardian bugs.

---

## Payload mode

Without a child network stack, payload mode reads stdin or `--payload` and optionally POSTs to `--tpf`. The same filter trust and transport considerations apply: the filter sees the **entire payload in plaintext**. MITM, Frida, and CA trust are **not** used in payload-only runs.

---

## Local privileges and secrets

These items are related to the same trust boundary and are called out here for completeness:

- **CA private key** (`rootCA-key.pem`) under `--ca-dir` is restricted after load/generate: mode `0600` on Unix, owner-only ACL on Windows via `icacls`. Treat the key as **highly confidential** regardless.
- **`install-system`** requires administrator privileges and affects **system-wide** trust while the CA remains installed. Run `guardian remove-system` or `guardian clean` when decommissioning.
- **`guardian clean`** always deletes local artifacts under `--ca-dir` (and orphan `~/.guardian/guardian.toml` when `ca_dir` is custom). System trust removal runs only when elevated; otherwise it warns to re-run with `sudo guardian clean` (Unix) or as Administrator (Windows), and lists any local paths that could not be deleted.
- **Java truststore password** is a fixed default in config (`guardian`). It is passed via `JAVA_TOOL_OPTIONS` and is visible to other local processes (Unix: `/proc/<pid>/cmdline`, `ps`; Windows: process command-line APIs / Task Manager). Blast radius is limited to the injected PKCS12 truststore, not the CA private key.

---

## Reporting security issues

If you discover a vulnerability in Guardian itself, please report it at
https://github.com/Sparse-Dynamix/guardian/issues with enough detail to
reproduce. Do not post live `--tpf` endpoints or decrypted traffic samples in
public reports.

---

## Summary

| Topic | Today | Future direction |
|-------|--------|------------------|
| Root CA + TLS MITM | Required for MITM + `--tpf`; decrypts hooked TLS | Richer CA lifecycle, possibly narrower trust scope |
| Filter sees plaintext | Always; full bodies posted to `--tpf` | Possible redaction, limits, stronger transport defaults |
| `--tpf` over HTTP | Allowed; common in local examples | Warnings or HTTPS enforcement for remote filters |
| Certificate pinning | Unsupported; failures look like generic TLS errors | Detection, clearer errors, documented workarounds |

Guardian trades **strong visibility into agent traffic** for **broad local trust and plaintext disclosure to the filter**. Use it only where that tradeoff is understood, intentional, and constrained by your own operational controls.
