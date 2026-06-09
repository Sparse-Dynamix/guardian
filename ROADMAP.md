## Overall impression (Fable)

This is genuinely good work. The architecture is clean and well-factored (mode dispatch → injector/proxy coordination → filter client), the two-layer Frida + MITM design is sound and well-documented in `AGENTS.md`, the filter fails closed, and the test culture is unusually strong for a project this age — 29 integration test files, real end-to-end tests against live endpoints, cross-platform smoke + coverage scripts, env-mutation locks in unit tests. The commit history shows disciplined iteration on cross-platform stability.

That said: **I would not ship a public beta yet.** There are a few correctness bugs, some security gaps that matter a lot for a tool whose pitch is "security," and — most importantly — a couple of product-level design risks for the AI-harness use case specifically. Details below, roughly by severity.

---

## Likely correctness bugs

**1. Documented env vars are probably broken (config separator).**

```136:136:src/config.rs
    builder = builder.add_source(Environment::with_prefix("GUARDIAN").separator("_"));
```

In the `config` crate, `separator("_")` means underscores denote *nesting*. So `GUARDIAN_TRYPANOPHOBE_FILTER` becomes the nested key `trypanophobe.filter`, which silently doesn't match the flat field `trypanophobe_filter`. Worse, `GUARDIAN_FILTER_TIMEOUT_SECS` becomes `filter.timeout.secs`, turning `filter` (an `Option<String>`)... it's a mess. The `AGENTS.md` / README advertise `GUARDIAN_TRYPANOPHOBE_FILTER`, `GUARDIAN_BIND`, `GUARDIAN_PORT`, `GUARDIAN_CA_DIR`, etc. I'd verify these actually work — I suspect most multi-word ones don't. There's no test covering env-var config loading (the `GUARDIAN_*` greps in tests are all test-harness vars, not config keys). This is a documented public interface that appears non-functional.

**2. Synthetic CONNECT mismatch with what the proxy expects.**

`AGENTS.md` says Layer 1 sends `CONNECT host:port HTTP/1.0`, but the hook actually sends HTTP/1.1 with `Proxy-Connection: Keep-Alive`:

```216:219:assets/connect_hook.js
            var connect_request = "CONNECT " + target + ":" + this.port + " HTTP/1.1\r\n"
                + "Host: " + target + ":" + this.port + "\r\n"
                + "Proxy-Connection: Keep-Alive\r\n"
                + "\r\n";
```

Not necessarily a bug, but the doc and code disagree, and `Keep-Alive` semantics interact with the patch's `Connection: close` behavior — worth confirming the actual handshake on the wire matches intent.

**3. CONNECT reply parsing is bounded to 4096 bytes / 200 attempts and ignores status.**

```223:247:assets/connect_hook.js
            var buf_recv = Memory.alloc(4096);
            var total = 0;
            var attempts = 0;
            while (total < 4096 && attempts < 200) {
```

The hook reads the proxy's CONNECT response but never checks for a `200` status — if the proxy returns `4xx/5xx`, the client proceeds to TLS-handshake into an error body. And the fixed 4096 buffer assumes the proxy never sends a large CONNECT response, which is fine for your own proxy but brittle. The `Thread.sleep(0.05)` polling inside a `connect()` interceptor also adds latency to every hooked connection.

**4. `try_wait_pid` treats "process gone" as exit code 0.**

```320:322:src/injector.rs
        match err.raw_os_error() {
            Some(libc::ESRCH) => WaitStatus::Exited(0),
```

Because Frida spawns the child (not a direct fork), you can't `waitpid` it, so you poll with `kill(pid,0)`. When the process disappears you report exit code `0` regardless of how it actually exited. For a passthrough/wrapper tool, propagating the real child exit code matters (CI, scripts, `&&` chains). The non-filtered path gets this right via `status.code()`; the filtered path can't and silently flattens to 0. Worth documenting at minimum.

**5. PID reuse race in the poll loop.** `wait_for_root` polls `kill(pid,0)` on a 50ms interval. Between the child exiting and the next poll, the OS can recycle that PID. Low probability, but it exists by construction with PID-polling. Worth a note.

---

## Security gaps (important for a security product)

**6. CA private key file permissions are never restricted.** The patch writes `rootCA.pem` + `rootCA-key.pem` via proxyapi, and nothing in `ca.rs`/`install.rs`/`mkcert.rs` chmods the key to `0600`. A locally-trusted root CA private key sitting at default umask (often `0644`) is a real local-privilege concern — anyone who reads it can MITM the user's entire machine for as long as the CA is trusted. For a tool that installs a system-trusted root, locking down the key is table stakes. I only see `0o755` on executables, never `0o600` on the key.

**7. Java truststore password is hardcoded (`"guardian"`) and passed on the command line.** 

```126:128:src/ca.rs
            let flag = format!(
                "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword={pwd}",
```

It's a truststore (not a keystore), so the blast radius is limited, but the password ends up in `JAVA_TOOL_OPTIONS` / process args, visible to any local process via `ps`. Minor, but flag it.

**8. The whole model rests on trusting a root CA + decrypting all TLS.** That's inherent to MITM and fine as a design — but the README's "optional" framing undersells it. For a beta you need a prominent, blunt SECURITY.md explaining: a root CA is installed, all TLS is decrypted and sent to the filter URL, and what the threat model is. Right now there's no SECURITY.md and `LICENSE`/`NOTICES` are the only governance files. There's also no `.github/` (no CI workflows, no issue templates) despite `package.json` pointing at GitHub issues — meaning your strong test/smoke/coverage scripts don't run on PRs.

**9. Filter endpoint sees plaintext of everything, over plain HTTP in all examples.** Every example uses `http://`. If the filter is remote, you're shipping decrypted traffic in cleartext to it. At minimum the docs should push HTTPS for `--tpf` and note the trust implications.

---

## Product / design risks for the AI-harness use case

**10. HTTP/2 and streaming are the elephant in the room.** The hook force-downgrades ALPN to `http/1.1`:

```277:298:assets/connect_hook.js
// Force http/1.1 ALPN so MITM TLS does not negotiate HTTP/2 (unsupported on this path).
```

And the filter design *buffers the full response body* before POSTing it and making an allow/block decision. But the primary AI-harness traffic — OpenAI/Anthropic/etc. — is **HTTP/2 + SSE token streaming**. Forcing HTTP/1.1 may break or degrade some providers, and buffering a streaming response defeats the purpose of streaming (the harness gets nothing until the full completion arrives, then it's filtered all-or-nothing). For the headline use case ("`guardian --tpf URL -- opencode`"), this is the make-or-break question. I'd want to see a real coding agent (Claude Code, opencode, etc.) actually working end-to-end under Guardian before calling it beta-ready. The known-limitations list mentions cert pinning and IPv6 but not streaming/H2 semantics, which are more likely to bite real users.

**11. Cert pinning + IPv6 gaps will hit real agents.** Many modern clients pin or use IPv6; `AGENTS.md` honestly lists these as limitations. That's good, but for a public beta you should expect a meaningful fraction of "it just hangs / fails" reports from exactly these. Some explicit detection + a clear error ("looks like this client pins certs / used IPv6, Guardian can't intercept") would massively cut support load.

**12. Version inconsistency.** `Cargo.toml` is `0.1.0`, `package.json` is `1.0.0`, and the code is littered with "v1" / "pre 1.0" language. Pick one story before a public release.

---

## Smaller things

- `proxy.rs` has both `start_proxy` and `start_proxy_and_wait`; fine, but `wait_for_listener` connecting via `TcpStream::connect` actually opens a real connection to the proxy on every poll, which the proxy then has to handle/drop. Minor.
- After shutdown there's a hardcoded `sleep(500ms)` in `main.rs` before cancelling the proxy — a smell that there's a races being papered over.
- No `--version`-surfaced build metadata (git SHA), which you'll want for beta bug reports.
- `connect_hook.js` skips `127.0.0.1` and `0.0.0.0` but not other loopback/private ranges; depending on intent that may be fine, but document it.

---

## Verdict

**Engineering quality: strong. Beta-readiness: not yet.** If I had to gate it, the blockers are:

1. Fix/verify the env-var config (#1) — a documented interface that looks broken.
2. Lock down the CA private key permissions (#6) — non-negotiable for a security tool.
3. Prove the headline flow works against a real streaming HTTP/2 AI agent, or scope the beta to clients/providers you've actually verified (#10).
4. Add a SECURITY.md + CI workflow and reconcile versioning (#8, #12).

The correctness bugs (#3, #4, exit-code flattening) and the doc/code drift (#2) I'd want fixed but they're not necessarily release-gating if documented.
