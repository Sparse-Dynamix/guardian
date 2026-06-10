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

**4. `try_wait_pid` treats "process gone" as exit code 0.**

```320:322:src/injector.rs
        match err.raw_os_error() {
            Some(libc::ESRCH) => WaitStatus::Exited(0),
```

Because Frida spawns the child (not a direct fork), you can't `waitpid` it, so you poll with `kill(pid,0)`. When the process disappears you report exit code `0` regardless of how it actually exited. For a passthrough/wrapper tool, propagating the real child exit code matters (CI, scripts, `&&` chains). The non-filtered path gets this right via `status.code()`; the filtered path can't and silently flattens to 0. Worth documenting at minimum.

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

**11. Cert pinning will hit real agents.** Many modern clients pin; `AGENTS.md` honestly lists these as limitations. That's good, but for a public beta you should expect a meaningful fraction of "it just hangs / fails" reports from exactly these. Some explicit detection + a clear error ("looks like this client pins certs, Guardian can't intercept") would massively cut support load.

**12. Version inconsistency.** `Cargo.toml` is `0.1.0`, `package.json` is `1.0.0`, and the code is littered with "v1" / "pre 1.0" language. Pick one story before a public release.

---

## Smaller things

- `proxy.rs` has both `start_proxy` and `start_proxy_and_wait`; fine, but `wait_for_listener` connecting via `TcpStream::connect` actually opens a real connection to the proxy on every poll, which the proxy then has to handle/drop. Minor.
- After shutdown there's a hardcoded `sleep(500ms)` in `main.rs` before cancelling the proxy — a smell that there's a races being papered over.
- No `--version`-surfaced build metadata (git SHA), which you'll want for beta bug reports.

---

## Verdict

**Engineering quality: strong. Beta-readiness: not yet.** If I had to gate it, the blockers are:

1. Fix/verify the env-var config (#1) — a documented interface that looks broken.
2. Lock down the CA private key permissions (#6) — non-negotiable for a security tool.
4. Add a SECURITY.md + CI workflow and reconcile versioning (#8, #12).
