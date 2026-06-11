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

2. Lock down the CA private key permissions (#6) — non-negotiable for a security tool.
4. Add a SECURITY.md + CI workflow and reconcile versioning (#8, #12).
