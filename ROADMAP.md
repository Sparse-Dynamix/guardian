## Security gaps (important for a security product)

**6. CA private key file permissions are never restricted.** The patch writes `rootCA.pem` + `rootCA-key.pem` via proxyapi, and nothing in `ca.rs`/`install.rs`/`mkcert.rs` chmods the key to `0600`. A locally-trusted root CA private key sitting at default umask (often `0644`) is a real local-privilege concern — anyone who reads it can MITM the user's entire machine for as long as the CA is trusted. For a tool that installs a system-trusted root, locking down the key is table stakes. I only see `0o755` on executables, never `0o600` on the key.

**7. Java truststore password is hardcoded (`"guardian"`) and passed on the command line.** 

```126:128:src/ca.rs
            let flag = format!(
                "-Djavax.net.ssl.trustStore={} -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword={pwd}",
```

It's a truststore (not a keystore), so the blast radius is limited, but the password ends up in `JAVA_TOOL_OPTIONS` / process args, visible to any local process via `ps`. Minor, but flag it.

---

## Product / design risks for the AI-harness use case

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
4. Add a CI workflow and reconcile versioning (#12).
