## Smaller things

- `proxy.rs` has both `start_proxy` and `start_proxy_and_wait`; fine, but `wait_for_listener` connecting via `TcpStream::connect` actually opens a real connection to the proxy on every poll, which the proxy then has to handle/drop. Minor.
- After shutdown there's a hardcoded `sleep(500ms)` in `main.rs` before cancelling the proxy — a smell that there's a races being papered over.

---

## Verdict

**Engineering quality: strong. Beta-readiness: not yet.** If I had to gate it, the blockers are:

4. Add a CI workflow and reconcile versioning (#12).
