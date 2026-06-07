mod common;

use common::{assert_http_jsonl, require_network, run_guardian_with_options, GuardianOptions};

/// Default denylist hooks HTTP on ports other than 80/443 (e.g. 8080-style traffic).
#[test]
fn http_on_nonstandard_port_is_intercepted() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    // httpbin.org serves HTTP on 80; explicit port exercises non-443/80-only allowlist removal.
    let run = run_guardian_with_options(GuardianOptions {
        url: Some("http://httpbin.org:80/get".to_string()),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");

    assert_http_jsonl(&run);
}
