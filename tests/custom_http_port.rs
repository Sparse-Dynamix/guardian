mod common;

use common::{assert_child_success, require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn custom_http_port_passthrough() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions {
        url: Some("http://httpbingo.org/get".into()),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}
