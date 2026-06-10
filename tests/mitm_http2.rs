mod common;

use common::{assert_child_success, require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn mitm_http2_passthrough() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(common::smoke_https_url()),
        curl_flags: vec!["--http2".to_string()],
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
    assert!(
        run.stdout.contains("httpbingo.org") || run.stdout.contains("\"url\""),
        "expected httpbingo response body; stdout:\n{}",
        run.stdout
    );
}
