mod common;

use std::sync::Arc;

use common::{
    assert_child_success, require_network, run_guardian_with_options_until, spawn_tpf_mock,
    GuardianOptions,
};

#[test]
fn mitm_tpf_posts_url_query() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let mock = spawn_tpf_mock();
    let requests = Arc::clone(&mock.requests);
    let opts = GuardianOptions {
        trypanophobe_filter: Some(mock.pass_url.clone()),
        ..GuardianOptions::default()
    };
    let run = run_guardian_with_options_until(opts, |run| {
        run.exit_code == 0
            && !run.stdout.trim().is_empty()
            && requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r.path_and_query.contains("url="))
    })
    .expect("spawn guardian");
    assert_child_success(&run);

    let http_filter = requests
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.path_and_query.contains("url="))
        .expect("expected TPF POST with url= query")
        .clone();
    assert!(
        !http_filter.body.is_empty(),
        "expected non-empty POST body from HTTP response filter"
    );
}
