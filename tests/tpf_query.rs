mod common;

use common::{require_network, run_guardian_with_options, spawn_tpf_mock, GuardianOptions};

#[test]
fn mitm_tpf_posts_url_query() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let mock = spawn_tpf_mock();
    let _run = run_guardian_with_options(GuardianOptions {
        trypanophobe_filter: Some(mock.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    let requests = mock.requests.lock().unwrap();
    let http_filter = requests
        .iter()
        .find(|r| r.path_and_query.contains("url="))
        .expect("expected at least one TPF POST with url= query");
    assert!(
        !http_filter.body.is_empty(),
        "expected non-empty POST body from HTTP response filter"
    );
}
