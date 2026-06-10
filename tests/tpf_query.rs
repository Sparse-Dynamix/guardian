mod common;

use common::{
    assert_child_success, fetch_tpf_requests, run_guardian_with_options_until, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

#[test]
fn mitm_tpf_posts_url_query() {
    let servers = spawn_test_servers(TestServersConfig::default());
    let opts = GuardianOptions {
        url: Some(servers.http_get_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    };
    let run = run_guardian_with_options_until(opts, |run| {
        run.exit_code == 0
            && !run.stdout.trim().is_empty()
            && fetch_tpf_requests(&servers)
                .iter()
                .any(|r| r.path_and_query.contains("url="))
    })
    .expect("spawn guardian");
    assert_child_success(&run);

    let http_filter = fetch_tpf_requests(&servers)
        .into_iter()
        .find(|r| r.path_and_query.contains("url="))
        .expect("expected TPF POST with url= query");
    assert!(
        !http_filter.body.is_empty(),
        "expected non-empty POST body from HTTP response filter"
    );
}
