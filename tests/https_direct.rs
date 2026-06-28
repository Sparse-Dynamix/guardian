mod common;

use common::{
    assert_child_success, assert_no_jsonl_stderr, require_network, run_guardian_direct_https,
    run_guardian_with_options, spawn_test_servers, GuardianOptions, TestServersConfig,
};

#[test]
fn direct_https_passthrough_runs_child() {
    if !require_network() {
        eprintln!("skipping: GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let servers = spawn_test_servers(TestServersConfig::default());
    let run =
        run_guardian_direct_https(&servers.http_get_url).expect("failed to spawn guardian");
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}

#[test]
fn direct_https_filtered_mitm_runs_child() {
    if !require_network() {
        eprintln!("skipping: GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_with_options(GuardianOptions {
        trypanophobe_filter: Some(servers.pass_url.clone()),
        url: Some(servers.http2_get_url.clone()),
        curl_flags: vec!["--http2".to_string()],
        extra_env: vec![(
            "GUARDIAN_UPSTREAM_TLS".to_string(),
            format!("default+ca:{}", servers.origin_ca_pem.display()),
        )],
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}
