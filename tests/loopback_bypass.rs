mod common;

use common::{
    assert_child_success, fetch_tpf_requests, run_guardian_with_options_once, spawn_test_servers,
    GuardianOptions, TestServersConfig, GUARDIAN_RUN_DEADLINE,
};

#[test]
fn loopback_bypass_skips_mitm_tpf_filter() {
    let servers = spawn_test_servers(TestServersConfig::default());
    assert!(
        servers.http_loopback_get_url.starts_with("http://127."),
        "expected loopback test server on 127/8, got {}",
        servers.http_loopback_get_url
    );

    let run = run_guardian_with_options_once(&GuardianOptions {
        url: Some(servers.http_loopback_get_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        curl_flags: vec![
            "--connect-timeout".to_string(),
            "3".to_string(),
            "--max-time".to_string(),
            "10".to_string(),
        ],
        ..GuardianOptions::default()
    })
    .unwrap_or_else(|e| {
        panic!("spawn guardian failed within {GUARDIAN_RUN_DEADLINE:?}: {e}");
    });
    assert_child_success(&run);

    let tpf_requests = fetch_tpf_requests(&servers);
    assert!(
        tpf_requests.is_empty(),
        "loopback connections must bypass MITM; unexpected TPF posts: {tpf_requests:?}"
    );
}
