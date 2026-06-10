mod common;

use common::{
    assert_child_success, require_network, run_guardian_with_options, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

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

#[test]
fn mitm_http2_local_self_signed_tpf() {
    let servers = spawn_test_servers(TestServersConfig::default());
    let upstream_tls = format!("default+ca:{}", servers.origin_ca_pem.display());

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(servers.http2_get_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        curl_flags: vec!["--http2".to_string()],
        extra_env: vec![("GUARDIAN_UPSTREAM_TLS".to_string(), upstream_tls)],
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
    assert!(
        run.stdout.contains("\"protocol\":\"h2\"") || run.stdout.contains("\"url\""),
        "expected local HTTPS HTTP/2 response body; stdout:\n{}",
        run.stdout
    );
}

#[test]
fn mitm_http2_local_h2c_passthrough() {
    let servers = spawn_test_servers(TestServersConfig::default());

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(servers.http2c_get_url.clone()),
        curl_flags: vec!["--http2-prior-knowledge".to_string()],
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
    assert!(
        run.stdout.contains("\"protocol\":\"h2\"") || run.stdout.contains("\"url\""),
        "expected local HTTP/2 response body; stdout:\n{}",
        run.stdout
    );
}
