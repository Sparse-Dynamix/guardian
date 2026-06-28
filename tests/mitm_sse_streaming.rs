mod common;

use std::time::Duration;

use common::{
    fetch_tpf_requests, require_network, run_guardian_with_options_once, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

#[test]
fn mitm_sse_streaming_passes_events_incrementally() {
    if !require_network() {
        eprintln!("skipping: GUARDIAN_SKIP_NETWORK set");
        return;
    }
    let servers = spawn_test_servers(TestServersConfig::default());

    let run = run_guardian_with_options_once(&GuardianOptions {
        url: Some(servers.sse_stream_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        curl_flags: vec![
            "-H".to_string(),
            "Accept: text/event-stream".to_string(),
            "--max-time".to_string(),
            "6".to_string(),
        ],
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("event: ping"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(run.stdout.contains("id: 0"), "stdout:\n{}", run.stdout);

    let requests = fetch_tpf_requests(&servers);
    assert!(
        requests.len() >= 1,
        "expected gated per-chunk TPF checks, got {} requests",
        requests.len()
    );
}

#[test]
fn mitm_sse_streaming_blocks_on_rejected_chunk() {
    if !require_network() {
        eprintln!("skipping: GUARDIAN_SKIP_NETWORK set");
        return;
    }
    let servers = spawn_test_servers(TestServersConfig {
        tpf_reject_needle: Some("id: 1".to_string()),
        ..TestServersConfig::default()
    });

    let run = run_guardian_with_options_once(&GuardianOptions {
        url: Some(servers.sse_stream_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        curl_flags: vec![
            "-H".to_string(),
            "Accept: text/event-stream".to_string(),
            "--max-time".to_string(),
            "6".to_string(),
        ],
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("id: 0"), "stdout:\n{}", run.stdout);
    assert!(
        run.stdout.contains("Content rejected by mock needle"),
        "stdout:\n{}",
        run.stdout
    );

    std::thread::sleep(Duration::from_millis(100));
    let requests = fetch_tpf_requests(&servers);
    assert!(
        !requests.is_empty(),
        "expected at least one TPF chunk check before block"
    );
}
