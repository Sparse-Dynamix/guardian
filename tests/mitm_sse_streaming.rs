mod common;

use std::time::Duration;

use common::{
    assert_child_success, fetch_tpf_requests, run_guardian_with_options, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

#[test]
fn mitm_sse_streaming_passes_events_incrementally() {
    let servers = spawn_test_servers(TestServersConfig {
        sse_events: Some(vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ]),
        ..TestServersConfig::default()
    });
    let url = format!("{}/", servers.sse_base_url);

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(url),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
    assert!(run.stdout.contains("alpha"), "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("beta"), "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("gamma"), "stdout:\n{}", run.stdout);

    let requests = fetch_tpf_requests(&servers);
    assert!(
        requests.len() >= 3,
        "expected gated per-chunk TPF checks, got {} requests",
        requests.len()
    );
}

#[test]
fn mitm_sse_streaming_blocks_on_rejected_chunk() {
    let servers = spawn_test_servers(TestServersConfig {
        sse_events: Some(vec![
            "safe".to_string(),
            "BLOCKME".to_string(),
            "after".to_string(),
        ]),
        tpf_reject_needle: Some("BLOCKME".to_string()),
        ..TestServersConfig::default()
    });
    let url = format!("{}/", servers.sse_base_url);

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(url),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("safe"), "stdout:\n{}", run.stdout);
    assert!(
        run.stdout.contains("Blocked by Guardian") || !run.stdout.contains("after"),
        "stream should be cut on blocked chunk; stdout:\n{}",
        run.stdout
    );

    std::thread::sleep(Duration::from_millis(100));
    let requests = fetch_tpf_requests(&servers);
    assert!(
        !requests.is_empty(),
        "expected at least one TPF chunk check before block"
    );
}
