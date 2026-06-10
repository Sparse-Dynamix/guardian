mod common;

use std::time::Duration;

use common::{
    assert_child_success, run_guardian_with_options, spawn_sse_origin, spawn_tpf_mock,
    spawn_tpf_mock_reject_body_containing, GuardianOptions,
};

#[test]
fn mitm_sse_streaming_passes_events_incrementally() {
    let origin = spawn_sse_origin(&["alpha", "beta", "gamma"]);
    let mock = spawn_tpf_mock();
    let url = format!("{}/", origin.base_url);

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(url),
        trypanophobe_filter: Some(mock.pass_url),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
    assert!(run.stdout.contains("alpha"), "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("beta"), "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("gamma"), "stdout:\n{}", run.stdout);

    let requests = mock.requests.lock().unwrap();
    assert!(
        requests.len() >= 3,
        "expected gated per-chunk TPF checks, got {} requests",
        requests.len()
    );
}

#[test]
fn mitm_sse_streaming_blocks_on_rejected_chunk() {
    let origin = spawn_sse_origin(&["safe", "BLOCKME", "after"]);
    let mock = spawn_tpf_mock_reject_body_containing("BLOCKME");
    let url = format!("{}/", origin.base_url);

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(url),
        trypanophobe_filter: Some(mock.pass_url),
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
    let requests = mock.requests.lock().unwrap();
    assert!(
        !requests.is_empty(),
        "expected at least one TPF chunk check before block"
    );
}
