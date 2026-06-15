mod common;

use common::{
    fetch_tpf_requests, run_guardian_payload, run_guardian_payload_until, spawn_tpf_mock,
    spawn_tpf_mock_reject_body_containing, spawn_tpf_mock_with_swap_body,
};

#[test]
fn payload_pass_echoes_input() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "alpha"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "alpha");
}

#[test]
fn payload_reject_returns_block_message() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload_until(
        &["--tpf", &mock.reject_url, "--payload", "beta"],
        None,
        |run| run.exit_code == 1 && run.stdout.contains("Blocked by Guardian"),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
}

#[test]
fn payload_swap_replaces_stdout() {
    let mock = spawn_tpf_mock_with_swap_body(b"custom-swap-body");
    let run = run_guardian_payload_until(
        &["--tpf", &mock.swap_url, "--tps", "--payload", "gamma"],
        None,
        |run| run.exit_code == 0 && run.stdout == "custom-swap-body",
    )
    .expect("spawn guardian");
    assert_eq!(run.stdout, "custom-swap-body");
}

#[test]
fn payload_pass_without_swap_keeps_body() {
    let mock = spawn_tpf_mock_with_swap_body(b"ignored-swap-body");
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "delta"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "delta");
}

#[test]
fn payload_reject_by_body_needle() {
    let mock = spawn_tpf_mock_reject_body_containing("needle");
    let run = run_guardian_payload_until(
        &["--tpf", &mock.pass_url, "--payload", "has-needle-inside"],
        None,
        |run| run.exit_code == 1,
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
}

#[test]
fn payload_posts_body_to_tpf_mock() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "record-me"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    let requests = fetch_tpf_requests(mock.servers());
    assert!(
        requests.iter().any(|r| r.body == b"record-me"),
        "expected TPF mock to record payload body"
    );
}
