mod common;

use common::{
    fetch_tpf_requests, run_guardian_payload, run_guardian_payload_until, spawn_tpf_mock,
    spawn_tpf_mock_reject_body_containing, spawn_tpf_mock_with_swap_body,
};

const PAYLOAD_SOURCE_URL: &str = "guardian://payload";

#[test]
fn payload_echo_without_tpf() {
    let run = run_guardian_payload(&["--payload", "echo-me"], None).expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "echo-me");
}

#[test]
fn payload_partial_206_without_swap_blocks() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload_until(
        &["--tpf", &mock.partial_url, "--payload", "partial"],
        None,
        |run| run.exit_code == 1 && run.stdout.contains("filter HTTP 206"),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
}

#[test]
fn payload_pass_echoes_input() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "alpha"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "alpha");
}

#[test]
fn payload_reject_returns_explicit_block_reason() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload_until(
        &["--tpf", &mock.reject_url, "--payload", "beta"],
        None,
        |run| {
            run.exit_code == 1
                && run.stdout.contains("All content chunks flagged")
                && run.stdout.contains("Stage: Content moderation")
        },
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
fn payload_partial_206_swap_replaces_stdout() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload_until(
        &["--tpf", &mock.partial_url, "--tps", "--payload", "partial"],
        None,
        |run| run.exit_code == 0 && run.stdout == "PARTIAL_SAFE_MD",
    )
    .expect("spawn guardian");
    assert_eq!(run.stdout, "PARTIAL_SAFE_MD");
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
        |run| run.exit_code == 1 && run.stdout.contains("Content rejected by mock needle"),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
}

#[test]
fn payload_posts_body_and_source_url_to_tpf_mock() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "record-me"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    let requests = fetch_tpf_requests(mock.servers());
    assert!(
        requests.iter().any(|r| r.body == b"record-me"),
        "expected TPF mock to record payload body"
    );
    assert!(
        requests.iter().any(|r| {
            r.path_and_query.contains("url=")
                && (r.path_and_query.contains(PAYLOAD_SOURCE_URL)
                    || r.path_and_query.contains("guardian%3A%2F%2Fpayload"))
        }),
        "expected TPF POST with url={PAYLOAD_SOURCE_URL}, got: {:?}",
        requests
            .iter()
            .map(|r| &r.path_and_query)
            .collect::<Vec<_>>()
    );
}
