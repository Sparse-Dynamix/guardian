mod common;

use common::{run_guardian_payload, run_guardian_payload_until, spawn_tpf_mock_with_swap_body};

#[test]
fn payload_swap_writes_tpf_body() {
    let mock = spawn_tpf_mock_with_swap_body(b"SWAPPED_BODY");
    let run = run_guardian_payload_until(
        &["--tpf", &mock.swap_url, "--tps", "--payload", "hello"],
        None,
        |run| run.exit_code == 0 && run.stdout == "SWAPPED_BODY",
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "SWAPPED_BODY");
}

#[test]
fn payload_without_swap_keeps_original() {
    let mock = spawn_tpf_mock_with_swap_body(b"SWAPPED_BODY");
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "hello"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "hello");
}
