mod common;

use common::{run_guardian_payload, run_guardian_payload_until, spawn_tpf_mock};

#[test]
fn payload_pass_with_tpf() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "hello"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "hello");
}

#[test]
fn payload_reject_with_tpf() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload_until(
        &["--tpf", &mock.reject_url, "--payload", "hello"],
        None,
        |run| {
            run.exit_code == 1
                && run.stdout.contains("All content chunks flagged")
                && run.stdout.contains("Stage: Content moderation")
        },
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
    assert!(run.stdout.contains("All content chunks flagged"));
}
