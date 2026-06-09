mod common;

use common::{run_guardian_payload, spawn_tpf_mock};

#[test]
fn payload_pass_with_tpf() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.pass_url, "--payload", "hello"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert!(run.stdout.contains(r#""safe":true"#));
}

#[test]
fn payload_reject_with_tpf() {
    let mock = spawn_tpf_mock();
    let run = run_guardian_payload(&["--tpf", &mock.reject_url, "--payload", "hello"], None)
        .expect("spawn guardian");
    assert_eq!(run.exit_code, 1);
    assert!(run.stdout.contains("Blocked by Guardian"));
}
