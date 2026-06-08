mod common;

use common::run_guardian_payload;

#[test]
fn payload_stdin_echo_without_tpf() {
    let run = run_guardian_payload(&[], Some(b"piped payload")).expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "piped payload");
}
