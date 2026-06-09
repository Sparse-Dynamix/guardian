mod common;

use common::run_guardian_payload;

#[test]
fn tps_without_tpf_payload_errors() {
    let run = run_guardian_payload(&["--tps", "--payload", "hello"], None).expect("spawn guardian");
    assert_ne!(run.exit_code, 0);
    assert!(
        run.stderr.contains("tps") || run.stderr.contains("tpf"),
        "stderr:\n{}",
        run.stderr
    );
}
