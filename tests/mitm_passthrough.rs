mod common;

use common::{assert_child_success, require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn mitm_without_tpf_runs_child_directly() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions::default()).expect("spawn guardian");
    assert_child_success(&run);
    assert!(
        !run.stderr.contains("\"type\":\"http\""),
        "passthrough should not emit JSONL"
    );
}
