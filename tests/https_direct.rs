mod common;

use common::{
    assert_child_success, assert_no_jsonl_stderr, require_network, run_guardian_direct_https,
};

#[test]
fn direct_https_passthrough_runs_child() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_direct_https().expect("failed to spawn guardian");
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}
