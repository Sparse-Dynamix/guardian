mod common;

use common::{assert_http_jsonl, require_network, run_guardian_child_spawn};

#[test]
fn child_spawn_reinstruments_and_logs_jsonl() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_child_spawn(false).expect("failed to spawn guardian");
    assert_http_jsonl(&run);
}
