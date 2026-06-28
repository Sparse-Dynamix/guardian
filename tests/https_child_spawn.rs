mod common;

use common::{
    assert_child_success, assert_no_jsonl_stderr, require_network, run_guardian_child_spawn,
    spawn_test_servers, TestServersConfig,
};

#[test]
fn child_spawn_passthrough_runs_child() {
    if !require_network() {
        eprintln!("skipping: GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_child_spawn(&servers.http_get_url).expect("failed to spawn guardian");
    assert_child_success(&run);
    assert_no_jsonl_stderr(&run);
}
