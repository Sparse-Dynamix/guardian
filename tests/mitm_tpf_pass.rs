mod common;

use common::{
    assert_child_success, require_network, run_guardian_with_options, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

#[test]
fn mitm_tpf_pass_forwards_response() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }
    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_with_options(GuardianOptions {
        url: Some(common::smoke_url()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
}
