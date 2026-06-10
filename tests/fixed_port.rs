mod common;

use common::{
    assert_child_success, require_network, run_guardian_with_options, spawn_test_servers,
    GuardianOptions, TestServersConfig,
};

#[test]
fn fixed_port_passthrough_runs_child() {
    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_with_options(GuardianOptions {
        port: Some(18080),
        url: Some(servers.http_get_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}

#[test]
fn fixed_port_filtered_mitm_runs_child() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }
    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_with_options(GuardianOptions {
        port: Some(18081),
        url: Some(common::smoke_url()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}
