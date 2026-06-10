mod common;

use common::{
    assert_child_success, run_guardian_with_options, spawn_test_servers, GuardianOptions,
    TestServersConfig,
};

#[test]
fn mitm_tpf_pass_forwards_response() {
    let servers = spawn_test_servers(TestServersConfig::default());
    let run = run_guardian_with_options(GuardianOptions {
        url: Some(servers.http_get_url.clone()),
        trypanophobe_filter: Some(servers.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
}
