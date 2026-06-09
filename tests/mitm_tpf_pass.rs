mod common;

use common::{
    assert_child_success, require_network, run_guardian_with_options, spawn_tpf_mock,
    GuardianOptions,
};

#[test]
fn mitm_tpf_pass_forwards_response() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let mock = spawn_tpf_mock();
    let run = run_guardian_with_options(GuardianOptions {
        trypanophobe_filter: Some(mock.pass_url.clone()),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_child_success(&run);
}
