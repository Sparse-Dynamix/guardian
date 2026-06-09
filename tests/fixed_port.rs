mod common;

use common::{
    assert_child_success, require_network, run_guardian_with_options, spawn_tpf_mock,
    GuardianOptions,
};

#[test]
fn fixed_port_passthrough_runs_child() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions {
        port: Some(18080),
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

    let mock = spawn_tpf_mock();
    let run = run_guardian_with_options(GuardianOptions {
        port: Some(18081),
        trypanophobe_filter: Some(mock.pass_url),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}
