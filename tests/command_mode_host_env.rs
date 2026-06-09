mod common;

use common::{require_network, run_guardian_echo_env_var, spawn_tpf_mock};

#[test]
fn passthrough_forwards_host_env() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo_env_var(
        "GUARDIAN_TEST_HOST_ENV",
        &[("GUARDIAN_TEST_HOST_ENV", "xyzzy")],
        None,
        None,
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("xyzzy"),
        "expected host env in passthrough child: {}",
        run.stdout
    );
}

#[test]
fn filtered_mitm_forwards_host_env() {
    if !require_network() {
        return;
    }
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "GUARDIAN_TEST_HOST_ENV",
        &[("GUARDIAN_TEST_HOST_ENV", "xyzzy")],
        None,
        Some(&mock.pass_url),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("xyzzy"),
        "expected host env in filtered child: {}",
        run.stdout
    );
}
