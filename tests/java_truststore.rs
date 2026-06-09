mod common;

use common::{portable_jdk_home, require_network, spawn_tpf_mock};

#[test]
fn java_truststore_created_when_keytool_available() {
    if !require_network() {
        return;
    }
    let Some(java_home) = portable_jdk_home() else {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17 (run scripts/coverage-linux.zx.ts once)");
        return;
    };

    let _mitm_guard = common::acquire_mitm_test_lock();
    let ca_dir = tempfile::TempDir::new().expect("ca dir");
    let mock = spawn_tpf_mock();
    let url = common::smoke_url();
    let curl = common::curl_program();
    let mut cmd = std::process::Command::new(common::guardian_bin());
    cmd.env("JAVA_HOME", &java_home);
    cmd.stdin(std::process::Stdio::null());
    cmd.args([
        "--ca-dir",
        ca_dir.path().to_str().unwrap(),
        "--tpf",
        &mock.pass_url,
        "--",
        &curl,
        "-sS",
        &url,
    ]);
    let status = cmd.status().expect("guardian status");
    assert!(status.success(), "guardian run failed");

    let truststore = ca_dir.path().join("guardian-java-truststore.p12");
    assert!(
        truststore.is_file(),
        "expected PKCS12 truststore at {}",
        truststore.display()
    );
}
