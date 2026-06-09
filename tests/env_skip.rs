mod common;

use common::{portable_jdk_home, require_network, run_guardian_echo_env_var, spawn_tpf_mock};

#[test]
fn skips_ca_env_when_parent_already_sets_bundle() {
    if !require_network() {
        return;
    }
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "CURL_CA_BUNDLE",
        &[("CURL_CA_BUNDLE", "/etc/ssl/certs/ca.pem")],
        None,
        Some(&mock.pass_url),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert_eq!(run.stdout.trim(), "/etc/ssl/certs/ca.pem");
}

#[test]
fn skips_java_tool_options_when_truststore_already_set() {
    if !require_network() {
        return;
    }
    let Some(jdk) = portable_jdk_home() else {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17");
        return;
    };
    let existing = "-Djavax.net.ssl.trustStore=/existing.p12 -Dfoo=bar";
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "JAVA_TOOL_OPTIONS",
        &[("JAVA_TOOL_OPTIONS", existing)],
        Some(&jdk),
        Some(&mock.pass_url),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert_eq!(run.stdout.trim(), existing);
}

#[test]
fn skips_node_options_when_flag_already_present() {
    if !require_network() {
        return;
    }
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "NODE_OPTIONS",
        &[("NODE_OPTIONS", "--use-openssl-ca --max-old-space-size=64")],
        None,
        Some(&mock.pass_url),
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "--use-openssl-ca --max-old-space-size=64"
    );
}
