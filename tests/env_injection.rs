mod common;

use common::{portable_jdk_home, require_network, run_guardian_echo_env_var, spawn_tpf_mock};

#[test]
fn child_inherits_merged_node_options() {
    if !require_network() {
        return;
    }
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "NODE_OPTIONS",
        &[("NODE_OPTIONS", "--max-old-space-size=128")],
        None,
        Some(&mock.pass_url),
    )
    .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("--use-openssl-ca"),
        "expected NODE_OPTIONS merge in child env: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("--max-old-space-size=128"),
        "expected existing NODE_OPTIONS preserved: {}",
        run.stdout
    );
}

#[test]
fn child_inherits_java_tool_options_when_jdk_available() {
    if !require_network() {
        return;
    }
    let Some(jdk) = portable_jdk_home() else {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17");
        return;
    };
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var(
        "JAVA_TOOL_OPTIONS",
        &[("JAVA_TOOL_OPTIONS", "-Dfoo=bar")],
        Some(&jdk),
        Some(&mock.pass_url),
    )
    .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("javax.net.ssl.trustStore="),
        "expected JAVA_TOOL_OPTIONS truststore flags: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("-Dfoo=bar"),
        "expected existing JAVA_TOOL_OPTIONS preserved: {}",
        run.stdout
    );
}

#[test]
fn child_inherits_ca_bundle_env() {
    if !require_network() {
        return;
    }
    let mock = spawn_tpf_mock();
    let run = run_guardian_echo_env_var("CURL_CA_BUNDLE", &[], None, Some(&mock.pass_url))
        .expect("failed to spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("guardian-ca-bundle.pem"),
        "expected CA bundle path in child env: {}",
        run.stdout
    );
}
