mod common;

use common::{require_network, run_guardian_echo_env_var};

#[test]
fn skips_ca_env_when_parent_already_sets_bundle() {
    if !require_network() {
        return;
    }
    let run = run_guardian_echo_env_var(
        "CURL_CA_BUNDLE",
        &[("CURL_CA_BUNDLE", "/etc/ssl/certs/ca.pem")],
        None,
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
    let jdk = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/jdk-17");
    if !jdk.join("bin/keytool").is_file() {
        eprintln!("skipping: portable JDK not found at .cache/jdk-17");
        return;
    }
    let existing = "-Djavax.net.ssl.trustStore=/existing.p12 -Dfoo=bar";
    let run = run_guardian_echo_env_var(
        "JAVA_TOOL_OPTIONS",
        &[("JAVA_TOOL_OPTIONS", existing)],
        Some(&jdk),
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
    let run = run_guardian_echo_env_var(
        "NODE_OPTIONS",
        &[("NODE_OPTIONS", "--use-openssl-ca --max-old-space-size=64")],
        None,
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert_eq!(
        run.stdout.trim(),
        "--use-openssl-ca --max-old-space-size=64"
    );
}
