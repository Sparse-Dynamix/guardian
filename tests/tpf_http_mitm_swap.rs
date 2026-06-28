mod common;

use common::{
    require_network, run_guardian_with_options_until, spawn_test_servers, GuardianOptions,
    TestServersConfig,
};

#[test]
fn mitm_swap_replaces_body_and_content_type() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }
    let servers = spawn_test_servers(TestServersConfig {
        tpf_swap_body: Some("# swapped by TPF mock\n".to_string()),
        ..TestServersConfig::default()
    });
    let opts = GuardianOptions {
        url: Some(servers.http_get_url.clone()),
        trypanophobe_filter: Some(servers.swap_url.clone()),
        trypanophobe_swap: true,
        curl_include_headers: true,
        ..GuardianOptions::default()
    };
    let run = run_guardian_with_options_until(opts, |run| {
        run.exit_code == 0
            && run.stdout.contains("swapped by TPF mock")
            && run.stdout.contains("text/markdown")
    })
    .expect("spawn guardian");

    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
}
