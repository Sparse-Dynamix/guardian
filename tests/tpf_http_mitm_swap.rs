mod common;

use common::{
    require_network, run_guardian_with_options_until, spawn_tpf_mock_with_swap_body,
    GuardianOptions,
};

#[test]
fn mitm_swap_replaces_body_and_content_type() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let mock = spawn_tpf_mock_with_swap_body(b"# swapped by TPF mock\n");
    let opts = GuardianOptions {
        trypanophobe_filter: Some(mock.swap_url.clone()),
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
