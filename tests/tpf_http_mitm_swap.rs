mod common;

use common::{
    require_network, run_guardian_with_options, spawn_tpf_mock_with_swap_body, GuardianOptions,
};

#[test]
fn mitm_swap_replaces_body_and_content_type() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let mock = spawn_tpf_mock_with_swap_body(b"# swapped by TPF mock\n");
    let run = run_guardian_with_options(GuardianOptions {
        trypanophobe_filter: Some(mock.swap_url.clone()),
        trypanophobe_swap: true,
        curl_include_headers: true,
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert_eq!(run.exit_code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("swapped by TPF mock"),
        "stdout:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("text/markdown"),
        "expected swapped Content-Type in curl -i output:\n{}",
        run.stdout
    );
}
