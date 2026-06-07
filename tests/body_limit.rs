mod common;

use common::{require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn body_limit_truncates_jsonl_previews() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions {
        body_limit: Some(32),
        url: Some("http://httpbin.org/bytes/512".to_string()),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");

    assert_eq!(run.exit_code, 0);
    assert!(
        run.stdout.len() >= 512,
        "curl should receive the full response body (got {} bytes)",
        run.stdout.len()
    );
    let http = run
        .jsonl
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
        .expect("http JSONL event");
    let response = http.get("response").expect("response object");
    assert_eq!(
        response
            .get("body_truncated")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(
        response.get("body_len").and_then(|v| v.as_u64()).unwrap_or(0) >= 512,
        "JSONL should record the full captured body length"
    );
}
