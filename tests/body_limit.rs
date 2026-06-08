mod common;

use common::{require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn body_limit_truncates_jsonl_previews() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let opts = GuardianOptions {
        body_limit: Some(32),
        url: Some("http://httpbingo.org/bytes/512".to_string()),
        ..GuardianOptions::default()
    };

    let mut last_run = None;
    for attempt in 0..3 {
        let run = run_guardian_with_options(opts.clone()).expect("failed to spawn guardian");
        let has_http = run
            .jsonl
            .iter()
            .any(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"));
        if run.exit_code == 0 && run.stdout.len() >= 512 && has_http {
            assert_eq!(run.exit_code, 0);
            let http = run
                .jsonl
                .iter()
                .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
                .expect("http JSONL event");
            let response = http.get("response").expect("response object");
            assert_eq!(
                response.get("body_truncated").and_then(|v| v.as_bool()),
                Some(true)
            );
            assert!(
                response
                    .get("body_len")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    >= 512,
                "JSONL should record the full captured body length"
            );
            return;
        }
        last_run = Some(run);
        if attempt < 2 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    let run = last_run.expect("guardian run");
    assert_eq!(run.exit_code, 0);
    assert!(
        run.stdout.len() >= 512,
        "curl should receive the full response body (got {} bytes); stderr:\n{}",
        run.stdout.len(),
        run.stderr
    );
    let http = run
        .jsonl
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
        .expect("http JSONL event");
    let response = http.get("response").expect("response object");
    assert_eq!(
        response.get("body_truncated").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(
        response
            .get("body_len")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= 512,
        "JSONL should record the full captured body length"
    );
}
