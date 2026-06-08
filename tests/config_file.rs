mod common;

use std::fs;
use std::io::Write;

use common::{assert_http_jsonl, require_network, run_guardian_with_options, GuardianOptions};
use tempfile::TempDir;

#[test]
fn config_file_settings_apply_to_run() {
    if !require_network() {
        return;
    }

    let config_dir = TempDir::new().expect("temp config dir");
    let config_path = config_dir.path().join("guardian.toml");
    let mut file = fs::File::create(&config_path).expect("create config");
    writeln!(
        file,
        r#"
body_limit = 64
port = 18082
"#
    )
    .unwrap();

    let run = run_guardian_with_options(GuardianOptions {
        config: Some(config_path),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");

    assert_http_jsonl(&run);
    let http = run
        .jsonl
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("http"))
        .expect("http event");
    let response = http.get("response").expect("response");
    assert_eq!(
        response.get("body_truncated").and_then(|v| v.as_bool()),
        Some(true),
        "config body_limit should truncate JSONL response preview"
    );
}
