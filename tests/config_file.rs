mod common;

use std::fs;
use std::io::Write;

use common::{assert_child_success, require_network, run_guardian_with_options, GuardianOptions};
use tempfile::TempDir;

#[test]
fn config_file_settings_apply() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let dir = TempDir::new().unwrap();
    let cfg_path = dir.path().join("guardian.toml");
    let mut f = fs::File::create(&cfg_path).unwrap();
    writeln!(f, "bind = \"127.0.0.1\"").unwrap();

    let run = run_guardian_with_options(GuardianOptions {
        config: Some(cfg_path),
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}
