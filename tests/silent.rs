mod common;

use common::{require_network, run_guardian_direct_https};

#[test]
fn silent_suppresses_jsonl_on_stderr() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_direct_https(true).expect("failed to spawn guardian");
    assert_eq!(
        run.exit_code, 0,
        "guardian exited with {}; stderr:\n{}",
        run.exit_code, run.stderr
    );
    assert!(
        run.jsonl.is_empty(),
        "expected no JSONL on stderr with --silent; got:\n{}",
        run.stderr
    );
    assert!(
        !run.stdout.trim().is_empty(),
        "expected non-empty child stdout"
    );
}
