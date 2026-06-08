mod common;

use common::{assert_child_success, require_network, run_guardian_with_options, GuardianOptions};

#[test]
fn verbose_flag_still_runs_child() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let run = run_guardian_with_options(GuardianOptions {
        verbose: true,
        ..GuardianOptions::default()
    })
    .expect("failed to spawn guardian");
    assert_child_success(&run);
}
