mod common;

use common::run_guardian_payload;

/// Host-aware `--filter` expressions are accepted in passthrough payload mode.
#[test]
fn host_filter_expression_accepted() {
    let run = run_guardian_payload(
        &[
            "--filter",
            r#"host && /\.example\.com$/.test(host)"#,
            "--payload",
            "ok",
        ],
        None,
    )
    .expect("spawn guardian");
    assert_eq!(run.exit_code, 0);
    assert_eq!(run.stdout, "ok");
}
