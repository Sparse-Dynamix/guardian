mod common;

use common::{run_guardian_with_options, spawn_ipv6_echo_server, GuardianOptions};

#[test]
fn mitm_ipv6_local_echo() {
    if std::net::TcpListener::bind("[::ffff:127.0.0.2]:0").is_err() {
        eprintln!("skipping: IPv6 loopback unavailable");
        return;
    }
    let origin = spawn_ipv6_echo_server();
    let url = format!("{}/", origin.base_url);

    let run = run_guardian_with_options(GuardianOptions {
        url: Some(url),
        ..GuardianOptions::default()
    })
    .expect("spawn guardian");

    assert!(
        run.stdout.contains("ipv6-works"),
        "expected IPv6-intercepted body; exit={} stderr:\n{} stdout:\n{}",
        run.exit_code,
        run.stderr,
        run.stdout
    );
}
