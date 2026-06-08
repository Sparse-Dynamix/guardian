mod common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{guardian_bin, require_network, resolve_executable, GuardianRun};

fn dns_lookup_args() -> Vec<String> {
    vec![
        resolve_executable("node"),
        "-e".to_string(),
        "require('dns').lookup('example.com', { family: 4 }, (err, address) => { if (err) { console.error(err); process.exit(1); } console.log(address); })".to_string(),
    ]
}

fn run_guardian_program(program_args: &[&str], timeout: Duration) -> std::io::Result<GuardianRun> {
    let bin = guardian_bin();
    assert!(
        bin.is_file(),
        "guardian binary missing at {}",
        bin.display()
    );

    let ca_dir = tempfile::TempDir::new()?;
    let mut args = vec![
        "--ca-dir".to_string(),
        ca_dir.path().display().to_string(),
        "--".to_string(),
    ];
    args.extend(program_args.iter().map(|s| (*s).to_string()));

    let mut child = Command::new(&bin);
    child.args(&args);
    child.stdout(Stdio::piped());
    child.stderr(Stdio::piped());

    let start = Instant::now();
    let mut process = child.spawn()?;
    let mut stdout = String::new();
    let mut stderr = String::new();

    loop {
        if let Some(mut out) = process.stdout.take() {
            out.read_to_string(&mut stdout)?;
            process.stdout = None;
        }
        if let Some(mut err) = process.stderr.take() {
            err.read_to_string(&mut stderr)?;
            process.stderr = None;
        }
        if let Some(status) = process.try_wait()? {
            return Ok(GuardianRun {
                exit_code: status.code().unwrap_or(-1),
                stdout,
                stderr,
                _ca_dir: ca_dir,
            });
        }
        if start.elapsed() > timeout {
            let _ = process.kill();
            let _ = process.wait();
            panic!(
                "guardian timed out after {:?} running {:?}; stderr:\n{}",
                timeout, program_args, stderr
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn spawned_dns_lookup_resolves_example_com() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let args = dns_lookup_args();
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let run = run_guardian_program(&refs, Duration::from_secs(15)).expect("failed to run guardian");

    assert_eq!(
        run.exit_code, 0,
        "DNS lookup failed under guardian; stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stdout.lines().any(|line| line.contains('.')),
        "expected IPv4 address in stdout; got:\n{}",
        run.stdout
    );
}

#[test]
fn spawned_curl_resolves_without_manual_resolve() {
    if !require_network() {
        eprintln!("skipping: network unreachable or GUARDIAN_SKIP_NETWORK set");
        return;
    }

    let curl = common::curl_program();
    let run = run_guardian_program(
        &[&curl, "-sSf", "--max-time", "15", "http://example.com/"],
        Duration::from_secs(30),
    )
    .expect("failed to run guardian");

    assert_eq!(
        run.exit_code, 0,
        "curl failed under guardian; stderr:\n{}",
        run.stderr
    );
    assert!(
        !run.stdout.trim().is_empty(),
        "expected curl response body; stderr:\n{}",
        run.stderr
    );
}
