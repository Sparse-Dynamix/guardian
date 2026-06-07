mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[cfg(unix)]
fn interrupt_exits_130_and_stops_child() {
    if which::which("sleep").is_err() {
        eprintln!("skipping: sleep not found");
        return;
    }

    let ca_dir = tempfile::TempDir::new().expect("ca dir");
    let bin = common::guardian_bin();
    assert!(bin.is_file(), "guardian binary missing at {}", bin.display());

    let mut child = Command::new(&bin)
        .args([
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--",
            "sleep",
            "60",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn guardian");

    let guardian_pid = child.id();
    std::thread::sleep(Duration::from_secs(2));

    unsafe {
        libc::kill(guardian_pid as i32, libc::SIGINT);
    }

    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait guardian") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("guardian did not exit after SIGINT");
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    assert_eq!(status.code(), Some(130), "expected exit 130 on SIGINT");
}
