mod common;

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sleep_program() -> String {
    if cfg!(target_os = "macos") {
        let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for sub in [
            "target/debug/guardian-sleep",
            "target/release/guardian-sleep",
        ] {
            let path = manifest.join(sub);
            if path.is_file() {
                return path.display().to_string();
            }
        }
    }
    "sleep".to_string()
}

fn free_local_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn wait_for_listener(port: u16) {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("guardian proxy listener did not start");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[cfg(unix)]
fn interrupt_exits_130_and_stops_child() {
    if which::which("sleep").is_err() {
        eprintln!("skipping: sleep not found");
        return;
    }

    let ca_dir = tempfile::TempDir::new().expect("ca dir");
    let mock = common::spawn_tpf_mock();
    let bin = common::guardian_bin();
    assert!(
        bin.is_file(),
        "guardian binary missing at {}",
        bin.display()
    );
    let sleep = sleep_program();
    let port = free_local_port();
    let port_arg = port.to_string();

    let mut child = Command::new(&bin)
        .args([
            "--ca-dir",
            ca_dir.path().to_str().unwrap(),
            "--tpf",
            mock.pass_url.as_str(),
            "--port",
            port_arg.as_str(),
            "--",
            sleep.as_str(),
            "60",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn guardian");

    let guardian_pid = child.id();
    wait_for_listener(port);
    std::thread::sleep(Duration::from_millis(500));

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
