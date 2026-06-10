use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use proxyapi::ca::Ssl;
use proxyapi::{Proxy, ProxyConfig, ProxyMode};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_START_TIMEOUT: Duration = Duration::from_secs(5);

fn wait_for_proxy(addr: SocketAddr) {
    let deadline = Instant::now() + PROXY_START_TIMEOUT;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("proxy did not start within {PROXY_START_TIMEOUT:?}");
}

fn read_connect_response(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("set read timeout");
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).expect("read CONNECT response");
    buf.truncate(n);
    buf
}

#[test]
fn embedded_proxy_connect_returns_200() {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let ca_dir = TempDir::new().expect("ca dir");
    Ssl::load_or_generate(ca_dir.path()).expect("generate CA");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let cancel = CancellationToken::new();
    let proxy_config = ProxyConfig {
        addr,
        mode: ProxyMode::Forward,
        event_tx: None,
        content_filter: None,
        ca_dir: ca_dir.path().to_path_buf(),
        upstream_tls: Default::default(),
        intercept: None,
        body_capture_limit: None,
        replay_rx: None,
    };
    let proxy = Proxy::new(proxy_config);
    let cancel_for_proxy = cancel.clone();
    rt.spawn(async move {
        let _ = proxy.start(cancel_for_proxy.cancelled_owned()).await;
    });

    wait_for_proxy(addr);

    let mut stream = TcpStream::connect_timeout(&addr, SOCKET_TIMEOUT).expect("connect to proxy");
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .expect("set write timeout");
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .expect("write CONNECT");

    let response = read_connect_response(&mut stream);
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected HTTP/1.1 200 CONNECT response, got: {text}"
    );

    cancel.cancel();
    rt.shutdown_timeout(Duration::from_secs(2));
}

#[test]
fn mock_proxy_connect_503_is_visible_to_client() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    listener.set_nonblocking(true).expect("set nonblocking");
    let addr = listener.local_addr().expect("local addr");

    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + PROXY_START_TIMEOUT;
        let mut stream = loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for mock CONNECT client");
            }
            if let Ok((s, _)) = listener.accept() {
                break s;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(SOCKET_TIMEOUT))
            .expect("write timeout");
        let mut req = [0u8; 256];
        let _ = stream.read(&mut req).expect("read request");
        stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            .expect("write 503");
    });

    let mut stream = TcpStream::connect_timeout(&addr, SOCKET_TIMEOUT).expect("connect mock");
    stream
        .write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
        .expect("write CONNECT");
    let response = read_connect_response(&mut stream);
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 503"),
        "expected 503 from mock proxy, got: {text}"
    );
    server.join().expect("mock server thread");
}
