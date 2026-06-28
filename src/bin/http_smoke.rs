//! Minimal HTTP client for smoke tests on platforms whose curl lacks HTTP/2.

use std::time::Duration;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use anyhow::{Context, Result};
use http::Request;
use reqwest::Url;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut require_http2 = false;
    let mut h2c_prior_knowledge = false;
    let mut force_ipv4 = false;
    let mut include_headers = false;
    let mut max_time_secs: Option<u64> = None;
    let mut url = None;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--http2" => require_http2 = true,
            "--ipv4" => force_ipv4 = true,
            "--http2-prior-knowledge" => h2c_prior_knowledge = true,
            "-i" | "--include" => include_headers = true,
            "--max-time" => {
                let secs = args
                    .next()
                    .context("--max-time requires a value")?
                    .parse::<u64>()
                    .context("parse --max-time value")?;
                max_time_secs = Some(secs);
            }
            _ => url = Some(arg),
        }
    }

    let url = url.context("usage: guardian-http-smoke [--http2|--http2-prior-knowledge] [--max-time SECS] <url>")?;
    if h2c_prior_knowledge {
        return run_h2c(&url).await;
    }

    let timeout_secs = max_time_secs.unwrap_or(20);
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(timeout_secs));
    if require_http2 {
        builder = builder.http2_prior_knowledge();
    }
    if force_ipv4 {
        builder = configure_ipv4_resolution(builder, &url)?;
    }

    let response = builder
        .build()
        .context("build HTTP client")?
        .get(&url)
        .send()
        .await
        .context("HTTP request failed")?;
    let status = response.status();
    eprintln!(
        "guardian-http-smoke version={:?} status={status}",
        response.version()
    );
    if include_headers {
        println!("HTTP/1.1 {status}");
        for (name, value) in response.headers() {
            if let Ok(value) = value.to_str() {
                println!("{name}: {value}");
            }
        }
        println!();
    }
    let body = response.text().await.context("read response body")?;
    print!("{body}");

    if !status.is_success() {
        std::process::exit(22);
    }
    Ok(())
}

async fn run_h2c(url: &str) -> Result<()> {
    let parsed = Url::parse(url).context("parse h2c URL")?;
    if parsed.scheme() != "http" {
        anyhow::bail!("--http2-prior-knowledge requires an http:// URL");
    }

    let host = parsed.host_str().context("h2c URL missing host")?;
    let port = parsed
        .port_or_known_default()
        .context("h2c URL missing port and scheme default")?;
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}"))?
        .next()
        .with_context(|| format!("no addresses resolved for {host}"))?;
    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr))
        .await
        .context("h2c TCP connect timed out")?
        .context("h2c TCP connect failed")?;

    let (mut client, connection) = h2::client::handshake(stream)
        .await
        .context("h2c handshake failed")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut path_and_query = parsed.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(query) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    let authority = parsed
        .port()
        .map(|explicit_port| format!("{host}:{explicit_port}"))
        .unwrap_or_else(|| host.to_string());
    let request = Request::builder()
        .method("GET")
        .uri(path_and_query)
        .header(http::header::HOST, authority)
        .body(())
        .context("build h2c request")?;

    let (response, _) = client
        .send_request(request, true)
        .context("send h2c request")?;
    let response = response.await.context("read h2c response headers")?;
    let status = response.status();
    eprintln!(
        "guardian-http-smoke version={:?} status={status}",
        response.version()
    );

    let mut body = response.into_body();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.context("read h2c response body")?;
        print!("{}", String::from_utf8_lossy(&chunk));
    }

    if !status.is_success() {
        std::process::exit(22);
    }
    Ok(())
}

fn configure_ipv4_resolution(
    builder: reqwest::ClientBuilder,
    url: &str,
) -> Result<reqwest::ClientBuilder> {
    let parsed = Url::parse(url).context("parse URL for IPv4 resolution")?;
    let host = parsed.host_str().context("URL missing host")?;
    if IpAddr::from_str(host).is_ok_and(|ip| ip.is_ipv4()) {
        return Ok(builder.local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    let port = parsed
        .port_or_known_default()
        .context("URL missing port and scheme default")?;
    let ipv4_addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}"))?
        .filter(|addr| addr.is_ipv4())
        .collect();
    if ipv4_addrs.is_empty() {
        anyhow::bail!("no IPv4 addresses resolved for {host}");
    }

    Ok(builder
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .resolve_to_addrs(host, &ipv4_addrs))
}
