//! Minimal WebSocket echo client for integration tests (spawned under guardian).

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

#[cfg(not(target_os = "macos"))]
mod tls {
    use std::sync::Arc;

    use anyhow::Result;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio_tungstenite::Connector;

    /// Proxelar MITM certificates are issued for the CONNECT authority, not the client SNI hostname.
    #[derive(Debug)]
    struct MitmSmokeVerifier;

    impl ServerCertVerifier for MitmSmokeVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    pub fn connector() -> Result<Connector> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(MitmSmokeVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Connector::Rustls(Arc::new(config)))
    }
}

#[cfg(target_os = "macos")]
mod tls {
    use anyhow::{Context, Result};
    use tokio_tungstenite::Connector;

    pub fn connector() -> Result<Connector> {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .context("native tls connector")?;
        Ok(Connector::NativeTls(connector))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::args()
        .nth(1)
        .context("usage: guardian-ws-smoke <ws-url>")?;
    let request = url.as_str().into_client_request()?;
    let connector = if url.starts_with("wss://") {
        Some(tls::connector()?)
    } else {
        None
    };
    let (mut ws, _) = connect_async_tls_with_config(request, None, false, connector)
        .await
        .context("websocket connect failed")?;
    ws.send(Message::Text("guardian-smoke".into()))
        .await
        .context("websocket send failed")?;
    if let Some(Ok(Message::Text(reply))) = ws.next().await {
        println!("{reply}");
    }
    ws.send(Message::Binary(vec![0, 159, 255, 1, 2].into()))
        .await
        .context("websocket binary send failed")?;
    let _ = ws.next().await;
    ws.close(None).await.ok();
    Ok(())
}
