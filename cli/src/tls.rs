use rustls::ClientConnection;
use rustls::StreamOwned;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;
use tungstenite::ClientRequestBuilder;
use tungstenite::WebSocket;
use tungstenite::handshake::HandshakeError;

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;
pub type WsConn = WebSocket<TlsStream>;

/// Loads the server's CA cert from a bundled PEM or a file path.
/// For now, uses the cert bundled at compile time.
fn tls_config() -> Arc<rustls::ClientConfig> {
    let cert_pem = include_bytes!("../server.crt");
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(&cert_pem[..]))
        .collect::<Result<_, _>>()
        .expect("invalid server cert");

    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store.add(cert).expect("failed to add cert");
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
}

/// Wrap an established TCP stream in TLS, then perform the WebSocket
/// handshake with `Authorization: Bearer <token>`. The URI is cosmetic —
/// the daemon doesn't route on path, it only validates the token.
pub fn connect(tcp_stream: TcpStream, token: &str) -> std::io::Result<WsConn> {
    let config = tls_config();
    let server_name = "abrasive".try_into().unwrap();
    let tls_conn = ClientConnection::new(config, server_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tls_stream = StreamOwned::new(tls_conn, tcp_stream);

    let req = ClientRequestBuilder::new("wss://abrasive/".parse().unwrap())
        .with_header("Authorization", format!("Bearer {token}"));

    let (ws, _resp) = tungstenite::client::client(req, tls_stream).map_err(|e| match e {
        HandshakeError::Failure(tungstenite::Error::Io(io)) => io,
        HandshakeError::Failure(other) => {
            std::io::Error::new(std::io::ErrorKind::Other, other.to_string())
        }
        HandshakeError::Interrupted(_) => {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, "ws handshake interrupted")
        }
    })?;

    Ok(ws)
}
