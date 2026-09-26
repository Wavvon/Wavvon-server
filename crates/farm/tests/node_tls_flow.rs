//! The farm reaching a hub on another machine, over a real TLS handshake.
//!
//! The unit tests in `node` cover which scheme a row resolves to. This covers
//! the part that can only be wrong at runtime: whether `pin` mode actually
//! pins. A verifier that accepted anything would pass every test that only
//! asks "did it connect" — so the assertion that matters here is the
//! **refusal** of a certificate whose digest does not match.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wavvon_farm::node::{client_config, NodeTarget};

/// A TLS server on a random port with a fresh self-signed certificate for
/// `node.test`. Returns its port and the SHA-256 of the certificate's DER,
/// which is exactly what an agent would advertise.
async fn start_pinned_node() -> (u16, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let digest = hex::encode(Sha256::digest(cert_der.as_ref()));
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

    // Naming the provider rather than taking the process default: this binary
    // links both rustls backends (tokio-tungstenite pulls aws-lc-rs in, the
    // farm asks for ring), and rustls refuses to guess between them. Same
    // provider `node::client_config` uses, so the handshake has one backend on
    // both ends.
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der], key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let mut buf = [0u8; 64];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                }
            });
        }
    });

    (port, digest)
}

async fn handshake(port: u16, node: &NodeTarget) -> anyhow::Result<()> {
    let config = client_config(node)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from(node.host.clone().unwrap())?;
    let mut tls = connector.connect(name, tcp).await?;
    tls.write_all(b"GET / HTTP/1.1\r\nhost: node.test\r\n\r\n")
        .await?;
    Ok(())
}

fn pinned(digest: Option<&str>) -> NodeTarget {
    NodeTarget {
        host: Some("node.test".to_string()),
        port: 0,
        tls_mode: "pin".to_string(),
        cert_sha256: digest.map(str::to_string),
    }
}

#[tokio::test]
async fn a_pinned_node_is_reached_on_its_own_certificate() {
    let (port, digest) = start_pinned_node().await;
    handshake(port, &pinned(Some(&digest)))
        .await
        .expect("the advertised digest must be the one that connects");
}

/// The assertion the whole mode rests on. A self-signed certificate has no
/// chain to validate and no CA to appeal to, so if the digest is not checked,
/// nothing is.
#[tokio::test]
async fn a_certificate_that_does_not_match_the_pin_is_refused() {
    let (port, _digest) = start_pinned_node().await;
    let wrong = "ab".repeat(32);
    let result = handshake(port, &pinned(Some(&wrong))).await;
    assert!(
        result.is_err(),
        "a node presented a certificate that is not the pinned one and the farm accepted it"
    );
}

/// Two nodes, two certificates: one node's digest must not admit the other.
/// The failure this guards against is a verifier that compares against
/// whatever it was last given.
#[tokio::test]
async fn one_nodes_pin_does_not_admit_another() {
    let (port_a, digest_a) = start_pinned_node().await;
    let (port_b, digest_b) = start_pinned_node().await;
    assert_ne!(digest_a, digest_b, "two self-signed certs must differ");

    handshake(port_a, &pinned(Some(&digest_a))).await.unwrap();
    assert!(
        handshake(port_b, &pinned(Some(&digest_a))).await.is_err(),
        "node A's pin admitted node B"
    );
    handshake(port_b, &pinned(Some(&digest_b))).await.unwrap();
}

/// CA validation against a self-signed certificate fails, which is the point:
/// an operator who leaves `tls_mode` at its default does not silently get
/// pinning's laxity about chains.
#[tokio::test]
async fn ca_mode_does_not_accept_a_self_signed_node() {
    let (port, _digest) = start_pinned_node().await;
    let ca = NodeTarget {
        host: Some("node.test".to_string()),
        port: 0,
        tls_mode: "ca".to_string(),
        cert_sha256: None,
    };
    assert!(
        handshake(port, &ca).await.is_err(),
        "the default mode must still require a certificate that validates"
    );
}
