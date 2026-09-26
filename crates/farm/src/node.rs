//! Where a hub actually is, and how to reach it.
//!
//! The farm has been able to run hubs on other machines for a while — the
//! agent reverse-connects and spawns them — but the proxy dialed
//! `127.0.0.1:<port>` for every one of them, so those hubs were unreachable
//! through the farm's own domain. This module is the missing half: a node has
//! a **host**, and a way to be trusted (farm-model.md, "Multi-node data
//! plane").
//!
//! Two trust modes, because the operator this layer targets is a self-hoster:
//!
//! - `ca` — ordinary certificate validation. For a node that already
//!   terminates TLS with a real certificate.
//! - `pin` — the agent advertises the SHA-256 of its self-signed certificate
//!   and the farm accepts that certificate and no other. The same primitive
//!   voice already uses (`voice_cert_hash`), rather than a new one.
//!
//! A private network between farm and nodes is not forbidden; it just becomes
//! an operator choice that makes either mode trivially satisfiable, rather
//! than a load-bearing assumption the farm cannot check.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

/// A hub's address as the farm resolved it: where the process is, and what
/// kind of connection reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTarget {
    /// The node's reachable host, or `None` for a hub on the farm's own
    /// machine — which is every hub a single-node farm has.
    pub host: Option<String>,
    pub port: u16,
    pub tls_mode: String,
    pub cert_sha256: Option<String>,
}

impl NodeTarget {
    /// A hub on this machine: no host recorded, or one that resolves to
    /// loopback. Reached over plain HTTP, exactly as before this existed.
    ///
    /// `localhost` counts. An operator who writes it means the same thing as
    /// `127.0.0.1`, and demanding TLS to a socket on the same machine would
    /// turn a correct configuration into an outage.
    pub fn is_local(&self) -> bool {
        match self.host.as_deref().map(str::trim) {
            None | Some("") => true,
            Some(host) => {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .map(|ip| ip.is_loopback())
                        .unwrap_or(false)
            }
        }
    }

    /// `http` on this machine, `https` to another one. There is no third
    /// option: a farm that quietly proxies plaintext across the open internet
    /// is the failure this design exists to refuse.
    pub fn scheme(&self) -> &'static str {
        if self.is_local() {
            "http"
        } else {
            "https"
        }
    }

    /// `host:port` for a URL or a `Host:` header.
    pub fn authority(&self) -> String {
        let host = match self.host.as_deref().map(str::trim) {
            None | Some("") => "127.0.0.1",
            Some(h) => h,
        };
        format!("{host}:{}", self.port)
    }

    /// The host to hand a TLS handshake, when there is one.
    pub fn tls_host(&self) -> Option<String> {
        if self.is_local() {
            return None;
        }
        self.host.as_deref().map(|h| h.trim().to_string())
    }
}

/// Accepts exactly one certificate, identified by the SHA-256 of its DER
/// encoding.
///
/// Deliberately not "accept anything": that is what `danger_accept_invalid_certs`
/// would give, and it would make `pin` mode weaker than `ca` rather than
/// stronger. The digest is the whole check — the node's certificate is
/// self-signed, so there is no chain to validate and no name to match, which
/// is exactly the situation voice's `serverCertificateHashes` was built for.
#[derive(Debug)]
struct PinnedCert {
    sha256: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let digest = hex::encode(Sha256::digest(end_entity.as_ref()));
        if digest.eq_ignore_ascii_case(&self.sha256) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "node certificate digest {digest} does not match the pinned {}",
                self.sha256
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The TLS configuration for reaching this node.
///
/// A pinned node with no digest recorded is an error rather than a fallback to
/// CA validation: the operator asked for pinning, and quietly validating some
/// other way is how a setting becomes a lie.
pub fn client_config(target: &NodeTarget) -> Result<ClientConfig> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));

    match target.tls_mode.as_str() {
        "pin" => {
            let sha256 = target
                .cert_sha256
                .clone()
                .filter(|d| !d.trim().is_empty())
                .context("node is set to pin its certificate but advertised no digest")?;
            let mut config = ClientConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .context("could not build a TLS configuration for a pinned node")?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCert {
                    sha256: sha256.trim().to_lowercase(),
                    provider,
                }))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(config)
        }
        _ => {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .context("could not build a TLS configuration for a node")?
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: Option<&str>) -> NodeTarget {
        NodeTarget {
            host: host.map(str::to_string),
            port: 4001,
            tls_mode: "ca".to_string(),
            cert_sha256: None,
        }
    }

    #[test]
    fn a_hub_with_no_host_is_the_farms_own_machine() {
        assert!(target(None).is_local());
        assert!(target(Some("")).is_local());
        assert!(target(Some("  ")).is_local());
        assert_eq!(target(None).scheme(), "http");
        assert_eq!(target(None).authority(), "127.0.0.1:4001");
    }

    #[test]
    fn loopback_written_any_way_stays_plaintext() {
        for host in ["127.0.0.1", "localhost", "LOCALHOST", "::1"] {
            assert!(target(Some(host)).is_local(), "{host} should be local");
            assert_eq!(target(Some(host)).scheme(), "http");
            assert_eq!(target(Some(host)).tls_host(), None);
        }
    }

    /// The rule the whole design rests on: another machine is reached over
    /// TLS, never plaintext.
    #[test]
    fn another_machine_is_always_tls() {
        let t = target(Some("node-2.example"));
        assert!(!t.is_local());
        assert_eq!(t.scheme(), "https");
        assert_eq!(t.authority(), "node-2.example:4001");
        assert_eq!(t.tls_host().as_deref(), Some("node-2.example"));
    }

    #[test]
    fn ca_mode_needs_no_digest_and_pin_mode_does() {
        let ca = target(Some("node-2.example"));
        assert!(client_config(&ca).is_ok());

        let mut pinned = target(Some("node-2.example"));
        pinned.tls_mode = "pin".to_string();
        assert!(
            client_config(&pinned).is_err(),
            "pinning with nothing to pin must fail rather than fall back to CA validation"
        );

        pinned.cert_sha256 = Some("ab".repeat(32));
        assert!(client_config(&pinned).is_ok());
    }
}
