//! LAN / offline mode: the private-address safety guard, self-signed cert
//! generation for the fingerprint-pinning trust tier, and mDNS/DNS-SD
//! advertisement.
//!
//! See `docs/docs/lan-mode.md` for the design. Two invariants this module
//! exists to enforce:
//!
//! 1. The no-CA trust tiers (self-signed, plaintext) must be **impossible**
//!    to enable on a publicly-routable address — [`resolve_lan_address`] is
//!    the hard guard.
//! 2. LAN mode never runs a local CA — [`load_or_create_self_signed`] only
//!    ever produces a single, stable, self-signed leaf cert whose fingerprint
//!    is meant to travel out-of-band (invite/QR/mDNS TXT record).

use std::net::IpAddr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Returns true if `ip` is loopback, RFC 1918 private, or link-local — i.e.
/// the address classes LAN mode is allowed to serve self-signed/plaintext
/// traffic on. See lan-mode.md §4.
pub fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() // 127/8
                || v4.is_private() // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() // ::1
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10
        }
    }
}

/// Resolve the address LAN mode will advertise/be reached at, and enforce
/// the hard private-address guard against it.
///
/// `configured` is `Settings::lan_advertise_addr` (`WAVVON_LAN_ADVERTISE_ADDR`).
/// When unset, the local outbound-facing IP is auto-detected. Either way the
/// result is validated against [`is_private_or_local`] before being
/// returned — this is what makes it structurally impossible for a LAN-mode
/// hub to end up advertising (or being told to bind) a public address.
///
/// `configured`, when present, must be a literal IP: LAN mode exists
/// precisely because there is no DNS to resolve a hostname against (see
/// lan-mode.md §1), so a non-IP value is a configuration error, not
/// something to resolve.
pub fn resolve_lan_address(configured: Option<&str>) -> Result<IpAddr> {
    let ip = match configured {
        Some(addr) => addr.parse::<IpAddr>().with_context(|| {
            format!(
                "WAVVON_LAN_ADVERTISE_ADDR '{addr}' is not a literal IP address. \
                 LAN mode has no DNS to resolve a hostname against — set it to a \
                 private IP, e.g. 192.168.1.50."
            )
        })?,
        None => detect_local_ip().context(
            "WAVVON_LAN_MODE is enabled but no WAVVON_LAN_ADVERTISE_ADDR was set and \
             the local network address could not be auto-detected. Set \
             WAVVON_LAN_ADVERTISE_ADDR explicitly.",
        )?,
    };

    if !is_private_or_local(&ip) {
        bail!(
            "WAVVON_LAN_MODE is enabled but the resolved address '{ip}' is not \
             private/loopback/link-local. Refusing to start: a LAN-mode hub \
             (self-signed or plaintext trust) must never be reachable from the \
             public internet. Use a private address (10.0.0.0/8, 172.16.0.0/12, \
             192.168.0.0/16, 169.254.0.0/16, fe80::/10) or disable WAVVON_LAN_MODE."
        );
    }

    Ok(ip)
}

/// Best-effort detection of the local outbound-facing IP address, used when
/// `WAVVON_LAN_ADVERTISE_ADDR` is not set.
///
/// Uses the classic "connect a UDP socket, read local_addr" trick: `connect`
/// on a UDP socket only asks the kernel to pick a route/local address, it
/// never actually sends a packet — so this works fully offline, including
/// on an air-gapped LAN with no route to the target address at all.
pub fn detect_local_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // 10.255.255.255 is just a plausible RFC1918 destination to force route
    // selection; nothing is ever sent there.
    socket.connect("10.255.255.255:1").ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// A self-signed LAN cert plus the fingerprint clients pin against.
pub struct LanCert {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 fingerprint of the DER cert, lowercase hex.
    pub fingerprint_hex: String,
}

/// Generate (once) or load a persisted self-signed TLS cert for LAN mode's
/// fingerprint-pinning tier.
///
/// Persisted at `cert_path`/`key_path` — by convention `lan_cert.pem` /
/// `lan_cert.key` in the working directory, alongside `hub_identity.json` —
/// so the fingerprint (and therefore any invite/QR already handed out) stays
/// valid across restarts.
pub fn load_or_create_self_signed(
    cert_path: &Path,
    key_path: &Path,
    advertise_ip: IpAddr,
) -> Result<LanCert> {
    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("Failed to read LAN cert {cert_path:?}"))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read LAN key {key_path:?}"))?;
        let fingerprint_hex = fingerprint_from_pem(&cert_pem)?;
        return Ok(LanCert {
            cert_pem,
            key_pem,
            fingerprint_hex,
        });
    }

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .context("Failed to initialize self-signed LAN cert params")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Wavvon LAN Hub");
    params.subject_alt_names = vec![
        rcgen::SanType::IpAddress(advertise_ip),
        rcgen::SanType::DnsName("localhost".try_into().context("Invalid SAN 'localhost'")?),
    ];

    let key_pair = rcgen::KeyPair::generate().context("Failed to generate LAN cert keypair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign LAN cert")?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let fingerprint_hex = hex::encode(Sha256::digest(cert.der()));

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("Failed to write LAN cert {cert_path:?}"))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("Failed to write LAN key {key_path:?}"))?;

    Ok(LanCert {
        cert_pem,
        key_pem,
        fingerprint_hex,
    })
}

fn fingerprint_from_pem(cert_pem: &str) -> Result<String> {
    let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .context("LAN cert PEM contains no certificate")?
        .context("Failed to parse LAN cert PEM")?;
    Ok(hex::encode(Sha256::digest(&der)))
}

/// Parameters for the mDNS/DNS-SD `_wavvon._tcp.local` announcement.
pub struct MdnsAnnounceParams<'a> {
    pub hub_name: &'a str,
    pub advertise_ip: IpAddr,
    pub port: u16,
    /// `"self"` or `"none"` — mirrors `Settings::lan_tls_mode`.
    pub tls_mode: &'a str,
    /// Fingerprint (self-signed tier) or hub identity pubkey hex (plaintext
    /// tier), so clients always have *something* to pin/verify against.
    pub fingerprint_or_pubkey: &'a str,
}

/// Start advertising this hub over mDNS. Returns the `ServiceDaemon`, which
/// must be kept alive for the advertisement to persist — dropping it
/// unregisters the service. Callers on a sandboxed/offline CI box where
/// multicast sockets aren't available should treat an `Err` here as
/// non-fatal (log and continue): mDNS is a discovery convenience, not part
/// of the safety invariant.
pub fn start_mdns_advertiser(params: &MdnsAnnounceParams) -> Result<mdns_sd::ServiceDaemon> {
    let daemon = mdns_sd::ServiceDaemon::new().context("Failed to start mDNS responder")?;

    let ip_str = params.advertise_ip.to_string();
    // mdns-sd derives an instance/host name; sanitize the hub name into
    // something DNS-SD-safe (ASCII, no dots) rather than rejecting odd names.
    let instance_name: String = params
        .hub_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let instance_name = if instance_name.is_empty() {
        "wavvon-hub".to_string()
    } else {
        instance_name
    };
    let host_name = format!("{instance_name}.local.");

    let properties = [
        ("name", params.hub_name),
        ("fp", params.fingerprint_or_pubkey),
        ("port", &params.port.to_string()),
        ("tls", params.tls_mode),
        ("v", "1"),
    ];

    let service_info = mdns_sd::ServiceInfo::new(
        "_wavvon._tcp.local.",
        &instance_name,
        &host_name,
        ip_str.as_str(),
        params.port,
        &properties[..],
    )
    .context("Failed to build mDNS ServiceInfo")?;

    daemon
        .register(service_info)
        .context("Failed to register mDNS service")?;

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_v4_addresses_are_accepted() {
        for addr in [
            "192.168.1.50",
            "10.0.0.1",
            "172.16.5.5",
            "127.0.0.1",
            "169.254.1.1",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(is_private_or_local(&ip), "{addr} should be private/local");
        }
    }

    #[test]
    fn public_v4_addresses_are_rejected() {
        for addr in ["8.8.8.8", "1.1.1.1", "203.0.113.7"] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(
                !is_private_or_local(&ip),
                "{addr} should NOT be private/local"
            );
        }
    }

    #[test]
    fn link_local_v6_is_accepted() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_or_local(&ip));
    }

    #[test]
    fn loopback_v6_is_accepted() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_or_local(&ip));
    }

    #[test]
    fn global_v6_is_rejected() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_private_or_local(&ip));
    }

    #[test]
    fn resolve_lan_address_happy_path_with_explicit_private_addr() {
        let ip = resolve_lan_address(Some("192.168.1.50")).expect("should accept private addr");
        assert_eq!(ip, "192.168.1.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_lan_address_rejects_public_addr() {
        let err = resolve_lan_address(Some("8.8.8.8")).unwrap_err();
        assert!(
            err.to_string().contains("Refusing to start"),
            "expected refusal message, got: {err}"
        );
    }

    #[test]
    fn resolve_lan_address_rejects_non_ip_hostname() {
        let err = resolve_lan_address(Some("hub.example.com")).unwrap_err();
        assert!(
            err.to_string().contains("not a literal IP address"),
            "expected literal-IP error, got: {err}"
        );
    }

    #[test]
    fn self_signed_cert_generation_and_reload_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("lan_cert.pem");
        let key_path = dir.path().join("lan_cert.key");
        let ip: IpAddr = "192.168.1.50".parse().unwrap();

        let first =
            load_or_create_self_signed(&cert_path, &key_path, ip).expect("first generation");
        assert!(first.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(first.fingerprint_hex.len(), 64, "sha256 hex is 64 chars");
        assert!(first.fingerprint_hex.chars().all(|c| c.is_ascii_hexdigit()));

        let second =
            load_or_create_self_signed(&cert_path, &key_path, ip).expect("reload from disk");
        assert_eq!(
            first.fingerprint_hex, second.fingerprint_hex,
            "reloading the persisted cert must reproduce the same fingerprint \
             so previously-issued invites/QR codes stay valid"
        );
        assert_eq!(first.cert_pem, second.cert_pem);
    }
}
