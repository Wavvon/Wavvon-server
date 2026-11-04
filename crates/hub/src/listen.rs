//! The HTTP listener's socket.
//!
//! `[::]` with `IPV6_V6ONLY` off takes IPv4 and IPv6 on one socket. Binding
//! `0.0.0.0` alone left a hub with an AAAA record unreachable to IPv6 clients,
//! and made `localhost` on Windows, which tries `::1` first, pay a ~200 ms
//! fallback on every new connection (#280). Windows defaults `IPV6_V6ONLY` to
//! on, so it has to be switched off explicitly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};

use socket2::{Domain, Protocol, Socket, Type};

fn bind(ip: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    let addr = SocketAddr::new(ip, port);
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        socket.set_only_v6(false)?;
    }
    // What tokio's own bind does on Unix, so a restart does not wait out
    // TIME_WAIT. On Windows the option means something else (port stealing).
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Bind `ip:port`. The default `::` falls back to `0.0.0.0`, with a warning,
/// on a host without IPv6 (a container started with it disabled); an address
/// the operator chose is never second-guessed.
pub fn http_listener(ip: IpAddr, port: u16) -> std::io::Result<TcpListener> {
    match bind(ip, port) {
        Err(e)
            if ip == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                && e.kind() != std::io::ErrorKind::AddrInUse =>
        {
            tracing::warn!("IPv6 unavailable ({e}); listening on IPv4 only");
            bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        }
        r => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_address_answers_both_families() {
        let listener = http_listener(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).unwrap();
        let addr = listener.local_addr().unwrap();
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, addr.port())).expect("IPv4 loopback");
        if addr.is_ipv6() {
            std::net::TcpStream::connect((Ipv6Addr::LOCALHOST, addr.port()))
                .expect("IPv6 loopback");
        }
    }

    #[test]
    fn an_ipv4_address_stays_ipv4() {
        let listener = http_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        assert!(listener.local_addr().unwrap().is_ipv4());
    }
}
