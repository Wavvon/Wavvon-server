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

/// Open connections beyond this are closed on accept. WebSockets count, so it
/// bounds sockets per hub, not requests.
// ponytail: fixed cap; make it a setting when a hub outgrows it.
pub const MAX_CONNECTIONS: usize = 10_000;

/// How long a client may take to send a request's headers, including the wait
/// for the next request on a kept-alive connection.
pub const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// An acceptor that holds a semaphore permit for each connection's lifetime
/// and drops new ones while none is free. Wrap it inside TLS so a refused
/// connection costs no handshake.
#[derive(Clone)]
pub struct LimitAcceptor<A> {
    inner: A,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl<A> LimitAcceptor<A> {
    pub fn new(inner: A, max: usize) -> Self {
        Self {
            inner,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(max)),
        }
    }
}

impl<I, S, A> axum_server::accept::Accept<I, S> for LimitAcceptor<A>
where
    A: axum_server::accept::Accept<I, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Limited<A::Stream>;
    type Service = A::Service;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<(Self::Stream, A::Service)>> + Send>,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return Box::pin(std::future::ready(Err(std::io::Error::other(
                "connection limit reached",
            ))));
        };
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (inner, service) = fut.await?;
            Ok((
                Limited {
                    inner,
                    _permit: permit,
                },
                service,
            ))
        })
    }
}

/// A stream that frees its connection slot when dropped.
pub struct Limited<T> {
    inner: T,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Limited<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Limited<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// The hub's HTTP server over `listener`: header-read timeout and connection
/// cap on both the plaintext and the TLS path.
pub async fn serve(
    listener: TcpListener,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    app: axum::Router,
) -> std::io::Result<()> {
    serve_with(listener, tls, app, MAX_CONNECTIONS, HEADER_READ_TIMEOUT).await
}

async fn serve_with(
    listener: TcpListener,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    app: axum::Router,
    max_connections: usize,
    header_read_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let limited = LimitAcceptor::new(axum_server::accept::DefaultAcceptor, max_connections);
    match tls {
        Some(config) => {
            let mut server = axum_server::from_tcp(listener)
                .acceptor(axum_server::tls_rustls::RustlsAcceptor::new(config).acceptor(limited));
            configure(server.http_builder(), header_read_timeout);
            server
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        }
        None => {
            let mut server = axum_server::from_tcp(listener).acceptor(limited);
            configure(server.http_builder(), header_read_timeout);
            server
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
        }
    }
}

fn configure(
    builder: &mut hyper_util::server::conn::auto::Builder<hyper_util::rt::TokioExecutor>,
    header_read_timeout: std::time::Duration,
) {
    // hyper enforces no timeout at all without a timer.
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    builder.http2().timer(hyper_util::rt::TokioTimer::new());
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

    async fn start(max: usize, timeout: std::time::Duration) -> SocketAddr {
        let listener = http_listener(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "ok" }));
        tokio::spawn(serve_with(listener, None, app, max, timeout));
        addr
    }

    /// Reads until the server closes the connection, or gives up after 5 s.
    async fn closed_by_server(stream: &mut tokio::net::TcpStream) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    async fn a_slow_request_header_is_cut_off() {
        use tokio::io::AsyncWriteExt;
        let addr = start(10, std::time::Duration::from_millis(500)).await;
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        assert!(closed_by_server(&mut slow).await);
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_and_slots_come_back() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let addr = start(1, std::time::Duration::from_secs(30)).await;
        let first = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Let the server accept the first before the second arrives.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(closed_by_server(&mut second).await);

        drop(first);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
        third
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut body = String::new();
        third.read_to_string(&mut body).await.unwrap();
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
    }
}
