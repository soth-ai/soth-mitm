use std::pin::Pin;
use std::task::{Context, Poll};

use mitm_core::DownstreamTlsBackend;
use mitm_tls::IssuedServerConfig;
#[cfg(not(target_os = "windows"))]
use openssl::pkey::PKey;
#[cfg(not(target_os = "windows"))]
use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslVerifyMode};
#[cfg(not(target_os = "windows"))]
use openssl::x509::X509;
#[cfg(not(target_os = "windows"))]
use tokio_openssl::SslStream as TokioOpenSslStream;
#[cfg(target_os = "windows")]
type TokioOpenSslStream<T> = T;
use tokio_rustls::server::TlsStream as RustlsTlsStream;
use tokio_rustls::TlsAcceptor;

pin_project_lite::pin_project! {
    #[project = DownstreamTlsStreamProj]
    pub(crate) enum DownstreamTlsStream {
        Rustls {
            #[pin]
            stream: RustlsTlsStream<TcpStream>,
        },
        OpenSsl {
            #[pin]
            stream: TokioOpenSslStream<TcpStream>,
        },
    }
}

impl DownstreamTlsStream {
    pub(crate) fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        match self {
            Self::Rustls { stream } => stream.get_ref().1.alpn_protocol().map(ToOwned::to_owned),
            Self::OpenSsl { stream } => {
                #[cfg(not(target_os = "windows"))]
                {
                    stream.ssl().selected_alpn_protocol().map(ToOwned::to_owned)
                }
                #[cfg(target_os = "windows")]
                {
                    let _ = stream;
                    None
                }
            }
        }
    }
}

impl AsyncRead for DownstreamTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.project() {
            DownstreamTlsStreamProj::Rustls { stream } => stream.poll_read(cx, buf),
            DownstreamTlsStreamProj::OpenSsl { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DownstreamTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.project() {
            DownstreamTlsStreamProj::Rustls { stream } => stream.poll_write(cx, buf),
            DownstreamTlsStreamProj::OpenSsl { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.project() {
            DownstreamTlsStreamProj::Rustls { stream } => stream.poll_flush(cx),
            DownstreamTlsStreamProj::OpenSsl { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.project() {
            DownstreamTlsStreamProj::Rustls { stream } => stream.poll_shutdown(cx),
            DownstreamTlsStreamProj::OpenSsl { stream } => stream.poll_shutdown(cx),
        }
    }
}

pub(crate) async fn accept_downstream_tls(
    backend: DownstreamTlsBackend,
    downstream: TcpStream,
    issued: &IssuedServerConfig,
    http2_enabled: bool,
) -> io::Result<DownstreamTlsStream> {
    match backend {
        DownstreamTlsBackend::Rustls => accept_with_rustls(downstream, issued).await,
        DownstreamTlsBackend::Openssl => {
            #[cfg(not(target_os = "windows"))]
            {
                return accept_with_openssl(downstream, issued, http2_enabled).await;
            }
            #[cfg(target_os = "windows")]
            {
                let _ = downstream;
                let _ = issued;
                let _ = http2_enabled;
                return Err(io::Error::other(
                    "downstream openssl backend is not supported on windows builds",
                ));
            }
        }
    }
}

async fn accept_with_rustls(
    downstream: TcpStream,
    issued: &IssuedServerConfig,
) -> io::Result<DownstreamTlsStream> {
    let acceptor = TlsAcceptor::from(Arc::clone(&issued.server_config));
    let stream = acceptor.accept(downstream).await.map_err(|error| {
        io::Error::other(format!("downstream rustls handshake failed: {error}"))
    })?;
    Ok(DownstreamTlsStream::Rustls { stream })
}

#[cfg(not(target_os = "windows"))]
async fn accept_with_openssl(
    downstream: TcpStream,
    issued: &IssuedServerConfig,
    http2_enabled: bool,
) -> io::Result<DownstreamTlsStream> {
    let acceptor = build_openssl_acceptor(issued, http2_enabled)?;
    let mut ssl = Ssl::new(acceptor.context()).map_err(|error| {
        io::Error::other(format!("build downstream openssl session failed: {error}"))
    })?;
    ssl.set_accept_state();

    let mut stream = TokioOpenSslStream::new(ssl, downstream).map_err(|error| {
        io::Error::other(format!("create downstream openssl stream failed: {error}"))
    })?;
    Pin::new(&mut stream).accept().await.map_err(|error| {
        io::Error::other(format!("downstream openssl handshake failed: {error}"))
    })?;

    Ok(DownstreamTlsStream::OpenSsl { stream })
}

#[cfg(not(target_os = "windows"))]
fn build_openssl_acceptor(
    issued: &IssuedServerConfig,
    http2_enabled: bool,
) -> io::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).map_err(|error| {
        io::Error::other(format!("build openssl acceptor failed: {error}"))
    })?;
    builder.set_verify(SslVerifyMode::NONE);

    let leaf_cert = X509::from_pem(issued.leaf_identity.leaf_cert_pem.as_bytes()).map_err(|error| {
        io::Error::other(format!("parse leaf certificate PEM failed: {error}"))
    })?;
    let leaf_key = PKey::private_key_from_pem(issued.leaf_identity.leaf_key_pem.as_bytes())
        .map_err(|error| io::Error::other(format!("parse leaf key PEM failed: {error}")))?;
    let ca_cert = X509::from_pem(issued.leaf_identity.ca_cert_pem.as_bytes()).map_err(|error| {
        io::Error::other(format!("parse CA certificate PEM failed: {error}"))
    })?;

    builder
        .set_private_key(&leaf_key)
        .map_err(|error| io::Error::other(format!("set openssl private key failed: {error}")))?;
    builder
        .set_certificate(&leaf_cert)
        .map_err(|error| io::Error::other(format!("set openssl leaf certificate failed: {error}")))?;
    builder
        .add_extra_chain_cert(ca_cert)
        .map_err(|error| io::Error::other(format!("set openssl chain certificate failed: {error}")))?;
    builder
        .check_private_key()
        .map_err(|error| io::Error::other(format!("openssl private key check failed: {error}")))?;

    let allow_http2 = http2_enabled;
    builder.set_alpn_select_callback(move |_ssl, client| {
        select_client_alpn(client, allow_http2).ok_or(AlpnError::NOACK)
    });

    Ok(builder.build())
}

#[cfg(not(target_os = "windows"))]
fn select_client_alpn(client_wire: &[u8], allow_http2: bool) -> Option<&[u8]> {
    if allow_http2 {
        if let Some(proto) = find_alpn(client_wire, b"h2") {
            return Some(proto);
        }
    }
    find_alpn(client_wire, b"http/1.1")
}

#[cfg(not(target_os = "windows"))]
fn find_alpn<'a>(client_wire: &'a [u8], needle: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0usize;
    while pos < client_wire.len() {
        let len = client_wire[pos] as usize;
        pos += 1;
        if len == 0 || pos + len > client_wire.len() {
            return None;
        }
        let candidate = &client_wire[pos..pos + len];
        if candidate == needle {
            return Some(candidate);
        }
        pos += len;
    }
    None
}
