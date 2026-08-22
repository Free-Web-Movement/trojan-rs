use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use aex::connection::context::{BoxReader, BoxWriter, Context};
use aex::http::types::Executor;
use futures::future::FutureExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls};

use crate::core::config::SSLConfig;
use crate::core::log::TrojanKeyLog;

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Adapts the split reader/writer halves carried by an aex context into a
/// single duplex stream so that a TLS handshake can be performed over them.
pub struct StreamPair {
    reader: BoxReader,
    writer: BoxWriter,
}

impl StreamPair {
    pub fn new(reader: BoxReader, writer: BoxWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for StreamPair {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamPair {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[derive(Clone, Default)]
pub struct OutboundStream(pub Arc<Mutex<Option<Box<dyn AsyncStream>>>>);

impl OutboundStream {
    pub fn new(stream: Box<dyn AsyncStream>) -> Self {
        Self(Arc::new(Mutex::new(Some(stream))))
    }

    pub fn take(&self) -> Option<Box<dyn AsyncStream>> {
        self.0.lock().unwrap().take()
    }
}

#[derive(Clone, Default)]
pub struct AlpnNegotiated(pub Option<String>);

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs?;
    if certs.is_empty() {
        anyhow::bail!("no certificate found in {}", path);
    }
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    match rustls_pemfile::private_key(&mut reader)? {
        Some(key) => Ok(key),
        None => anyhow::bail!("no private key found in {}", path),
    }
}

fn key_log() -> Option<Arc<dyn rustls::KeyLog>> {
    if crate::core::log::keylog_enabled() {
        Some(Arc::new(TrojanKeyLog))
    } else {
        None
    }
}

pub fn server_config(cfg: &SSLConfig) -> anyhow::Result<rustls::ServerConfig> {
    let certs = load_certs(&cfg.cert)?;
    let key = load_key(&cfg.key)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    if let Some(kl) = key_log() {
        config.key_log = kl;
    }
    Ok(config)
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn client_config(cfg: &SSLConfig) -> anyhow::Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    let mut config = if cfg.verify && cfg.verify_hostname {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };
    config.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    if let Some(kl) = key_log() {
        config.key_log = kl;
    }
    Ok(config)
}

pub struct TlsMiddleware;

impl TlsMiddleware {
    /// Server-side middleware: performs the TLS handshake over the inbound
    /// context streams (installed by the unified server) and installs the TLS
    /// halves back into `ctx.reader`/`ctx.writer`.
    pub fn accept(acceptor: TlsAcceptor) -> Arc<Executor> {
        Arc::new(move |ctx: &mut Context| {
            let acceptor = acceptor.clone();
            async move {
                let Some(reader) = ctx.reader.take() else {
                    log::error!("tls accept middleware: no reader in context");
                    return false;
                };
                let Some(writer) = ctx.writer.take() else {
                    log::error!("tls accept middleware: no writer in context");
                    return false;
                };
                match acceptor.accept(StreamPair::new(reader, writer)).await {
                    Ok(tls) => {
                        let alpn = tls
                            .get_ref()
                            .1
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).into_owned());
                        ctx.local.set_value(AlpnNegotiated(alpn));
                        let (reader, writer) = tokio::io::split(tls);
                        ctx.reader = Some(Box::new(BufReader::new(reader)));
                        ctx.writer = Some(Box::new(writer));
                        true
                    }
                    Err(e) => {
                        log::warn!("{} SSL handshake failed: {}", ctx.addr, e);
                        false
                    }
                }
            }
            .boxed()
        })
    }

    /// Client-side middleware: connects to `remote_addr:remote_port`, performs
    /// the TLS handshake (SNI from `ssl.sni` or the remote address) and stores
    /// the established TLS stream as the outbound stream in the context.
    pub fn connect(
        ssl_config: Arc<SSLConfig>,
        no_delay: bool,
        remote_addr: String,
        remote_port: u16,
    ) -> Arc<Executor> {
        Arc::new(move |ctx: &mut Context| {
            let ssl_config = ssl_config.clone();
            let remote_addr = remote_addr.clone();
            async move {
                let inner = match client_config(&ssl_config) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("failed to build TLS client config: {}", e);
                        return false;
                    }
                };
                let connector = TlsConnector::from(Arc::new(inner));
                let tcp = match TcpStream::connect((remote_addr.as_str(), remote_port)).await {
                    Ok(t) => t,
                    Err(e) => {
                        log::error!(
                            "{} cannot establish connection to remote server {}:{}: {}",
                            ctx.addr,
                            remote_addr,
                            remote_port,
                            e
                        );
                        return false;
                    }
                };
                if no_delay {
                    let _ = tcp.set_nodelay(true);
                }
                let sni = if ssl_config.sni.is_empty() {
                    remote_addr.clone()
                } else {
                    ssl_config.sni.clone()
                };
                let server_name = match ServerName::try_from(sni.clone()) {
                    Ok(n) => n.to_owned(),
                    Err(e) => {
                        log::error!("invalid SNI {}: {}", sni, e);
                        return false;
                    }
                };
                match connector.connect(server_name, tcp).await {
                    Ok(tls) => {
                        log::info!(
                            "{} tunnel established with {}:{}",
                            ctx.addr,
                            remote_addr,
                            remote_port
                        );
                        ctx.local.set_value(OutboundStream::new(Box::new(tls)));
                        true
                    }
                    Err(e) => {
                        log::error!(
                            "{} SSL handshake failed with {}:{}: {}",
                            ctx.addr,
                            remote_addr,
                            remote_port,
                            e
                        );
                        false
                    }
                }
            }
            .boxed()
        })
    }
}
