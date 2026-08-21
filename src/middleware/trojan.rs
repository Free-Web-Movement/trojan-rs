use std::sync::{Arc, Mutex};

use aex::connection::context::{BoxReader, Context};
use aex::http::types::Executor;
use futures::future::FutureExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::core::authenticator::Authenticator;
use crate::core::config::Config;
use crate::middleware::tls::{AlpnNegotiated, OutboundStream};
use crate::proto::socks5address::{ParseResult, Socks5Address};
use crate::proto::trojanrequest::{Command, TrojanRequest, MAX_HEADER_LENGTH};
use crate::session::{relay, resolve, run_udp_session, UdpRole, MAX_LENGTH};

const SOCKS5_VERSION: u8 = 5;
const SOCKS5_NO_AUTH: u8 = 0;

#[derive(Clone)]
pub struct Socks5Target {
    pub command: Command,
    pub address: Socks5Address,
}

#[derive(Clone, Default)]
pub struct ClientUdpSocket(pub Arc<Mutex<Option<Arc<UdpSocket>>>>);

impl ClientUdpSocket {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self(Arc::new(Mutex::new(Some(socket))))
    }

    pub fn take(&self) -> Option<Arc<UdpSocket>> {
        self.0.lock().unwrap().take()
    }
}

async fn read_more(reader: &mut BoxReader, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let chunk = reader.fill_buf().await?;
    if chunk.is_empty() {
        return Ok(0);
    }
    let n = chunk.len();
    buf.extend_from_slice(chunk);
    reader.consume(n);
    Ok(n)
}

fn alpn_fallback_port(config: &Config, ctx: &Context) -> u16 {
    if let Some(AlpnNegotiated(Some(alpn))) = ctx.local.get_value::<AlpnNegotiated>() {
        if let Some(port) = config.ssl.alpn_port_override.get(&alpn) {
            return *port;
        }
    }
    config.remote_port
}

async fn connect_outbound(
    config: &Config,
    host: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    let addr = resolve(host, port, config.tcp.prefer_ipv4).await?;
    let tcp = TcpStream::connect(addr).await?;
    if config.tcp.no_delay {
        let _ = tcp.set_nodelay(true);
    }
    if config.tcp.keep_alive {
        let ka = socket2::TcpKeepalive::new();
        let _ = socket2::SockRef::from(&tcp).set_tcp_keepalive(&ka);
    }
    Ok(tcp)
}

pub struct TrojanMiddleware;

impl TrojanMiddleware {
    /// Server-side middleware: parses the trojan request, authenticates the
    /// client and relays traffic to the requested target. Non-trojan traffic
    /// is forwarded to the fallback target (`remote_addr`/`remote_port`,
    /// with ALPN port override support).
    pub fn server(config: Arc<Config>, auth: Option<Arc<Authenticator>>) -> Arc<Executor> {
        Arc::new(move |ctx: &mut Context| {
            let config = config.clone();
            let auth = auth.clone();
            async move {
                let peer = ctx.addr;
                let Some(mut reader) = ctx.reader.take() else {
                    log::error!("{} trojan middleware: no reader in context", peer);
                    return false;
                };
                let Some(writer) = ctx.writer.take() else {
                    log::error!("{} trojan middleware: no writer in context", peer);
                    return false;
                };

                let mut buf: Vec<u8> = Vec::with_capacity(MAX_LENGTH);
                let parsed = loop {
                    match TrojanRequest::parse(&buf) {
                        ParseResult::Complete((req, consumed)) => break Ok((req, consumed)),
                        ParseResult::Invalid => break Err(buf.clone()),
                        ParseResult::Partial => {
                            if buf.len() > MAX_HEADER_LENGTH {
                                break Err(buf.clone());
                            }
                            match read_more(&mut reader, &mut buf).await {
                                Ok(0) => {
                                    if buf.is_empty() {
                                        return false;
                                    }
                                    break Err(buf.clone());
                                }
                                Ok(_) => {}
                                Err(_) => return false,
                            }
                        }
                    }
                };

                let (req, consumed) = match parsed {
                    Ok(v) => v,
                    Err(head) => {
                        let port = alpn_fallback_port(&config, ctx);
                        log::warn!(
                            "{} not trojan request, connecting to {}:{}",
                            peer,
                            config.remote_addr,
                            port
                        );
                        match connect_outbound(&config, &config.remote_addr, port).await {
                            Ok(tcp) => {
                                log::info!("{} tunnel established", peer);
                                let stats =
                                    relay(reader, writer, tcp, &head).await.unwrap_or_default();
                                log::info!(
                                    "{} disconnected, {} bytes received, {} bytes sent, lasted for {} seconds",
                                    peer,
                                    stats.recv,
                                    stats.sent,
                                    ctx.elapsed() / 1000
                                );
                            }
                            Err(e) => {
                                log::error!(
                                    "{} cannot establish connection to remote server {}:{}: {}",
                                    peer,
                                    config.remote_addr,
                                    port,
                                    e
                                );
                            }
                        }
                        return false;
                    }
                };

                let mut valid = config.hashed_passwords.contains_key(&req.password);
                let mut auth_password = String::new();
                if valid {
                    if let Some(original) = config.hashed_passwords.get(&req.password) {
                        log::info!("{} authenticated as {}", peer, original);
                    }
                } else if let Some(auth) = &auth {
                    if auth.auth(&req.password).await {
                        valid = true;
                        auth_password = req.password.clone();
                        log::info!(
                            "{} authenticated by authenticator ({})",
                            peer,
                            &req.password[..req.password.len().min(7)]
                        );
                    }
                }
                if !valid {
                    log::warn!(
                        "{} valid trojan request structure but possibly incorrect password ({})",
                        peer,
                        req.password
                    );
                }

                let leftover = buf[consumed..].to_vec();
                let stats = if !valid {
                    let port = alpn_fallback_port(&config, ctx);
                    match connect_outbound(&config, &config.remote_addr, port).await {
                        Ok(tcp) => relay(reader, writer, tcp, &buf).await.unwrap_or_default(),
                        Err(_) => Default::default(),
                    }
                } else {
                    match req.command {
                        Command::Connect => {
                            log::info!(
                                "{} requested connection to {}:{}",
                                peer,
                                req.address.address,
                                req.address.port
                            );
                            match connect_outbound(
                                &config,
                                &req.address.address,
                                req.address.port,
                            )
                            .await
                            {
                                Ok(tcp) => {
                                    log::info!("{} tunnel established", peer);
                                    relay(reader, writer, tcp, &leftover)
                                        .await
                                        .unwrap_or_default()
                                }
                                Err(e) => {
                                    log::error!(
                                        "{} cannot establish connection to remote server {}:{}: {}",
                                        peer,
                                        req.address.address,
                                        req.address.port,
                                        e
                                    );
                                    Default::default()
                                }
                            }
                        }
                        Command::UdpAssociate => {
                            log::info!(
                                "{} requested UDP associate to {}:{}",
                                peer,
                                req.address.address,
                                req.address.port
                            );
                            let bind_addr = if ctx.addr.is_ipv4() {
                                "0.0.0.0:0"
                            } else {
                                "[::]:0"
                            };
                            match UdpSocket::bind(bind_addr).await {
                                Ok(udp) => {
                                    run_udp_session(
                                        reader,
                                        writer,
                                        Arc::new(udp),
                                        UdpRole::Server {
                                            prefer_ipv4: config.tcp.prefer_ipv4,
                                        },
                                        config.udp_timeout,
                                        leftover,
                                    )
                                    .await
                                }
                                Err(e) => {
                                    log::error!("{} cannot bind UDP socket: {}", peer, e);
                                    Default::default()
                                }
                            }
                        }
                    }
                };

                if !auth_password.is_empty() {
                    if let Some(auth) = &auth {
                        auth.record(&auth_password, stats.recv, stats.sent).await;
                    }
                }
                log::info!(
                    "{} disconnected, {} bytes received, {} bytes sent, lasted for {} seconds",
                    peer,
                    stats.recv,
                    stats.sent,
                    ctx.elapsed() / 1000
                );
                false
            }
            .boxed()
        })
    }

    /// Client-side SOCKS5 middleware: performs the SOCKS5 handshake with the
    /// local client and stores the requested target in the context.
    pub fn socks5(_config: Arc<Config>) -> Arc<Executor> {
        Arc::new(|ctx: &mut Context| {
            async move {
                let peer = ctx.addr;
                let Some(reader) = ctx.reader.as_mut() else {
                    return false;
                };
                let Some(writer) = ctx.writer.as_mut() else {
                    return false;
                };

                let mut buf: Vec<u8> = Vec::with_capacity(MAX_LENGTH);
                loop {
                    if buf.len() >= 2 && buf.len() >= 2 + buf[1] as usize {
                        break;
                    }
                    match read_more(reader, &mut buf).await {
                        Ok(0) | Err(_) => return false,
                        Ok(_) => {}
                    }
                }
                if buf[0] != SOCKS5_VERSION {
                    log::error!("{} unknown protocol", peer);
                    return false;
                }
                let nmethods = buf[1] as usize;
                if !buf[2..2 + nmethods].contains(&SOCKS5_NO_AUTH) {
                    log::error!("{} unsupported auth method", peer);
                    let _ = writer.write_all(b"\x05\xff").await;
                    return false;
                }
                if writer.write_all(b"\x05\x00").await.is_err() {
                    return false;
                }

                buf.clear();
                let (command, address) = loop {
                    if buf.len() >= 4 {
                        if buf[0] != SOCKS5_VERSION || buf[2] != 0 {
                            log::error!("{} bad request", peer);
                            return false;
                        }
                        match Socks5Address::parse(&buf[3..]) {
                            ParseResult::Complete((addr, _)) => {
                                let command = match Command::from_byte(buf[1]) {
                                    Some(c) => c,
                                    None => {
                                        log::error!("{} unsupported command", peer);
                                        let _ = writer
                                            .write_all(&[
                                                0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00,
                                            ])
                                            .await;
                                        return false;
                                    }
                                };
                                break (command, addr);
                            }
                            ParseResult::Partial => {}
                            ParseResult::Invalid => {
                                log::error!("{} bad request", peer);
                                return false;
                            }
                        }
                    }
                    match read_more(reader, &mut buf).await {
                        Ok(0) | Err(_) => return false,
                        Ok(_) => {}
                    }
                };

                log::info!(
                    "{} requested {} to {}:{}",
                    peer,
                    if command == Command::UdpAssociate {
                        "UDP associate"
                    } else {
                        "connection"
                    },
                    address.address,
                    address.port
                );

                match command {
                    Command::Connect => {
                        if writer
                            .write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                            .await
                            .is_err()
                        {
                            return false;
                        }
                    }
                    Command::UdpAssociate => {
                        let bind_addr = if ctx.addr.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        };
                        let udp = match UdpSocket::bind(bind_addr).await {
                            Ok(u) => u,
                            Err(_) => return false,
                        };
                        let local = match udp.local_addr() {
                            Ok(a) => a,
                            Err(_) => return false,
                        };
                        log::info!(
                            "{} requested UDP associate to {}:{}, open UDP socket {} for relay",
                            peer,
                            address.address,
                            address.port,
                            local
                        );
                        let mut reply = vec![0x05, 0x00, 0x00];
                        reply.extend_from_slice(&Socks5Address::generate(local));
                        if writer.write_all(&reply).await.is_err() {
                            return false;
                        }
                        ctx.local.set_value(ClientUdpSocket::new(Arc::new(udp)));
                    }
                }

                ctx.local.set_value(Socks5Target { command, address });
                true
            }
            .boxed()
        })
    }

    /// Client-side trojan middleware: sends the trojan request header over the
    /// established TLS tunnel and relays traffic between the local client and
    /// the remote server.
    pub fn client(config: Arc<Config>) -> Arc<Executor> {
        Arc::new(move |ctx: &mut Context| {
            let config = config.clone();
            async move {
                let peer = ctx.addr;
                let Some(target) = ctx.local.get_value::<Socks5Target>() else {
                    return false;
                };
                let Some(outbound) = ctx.local.get_value::<OutboundStream>().and_then(|o| o.take())
                else {
                    log::error!("{} trojan client middleware: no outbound stream", peer);
                    return false;
                };

                let Some(hash) = config.hashed_passwords.keys().min().cloned() else {
                    log::error!("{} no password configured", peer);
                    return false;
                };

                let header = TrojanRequest::generate_for(&hash, target.command, &target.address);

                let mut outbound = outbound;
                if outbound.write_all(&header).await.is_err() {
                    return false;
                }

                let stats = match target.command {
                    Command::Connect => {
                        let Some(reader) = ctx.reader.take() else {
                            return false;
                        };
                        let Some(writer) = ctx.writer.take() else {
                            return false;
                        };
                        relay(reader, writer, outbound, &[]).await.unwrap_or_default()
                    }
                    Command::UdpAssociate => {
                        let Some(udp) =
                            ctx.local.get_value::<ClientUdpSocket>().and_then(|u| u.take())
                        else {
                            return false;
                        };
                        let (out_r, out_w) = tokio::io::split(outbound);
                        run_udp_session(
                            out_r,
                            out_w,
                            udp,
                            UdpRole::Client,
                            config.udp_timeout,
                            Vec::new(),
                        )
                        .await
                    }
                };

                log::info!(
                    "{} disconnected, {} bytes received, {} bytes sent, lasted for {} seconds",
                    peer,
                    stats.recv,
                    stats.sent,
                    ctx.elapsed() / 1000
                );
                false
            }
            .boxed()
        })
    }
}
