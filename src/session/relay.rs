use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(feature = "server")]
use futures::future::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::middleware::tls::AsyncStream;
use crate::proto::socks5address::Socks5Address;
use crate::proto::udppacket::UdpPacket;

pub const MAX_LENGTH: usize = 8192;

#[derive(Debug, Clone, Copy, Default)]
pub struct RelayStats {
    pub sent: u64,
    pub recv: u64,
}

/// Resolves `host:port`, preferring IPv4 results when requested.
pub async fn resolve(host: &str, port: u16, prefer_ipv4: bool) -> anyhow::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        anyhow::bail!("cannot resolve {}:", host);
    }
    if prefer_ipv4 {
        if let Some(v4) = addrs.iter().find(|a| a.is_ipv4()) {
            return Ok(*v4);
        }
    }
    Ok(addrs[0])
}

fn pump<R, W>(reader: R, writer: W, counter: Arc<AtomicU64>) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut reader = reader;
        let mut writer = writer;
        let mut buf = vec![0u8; MAX_LENGTH];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if writer.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    counter.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => break,
            }
        }
        let _ = writer.shutdown().await;
    })
}

/// Relays data between an inbound (reader/writer) pair and an outbound duplex
/// stream. Optionally writes `initial_payload` to the outbound stream first.
/// The session ends as soon as either direction finishes; byte counters stay
/// accurate because each direction counts incrementally.
pub async fn relay<R, W, S>(
    client_r: R,
    client_w: W,
    outbound: S,
    initial_payload: &[u8],
) -> anyhow::Result<RelayStats>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: AsyncStream + 'static,
{
    let mut outbound = outbound;
    if !initial_payload.is_empty() {
        outbound.write_all(initial_payload).await?;
    }
    let sent_counter = Arc::new(AtomicU64::new(0));
    let recv_counter = Arc::new(AtomicU64::new(0));
    let (out_r, out_w) = tokio::io::split(outbound);
    let mut up = pump(client_r, out_w, sent_counter.clone());
    let mut down = pump(out_r, client_w, recv_counter.clone());
    tokio::select! {
        _ = &mut up => down.abort(),
        _ = &mut down => up.abort(),
    }
    Ok(RelayStats {
        sent: sent_counter.load(Ordering::Relaxed),
        recv: recv_counter.load(Ordering::Relaxed),
    })
}

#[derive(Debug, Clone)]
pub enum UdpRole {
    /// Server side: forwards packets to the address embedded in each packet.
    Server { prefer_ipv4: bool },
    /// Client side: relays SOCKS5 UDP datagrams back to the last local sender.
    Client,
}

/// Runs a trojan UDP forwarding session over the given stream halves and UDP
/// socket until EOF, error, or inactivity timeout. `initial_buffer` holds
/// bytes that were already consumed from the stream before the session
/// started (e.g. payload following the trojan request header).
///
/// Server role: the socket talks to arbitrary targets embedded in each packet.
/// Client role: the socket is the local SOCKS5 relay; trojan packets travel
/// exclusively over the TCP stream in both directions.
pub async fn run_udp_session(
    mut stream_reader: impl AsyncRead + Unpin + Send + 'static,
    mut stream_writer: impl AsyncWrite + Unpin + Send + 'static,
    udp_socket: Arc<UdpSocket>,
    role: UdpRole,
    udp_timeout: i32,
    initial_buffer: Vec<u8>,
) -> RelayStats {
    let timeout = Duration::from_secs(udp_timeout.max(1) as u64);
    let sent = Arc::new(AtomicU64::new(0));
    let recv = Arc::new(AtomicU64::new(0));
    let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let (up, down) = match role {
        UdpRole::Server { prefer_ipv4 } => {
            let up_sock = udp_socket.clone();
            let up_sent = sent.clone();
            let up = tokio::spawn(async move {
                let mut buffered: Vec<u8> = initial_buffer;
                let mut chunk = vec![0u8; MAX_LENGTH];
                loop {
                    if buffered.is_empty() {
                        match stream_reader.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buffered.extend_from_slice(&chunk[..n]),
                        }
                    }
                    match UdpPacket::parse(&buffered) {
                        crate::proto::socks5address::ParseResult::Complete((packet, consumed)) => {
                            buffered.drain(..consumed);
                            up_sent.fetch_add(packet.length as u64, Ordering::Relaxed);
                            let target = match resolve(
                                &packet.address.address,
                                packet.address.port,
                                prefer_ipv4,
                            )
                            .await
                            {
                                Ok(a) => a,
                                Err(_) => break,
                            };
                            if up_sock.send_to(&packet.payload, target).await.is_err() {
                                break;
                            }
                        }
                        crate::proto::socks5address::ParseResult::Partial => {
                            if buffered.len() > MAX_LENGTH {
                                log::error!("UDP packet too long");
                                break;
                            }
                            match stream_reader.read(&mut chunk).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => buffered.extend_from_slice(&chunk[..n]),
                            }
                        }
                        crate::proto::socks5address::ParseResult::Invalid => {
                            log::warn!("invalid UDP packet");
                            break;
                        }
                    }
                }
            });

            let down_sock = udp_socket.clone();
            let down_recv = recv.clone();
            let down_peer = last_peer.clone();
            let down = tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_LENGTH];
                loop {
                    let (size, endpoint) =
                        match tokio::time::timeout(timeout, down_sock.recv_from(&mut buf)).await {
                            Ok(Ok((size, endpoint))) => (size, endpoint),
                            Ok(Err(_)) => break,
                            Err(_) => break,
                        };
                    *down_peer.lock().unwrap() = Some(endpoint);
                    let packet = UdpPacket::generate(endpoint, &buf[..size]);
                    if stream_writer.write_all(&packet).await.is_err() {
                        break;
                    }
                    down_recv.fetch_add(size as u64, Ordering::Relaxed);
                }
            });
            (up, down)
        }
        UdpRole::Client => {
            // stream -> local SOCKS5 client
            let up_sock = udp_socket.clone();
            let up_recv = recv.clone();
            let up_peer = last_peer.clone();
            let up = tokio::spawn(async move {
                let mut buffered: Vec<u8> = initial_buffer;
                let mut chunk = vec![0u8; MAX_LENGTH];
                loop {
                    if buffered.is_empty() {
                        match tokio::time::timeout(timeout, stream_reader.read(&mut chunk)).await {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                            Ok(Ok(n)) => buffered.extend_from_slice(&chunk[..n]),
                        }
                    }
                    match UdpPacket::parse(&buffered) {
                        crate::proto::socks5address::ParseResult::Complete((packet, consumed)) => {
                            buffered.drain(..consumed);
                            up_recv.fetch_add(packet.length as u64, Ordering::Relaxed);
                            let target = *up_peer.lock().unwrap();
                            let Some(target) = target else {
                                continue;
                            };
                            let datagram = socks5_udp_datagram(&packet.address, &packet.payload);
                            if up_sock.send_to(&datagram, target).await.is_err() {
                                break;
                            }
                        }
                        crate::proto::socks5address::ParseResult::Partial => {
                            if buffered.len() > MAX_LENGTH {
                                log::error!("UDP packet too long");
                                break;
                            }
                            match tokio::time::timeout(timeout, stream_reader.read(&mut chunk))
                                .await
                            {
                                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                                Ok(Ok(n)) => buffered.extend_from_slice(&chunk[..n]),
                            }
                        }
                        crate::proto::socks5address::ParseResult::Invalid => {
                            log::warn!("invalid UDP packet");
                            break;
                        }
                    }
                }
            });

            // local SOCKS5 client -> stream
            let down_sock = udp_socket.clone();
            let down_sent = sent.clone();
            let down_peer = last_peer.clone();
            let down = tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_LENGTH];
                loop {
                    let (size, src) =
                        match tokio::time::timeout(timeout, down_sock.recv_from(&mut buf)).await {
                            Ok(Ok(v)) => v,
                            Ok(Err(_)) | Err(_) => break,
                        };
                    *down_peer.lock().unwrap() = Some(src);
                    if size < 4 || buf[2] != 0 {
                        continue;
                    }
                    let (address, address_len) = match Socks5Address::parse(&buf[3..size]) {
                        crate::proto::socks5address::ParseResult::Complete(v) => v,
                        _ => continue,
                    };
                    let payload = &buf[3 + address_len..size];
                    let packet = UdpPacket::generate_for(&address, payload);
                    if stream_writer.write_all(&packet).await.is_err() {
                        break;
                    }
                    down_sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
            });
            (up, down)
        }
    };

    let mut up = up;
    let mut down = down;
    tokio::select! {
        _ = &mut up => down.abort(),
        _ = &mut down => up.abort(),
    }
    RelayStats {
        sent: sent.load(Ordering::Relaxed),
        recv: recv.load(Ordering::Relaxed),
    }
}

/// Builds the SOCKS5 UDP datagram header prefix (`RSV FRG ATYP ...`) for a
/// target address followed by `payload`.
pub fn socks5_udp_datagram(address: &Socks5Address, payload: &[u8]) -> Vec<u8> {
    let mut ret = vec![0, 0, 0];
    ret.extend_from_slice(&address.to_bytes());
    ret.extend_from_slice(payload);
    ret
}

/// Generic middleware that relays the inbound context streams to the
/// outbound stream stashed in the context (used by forward mode).
#[cfg(feature = "server")]
pub fn relay_middleware() -> std::sync::Arc<aex::http::types::Executor> {
    Arc::new(|ctx: &mut aex::connection::context::Context| {
        async move {
            let Some(outbound) = ctx
                .local
                .get_value::<crate::middleware::tls::OutboundStream>()
                .and_then(|o| o.take())
            else {
                log::error!("{} relay middleware: no outbound stream", ctx.addr);
                return false;
            };
            let Some(reader) = ctx.reader.take() else {
                return false;
            };
            let Some(writer) = ctx.writer.take() else {
                return false;
            };
            let stats = relay(reader, writer, outbound, &[])
                .await
                .unwrap_or_default();
            log::info!(
                "{} disconnected, {} bytes received, {} bytes sent, lasted for {} seconds",
                ctx.addr,
                stats.recv,
                stats.sent,
                ctx.elapsed() / 1000
            );
            false
        }
        .boxed()
    })
}
