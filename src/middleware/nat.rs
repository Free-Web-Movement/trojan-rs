//! NAT mode middleware: recovers the original destination of a transparently
//! redirected (iptables REDIRECT / TPROXY) connection via `SO_ORIGINAL_DST`.
//!
//! The unified server attaches the accepted connection's file descriptor to
//! the context as a [`ConnectionFd`] attribute; the split reader/writer halves
//! share the same descriptor, so the lookup works at any point of the chain.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use aex::connection::context::{ConnectionFd, Context};
use aex::http::types::Executor;
use futures::future::FutureExt;

use crate::middleware::trojan::Socks5Target;
use crate::proto::socks5address::AddressType;
use crate::proto::trojanrequest::Command;

/// Same values as linux/netfilter_ipv4.h and linux/netfilter_ipv6/ip6_tables.h.
/// Defining them here avoids a hard dependency on linux-headers.
const SO_ORIGINAL_DST: libc::c_int = 80;
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

/// Recovers the pre-redirect destination address from the connection's file
/// descriptor attribute and stashes it as the [`Socks5Target`] so that the
/// TLS connect + trojan client middlewares can proceed.
pub fn original_dst() -> std::sync::Arc<Executor> {
    Arc::new(|ctx: &mut Context| {
        async move {
            let Some(conn_fd) = ctx.local.get_value::<ConnectionFd>() else {
                log::error!("{} nat middleware: no connection fd attribute", ctx.addr);
                return false;
            };

            let target = match original_destination(conn_fd.0) {
                Ok(a) => a,
                Err(e) => {
                    log::error!("{} cannot get original destination: {}", ctx.addr, e);
                    return false;
                }
            };

            let address = crate::proto::socks5address::Socks5Address {
                address_type: if target.is_ipv4() {
                    AddressType::IPv4
                } else {
                    AddressType::IPv6
                },
                address: target.ip().to_string(),
                port: target.port(),
            };
            log::info!(
                "{} forwarding to {}:{} via remote server",
                ctx.addr,
                address.address,
                address.port
            );

            ctx.local.set_value(Socks5Target {
                command: Command::Connect,
                address,
            });

            true
        }
        .boxed()
    })
}

fn original_destination(fd: std::os::fd::RawFd) -> anyhow::Result<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // IPv6 first (IP6T_SO_ORIGINAL_DST), then IPv4 (SO_ORIGINAL_DST),
        // mirroring the C++ implementation.
        if libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) != 0
        {
            addr = std::mem::zeroed();
            len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            ) != 0
            {
                anyhow::bail!(
                    "getsockopt(SO_ORIGINAL_DST) failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        match addr.ss_family as libc::c_int {
            libc::AF_INET => {
                let sa: &libc::sockaddr_in = &*(&addr as *const _ as *const libc::sockaddr_in);
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let sa: &libc::sockaddr_in6 = &*(&addr as *const _ as *const libc::sockaddr_in6);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sa.sin6_addr.s6_addr),
                    u16::from_be(sa.sin6_port),
                    sa.sin6_flowinfo,
                    sa.sin6_scope_id,
                )))
            }
            family => anyhow::bail!(
                "unsupported original destination address family: {}",
                family
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn constants_match_netfilter_headers() {
        assert_eq!(SO_ORIGINAL_DST, 80);
        assert_eq!(IP6T_SO_ORIGINAL_DST, 80);
    }

    #[test]
    fn original_dst_on_plain_socket_fails() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(original_destination(sock.as_raw_fd()).is_err());
    }
}
