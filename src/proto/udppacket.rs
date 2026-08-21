use super::socks5address::{ParseResult, Socks5Address};
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub address: Socks5Address,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    /// Parses a trojan UDP packet: `socks5 address | length(2) | CRLF | payload`.
    /// Returns the packet and the total number of bytes it occupies in `data`.
    pub fn parse(data: &[u8]) -> ParseResult<(UdpPacket, usize)> {
        if data.is_empty() {
            return ParseResult::Partial;
        }
        let (address, address_len) = match Socks5Address::parse(data) {
            ParseResult::Complete(v) => v,
            ParseResult::Partial => return ParseResult::Partial,
            ParseResult::Invalid => return ParseResult::Invalid,
        };
        if data.len() < address_len + 2 {
            return ParseResult::Partial;
        }
        let length = u16::from_be_bytes([data[address_len], data[address_len + 1]]);
        if data.len() < address_len + 4 + length as usize {
            return ParseResult::Partial;
        }
        if &data[address_len + 2..address_len + 4] != b"\r\n" {
            return ParseResult::Invalid;
        }
        let payload = data[address_len + 4..address_len + 4 + length as usize].to_vec();
        ParseResult::Complete((
            UdpPacket {
                address,
                length,
                payload,
            },
            address_len + 4 + length as usize,
        ))
    }

    /// Generates a trojan UDP packet for the given endpoint.
    pub fn generate(endpoint: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut ret = Socks5Address::generate(endpoint);
        ret.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ret.extend_from_slice(b"\r\n");
        ret.extend_from_slice(payload);
        ret
    }

    /// Generates a trojan UDP packet for the given SOCKS5 address.
    pub fn generate_for(address: &Socks5Address, payload: &[u8]) -> Vec<u8> {
        let mut ret = address.to_bytes();
        ret.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ret.extend_from_slice(b"\r\n");
        ret.extend_from_slice(payload);
        ret
    }

    /// Generates a trojan UDP packet with a domain name target.
    #[allow(dead_code)]
    pub fn generate_domain(domainname: &str, port: u16, payload: &[u8]) -> Vec<u8> {
        let mut ret = Vec::with_capacity(1 + 1 + domainname.len() + 2 + 2 + 2 + payload.len());
        ret.push(super::socks5address::ATYP_DOMAINNAME);
        ret.push(domainname.len() as u8);
        ret.extend_from_slice(domainname.as_bytes());
        ret.extend_from_slice(&port.to_be_bytes());
        ret.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        ret.extend_from_slice(b"\r\n");
        ret.extend_from_slice(payload);
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::socks5address::AddressType;

    #[test]
    fn parse_generate_roundtrip_endpoint() {
        let ep: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let bytes = UdpPacket::generate(ep, b"dns query");
        let (pkt, len) = match UdpPacket::parse(&bytes) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(len, bytes.len());
        assert_eq!(pkt.address.address, "10.0.0.1");
        assert_eq!(pkt.address.port, 5353);
        assert_eq!(pkt.length, 9);
        assert_eq!(pkt.payload, b"dns query");
    }

    #[test]
    fn parse_generate_roundtrip_domain() {
        let bytes = UdpPacket::generate_domain("dns.example", 53, b"abcd");
        let (pkt, len) = match UdpPacket::parse(&bytes) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(len, bytes.len());
        assert_eq!(pkt.address.address_type, AddressType::Domainname);
        assert_eq!(pkt.address.address, "dns.example");
        assert_eq!(pkt.length, 4);
        assert_eq!(pkt.payload, b"abcd");
    }

    #[test]
    fn parse_partial_when_payload_short() {
        let bytes = UdpPacket::generate_domain("dns.example", 53, b"abcd");
        assert_eq!(
            UdpPacket::parse(&bytes[..bytes.len() - 1]),
            ParseResult::Partial
        );
    }

    #[test]
    fn parse_invalid_when_crlf_missing() {
        let mut bytes = UdpPacket::generate_domain("dns.example", 53, b"abcd");
        let crlf_pos = bytes.len() - 4 - 2;
        bytes[crlf_pos] = b'X';
        bytes[crlf_pos + 1] = b'Y';
        assert_eq!(UdpPacket::parse(&bytes), ParseResult::Invalid);
    }

    #[test]
    fn parse_empty_is_partial() {
        assert_eq!(UdpPacket::parse(&[]), ParseResult::Partial);
    }
}
