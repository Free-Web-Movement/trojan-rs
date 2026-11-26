use std::net::{IpAddr, SocketAddr};

pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAINNAME: u8 = 3;
pub const ATYP_IPV6: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    IPv4,
    Domainname,
    IPv6,
}

impl AddressType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            ATYP_IPV4 => Some(AddressType::IPv4),
            ATYP_DOMAINNAME => Some(AddressType::Domainname),
            ATYP_IPV6 => Some(AddressType::IPv6),
            _ => None,
        }
    }

    pub fn as_byte(&self) -> u8 {
        match self {
            AddressType::IPv4 => ATYP_IPV4,
            AddressType::Domainname => ATYP_DOMAINNAME,
            AddressType::IPv6 => ATYP_IPV6,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Address {
    pub address_type: AddressType,
    pub address: String,
    pub port: u16,
}

/// Outcome of parsing a SOCKS5 address from a byte buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult<T> {
    Complete(T),
    Partial,
    Invalid,
}

impl Socks5Address {
    /// Parses a SOCKS5 address (ATYP + addr + port) from `data`.
    /// Returns the parsed address and the number of bytes consumed.
    pub fn parse(data: &[u8]) -> ParseResult<(Socks5Address, usize)> {
        if data.is_empty() {
            return ParseResult::Partial;
        }
        let address_type = match AddressType::from_byte(data[0]) {
            Some(t) => t,
            None => return ParseResult::Invalid,
        };
        match address_type {
            AddressType::IPv4 => {
                if data.len() < 1 + 4 + 2 {
                    return ParseResult::Partial;
                }
                let address = format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                ParseResult::Complete((
                    Socks5Address {
                        address_type,
                        address,
                        port,
                    },
                    1 + 4 + 2,
                ))
            }
            AddressType::Domainname => {
                if data.len() < 2 {
                    return ParseResult::Partial;
                }
                let domain_len = data[1] as usize;
                if domain_len == 0 {
                    return ParseResult::Invalid;
                }
                if data.len() < 1 + 1 + domain_len + 2 {
                    return ParseResult::Partial;
                }
                let address = String::from_utf8_lossy(&data[2..2 + domain_len]).into_owned();
                let port = u16::from_be_bytes([data[domain_len + 2], data[domain_len + 3]]);
                ParseResult::Complete((
                    Socks5Address {
                        address_type,
                        address,
                        port,
                    },
                    1 + 1 + domain_len + 2,
                ))
            }
            AddressType::IPv6 => {
                if data.len() < 1 + 16 + 2 {
                    return ParseResult::Partial;
                }
                let groups: Vec<String> = (0..8)
                    .map(|i| format!("{:02x}{:02x}", data[1 + i * 2], data[2 + i * 2]))
                    .collect();
                let address = groups.join(":");
                let port = u16::from_be_bytes([data[17], data[18]]);
                ParseResult::Complete((
                    Socks5Address {
                        address_type,
                        address,
                        port,
                    },
                    1 + 16 + 2,
                ))
            }
        }
    }

    /// Serializes this address back into wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = vec![self.address_type.as_byte()];
        match self.address_type {
            AddressType::IPv4 => {
                if let Ok(IpAddr::V4(ip)) = self.address.parse::<IpAddr>() {
                    ret.extend_from_slice(&ip.octets());
                } else {
                    ret.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
            AddressType::Domainname => {
                ret.push(self.address.len() as u8);
                ret.extend_from_slice(self.address.as_bytes());
            }
            AddressType::IPv6 => {
                if let Ok(IpAddr::V6(ip)) = self.address.parse::<IpAddr>() {
                    ret.extend_from_slice(&ip.octets());
                } else {
                    ret.extend_from_slice(&[0u8; 16]);
                }
            }
        }
        ret.extend_from_slice(&self.port.to_be_bytes());
        ret
    }

    /// Generates the wire format for a UDP endpoint.
    pub fn generate(endpoint: SocketAddr) -> Vec<u8> {
        let mut ret = Vec::with_capacity(19);
        match endpoint.ip() {
            IpAddr::V4(ip) => {
                ret.push(ATYP_IPV4);
                ret.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                ret.push(ATYP_IPV6);
                ret.extend_from_slice(&ip.octets());
            }
        }
        ret.extend_from_slice(&endpoint.port().to_be_bytes());
        ret
    }

    /// Generates the wire format for an unspecified IPv4 endpoint.
    #[allow(dead_code)]
    pub fn generate_unspecified() -> Vec<u8> {
        vec![ATYP_IPV4, 0, 0, 0, 0, 0, 0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        let data = [1u8, 8, 8, 8, 8, 0x01, 0xbb];
        let (addr, len) = match Socks5Address::parse(&data) {
            ParseResult::Complete(v) => v,
            _ => panic!("expected complete"),
        };
        assert_eq!(len, 7);
        assert_eq!(addr.address, "8.8.8.8");
        assert_eq!(addr.port, 443);
        assert_eq!(addr.address_type, AddressType::IPv4);
    }

    #[test]
    fn parse_ipv4_partial() {
        assert_eq!(Socks5Address::parse(&[1u8, 8, 8]), ParseResult::Partial);
    }

    #[test]
    fn parse_domain() {
        let mut data = vec![3u8, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&8080u16.to_be_bytes());
        let (addr, len) = match Socks5Address::parse(&data) {
            ParseResult::Complete(v) => v,
            _ => panic!("expected complete"),
        };
        assert_eq!(len, 2 + 11 + 2);
        assert_eq!(addr.address, "example.com");
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn parse_domain_zero_length_invalid() {
        assert_eq!(
            Socks5Address::parse(&[3u8, 0, 1, 2, 3]),
            ParseResult::Invalid
        );
    }

    #[test]
    fn parse_domain_partial() {
        let mut data = vec![3u8, 20];
        data.extend_from_slice(b"short");
        assert_eq!(Socks5Address::parse(&data), ParseResult::Partial);
    }

    #[test]
    fn parse_ipv6_format_matches_cxx() {
        let mut data = vec![4u8];
        for i in 0..16u8 {
            data.push(i * 0x11);
        }
        data.extend_from_slice(&0x0050u16.to_be_bytes());
        let (addr, len) = match Socks5Address::parse(&data) {
            ParseResult::Complete(v) => v,
            _ => panic!("expected complete"),
        };
        assert_eq!(len, 19);
        assert_eq!(addr.address, "0011:2233:4455:6677:8899:aabb:ccdd:eeff");
        assert_eq!(addr.port, 80);
    }

    #[test]
    fn invalid_type() {
        assert_eq!(Socks5Address::parse(&[9u8, 0, 0]), ParseResult::Invalid);
        assert_eq!(Socks5Address::parse(&[]), ParseResult::Partial);
    }

    #[test]
    fn generate_roundtrip() {
        let ep: SocketAddr = "192.168.1.1:1234".parse().unwrap();
        let bytes = Socks5Address::generate(ep);
        let (addr, _) = match Socks5Address::parse(&bytes) {
            ParseResult::Complete(v) => v,
            _ => panic!("expected complete"),
        };
        assert_eq!(addr.address, "192.168.1.1");
        assert_eq!(addr.port, 1234);
    }

    #[test]
    fn to_bytes_roundtrip_domain() {
        let addr = Socks5Address {
            address_type: AddressType::Domainname,
            address: "example.com".to_string(),
            port: 443,
        };
        let bytes = addr.to_bytes();
        let (parsed, _) = match Socks5Address::parse(&bytes) {
            ParseResult::Complete(v) => v,
            _ => panic!("expected complete"),
        };
        assert_eq!(parsed, addr);
    }

    #[test]
    fn generate_unspecified_is_seven_bytes() {
        let bytes = Socks5Address::generate_unspecified();
        assert_eq!(bytes, vec![1, 0, 0, 0, 0, 0, 0]);
    }
}
