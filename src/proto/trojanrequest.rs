use super::socks5address::{ATYP_DOMAINNAME, ParseResult, Socks5Address};

pub const COMMAND_CONNECT: u8 = 1;
pub const COMMAND_UDP_ASSOCIATE: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    UdpAssociate,
}

impl Command {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            COMMAND_CONNECT => Some(Command::Connect),
            COMMAND_UDP_ASSOCIATE => Some(Command::UdpAssociate),
            _ => None,
        }
    }

    pub fn as_byte(&self) -> u8 {
        match self {
            Command::Connect => COMMAND_CONNECT,
            Command::UdpAssociate => COMMAND_UDP_ASSOCIATE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrojanRequest {
    pub password: String,
    pub command: Command,
    pub address: Socks5Address,
    pub payload: Vec<u8>,
}

/// Maximum bytes we will buffer while waiting for a complete request header.
pub const MAX_HEADER_LENGTH: usize = 8192;

impl TrojanRequest {
    /// Incrementally parses a trojan request:
    /// `password(56) CRLF | command(1) | socks5 address | CRLF` followed by payload.
    /// Returns `Partial` while more data is needed, `Invalid` when the
    /// structure is definitively not a trojan request.
    pub fn parse(data: &[u8]) -> ParseResult<(TrojanRequest, usize)> {
        let first = match find_crlf(data) {
            Some(pos) => pos,
            None => {
                if data.len() > MAX_HEADER_LENGTH {
                    return ParseResult::Invalid;
                }
                return ParseResult::Partial;
            }
        };
        let password = String::from_utf8_lossy(&data[..first]).into_owned();
        let payload = &data[first + 2..];
        if payload.is_empty() {
            return ParseResult::Invalid;
        }
        let command = match Command::from_byte(payload[0]) {
            Some(c) => c,
            None => return ParseResult::Invalid,
        };
        let (address, address_len) = match Socks5Address::parse(&payload[1..]) {
            ParseResult::Complete(v) => v,
            ParseResult::Partial => return ParseResult::Partial,
            ParseResult::Invalid => return ParseResult::Invalid,
        };
        let crlf_start = 1 + address_len;
        if payload.len() < crlf_start + 2 {
            return ParseResult::Partial;
        }
        if &payload[crlf_start..crlf_start + 2] != b"\r\n" {
            return ParseResult::Invalid;
        }
        let consumed = first + 2 + crlf_start + 2;
        ParseResult::Complete((
            TrojanRequest {
                password,
                command,
                address,
                payload: payload[crlf_start + 2..].to_vec(),
            },
            consumed,
        ))
    }

    /// Generates a trojan request header for the given target.
    pub fn generate_for(password: &str, command: Command, address: &Socks5Address) -> Vec<u8> {
        let mut ret = password.as_bytes().to_vec();
        ret.extend_from_slice(b"\r\n");
        ret.push(command.as_byte());
        ret.extend_from_slice(&address.to_bytes());
        ret.extend_from_slice(b"\r\n");
        ret
    }

    /// Generates a trojan request header for a domain name target.
    #[allow(dead_code)]
    pub fn generate(password: &str, domainname: &str, port: u16, tcp: bool) -> Vec<u8> {
        let mut ret = Vec::with_capacity(password.len() + 2 + 1 + 1 + domainname.len() + 2 + 2);
        ret.extend_from_slice(password.as_bytes());
        ret.extend_from_slice(b"\r\n");
        ret.push(if tcp { COMMAND_CONNECT } else { COMMAND_UDP_ASSOCIATE });
        ret.push(ATYP_DOMAINNAME);
        ret.push(domainname.len() as u8);
        ret.extend_from_slice(domainname.as_bytes());
        ret.extend_from_slice(&port.to_be_bytes());
        ret.extend_from_slice(b"\r\n");
        ret
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::socks5address::AddressType;

    fn sample_request() -> Vec<u8> {
        let password = "a".repeat(56);
        let mut data = password.clone().into_bytes();
        data.extend_from_slice(b"\r\n");
        data.push(1);
        data.extend_from_slice(&[3, 11]);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(b"hello world");
        data
    }

    #[test]
    fn parse_complete() {
        let data = sample_request();
        let (req, consumed) = match TrojanRequest::parse(&data) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(consumed, 56 + 2 + 1 + (1 + 1 + 11 + 2) + 2);
        assert_eq!(req.password, "a".repeat(56));
        assert_eq!(req.command, Command::Connect);
        assert_eq!(req.address.address, "example.com");
        assert_eq!(req.address.port, 443);
        assert_eq!(req.payload, b"hello world");
    }

    #[test]
    fn parse_partial_then_complete() {
        let data = sample_request();
        for cut in [10usize, 57, 60, 70] {
            if cut < data.len() {
                assert_eq!(
                    TrojanRequest::parse(&data[..cut]),
                    ParseResult::Partial,
                    "cut at {}",
                    cut
                );
            }
        }
        assert!(matches!(
            TrojanRequest::parse(&data),
            ParseResult::Complete(_)
        ));
    }

    #[test]
    fn parse_invalid_bad_command() {
        let mut data = sample_request();
        data[58] = 2;
        assert_eq!(TrojanRequest::parse(&data), ParseResult::Invalid);
    }

    #[test]
    fn parse_invalid_http_like() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(TrojanRequest::parse(data), ParseResult::Invalid);
    }

    #[test]
    fn parse_invalid_missing_crlf_after_address() {
        let password = "a".repeat(56);
        let mut data = password.into_bytes();
        data.extend_from_slice(b"\r\n");
        data.push(1);
        data.extend_from_slice(&[3, 9]);
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data.extend_from_slice(b"XX");
        assert_eq!(TrojanRequest::parse(&data), ParseResult::Invalid);
    }

    #[test]
    fn parse_udp_associate() {
        let password = "b".repeat(56);
        let mut data = password.clone().into_bytes();
        data.extend_from_slice(b"\r\n");
        data.push(3);
        data.extend_from_slice(&[1, 1, 2, 3, 4]);
        data.extend_from_slice(&53u16.to_be_bytes());
        data.extend_from_slice(b"\r\n");
        let (req, _) = match TrojanRequest::parse(&data) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(req.command, Command::UdpAssociate);
        assert_eq!(req.address.address_type, AddressType::IPv4);
        assert_eq!(req.address.address, "1.2.3.4");
        assert_eq!(req.address.port, 53);
        assert!(req.payload.is_empty());
    }

    #[test]
    fn generate_matches_protocol() {
        let out = TrojanRequest::generate(&"p".repeat(56), "example.com", 443, true);
        let (req, consumed) = match TrojanRequest::parse(&out) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(consumed, out.len());
        assert_eq!(req.command, Command::Connect);
        assert_eq!(req.address.address, "example.com");
        assert_eq!(req.address.port, 443);
        assert!(req.payload.is_empty());

        let out_udp = TrojanRequest::generate(&"p".repeat(56), "example.com", 53, false);
        let (req_udp, _) = match TrojanRequest::parse(&out_udp) {
            ParseResult::Complete(v) => v,
            other => panic!("expected complete, got {:?}", other),
        };
        assert_eq!(req_udp.command, Command::UdpAssociate);
    }

    #[test]
    fn generate_with_short_password_still_parses() {
        let out = TrojanRequest::generate("short", "d.io", 80, true);
        assert!(matches!(
            TrojanRequest::parse(&out),
            ParseResult::Complete(_)
        ));
    }
}
