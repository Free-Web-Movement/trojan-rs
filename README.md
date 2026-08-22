# trojan-rs

An unidentifiable mechanism that helps you bypass GFW — rewritten in Rust.

This is a Rust implementation of the [trojan](https://github.com/trojan-gfw/trojan) protocol, built on the [aex](https://github.com/Free-Web-Movement/aex) middleware framework. It keeps full wire compatibility with the original C++ trojan: the same protocol, the same `config.json` format, and the same command-line workflow.

## Features

- **Server / Client / Forward / NAT** run types
  - `server`: trojan server with TLS; non-trojan traffic falls through to a fallback web server
  - `client`: SOCKS5 proxy that tunnels traffic to a trojan server
  - `forward`: transparent forwarder for traffic already speaking the trojan protocol
  - `nat`: transparent proxy that recovers the original destination of iptables-redirected connections via `SO_ORIGINAL_DST`
- SOCKS5 TCP connect and UDP ASSOCIATE
- TLS 1.3 via rustls (no OpenSSL dependency), ALPN support
- Optional MySQL-based user authentication (`mysql` feature)
- Unified multi-protocol listener from aex, with per-connection attributes for middleware

## Build

Requires only a Rust toolchain (1.75+). See [docs/build.md](docs/build.md) or run:

```bash
git clone --recurse-submodules https://github.com/Free-Web-Movement/trojan-rs.git
cd trojan-rs
cargo build --release
```

## Usage

```bash
./target/release/trojan-rs config.json        # run
./target/release/trojan-rs --test config.json # validate config
```

`SIGHUP` restarts the service with a reloaded config; `SIGTERM`/`SIGINT` stop it.

Full documentation lives in [docs/](docs/README.md).

## License

[GPLv3](LICENSE)
