# Build

trojan-rs is written in Rust and only requires a Rust toolchain to build — there is no dependency on CMake, Boost, or OpenSSL (TLS is provided by rustls). Linux, macOS, and other Unix-like platforms are supported.

## Dependencies

- [Rust](https://www.rust-lang.org/tools/install) >= 1.75 (via `rustup` or your distribution's package manager)
- A C toolchain (e.g. `build-essential` on Debian/Ubuntu) for linking

For Debian users:

```bash
sudo apt -y install build-essential curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Clone

The [aex](https://github.com/Free-Web-Movement/aex) framework is vendored as a git submodule, so clone recursively:

```bash
git clone --recurse-submodules https://github.com/Free-Web-Movement/trojan-rs.git
cd trojan-rs/
```

If you already cloned without `--recurse-submodules`, run `git submodule update --init` inside the repository.

## Build and Test

```bash
cargo build --release
```

To enable MySQL-based user authentication, build with the `mysql` feature:

```bash
cargo build --release --features mysql
```

Run the unit test suite with:

```bash
cargo test
```

## Install

Copy the binary wherever you like, e.g.:

```bash
sudo cp target/release/trojan-rs /usr/local/bin/
```
