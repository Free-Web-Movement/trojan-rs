//! trojan library crate.
//!
//! Both the CLI binary (`src/main.rs`) and the Android JNI bridge
//! (`src/jni`) are thin shells over this library, so every run mode —
//! server, client, forward, NAT — is available to embedded hosts too.

pub mod core;
pub mod middleware;
pub mod proto;
pub mod session;

#[cfg(any(feature = "jni", target_os = "android"))]
pub mod jni;
