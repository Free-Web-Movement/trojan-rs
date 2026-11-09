//! Android JNI bridge.
//!
//! Exposes trojan to Android via JNI. The library is compiled as a
//! `cdylib` (`libtrojan.so`); Java/Kotlin loads it and calls the exported
//! functions to run a trojan client, a trojan server, or both (different
//! instances on different ports), on the device. A phone can act as a
//! client terminal *and* as a server for the FreeWebMovement peer-to-peer
//! mesh.
//!
//! # Kotlin surface
//!
//! ```kotlin
//! object TrojanNative {
//!     init { System.loadLibrary("trojan") }
//!     // legacy API kept for compatibility with the old C++ JNIHelper:
//!     external fun trojan(config: String)
//!     external fun stop()
//!     // new API:
//!     external fun startClient(config: String): Boolean
//!     external fun startServer(config: String): Boolean
//!     external fun stopClient(): Boolean
//!     external fun stopServer(): Boolean
//!     external fun getState(): Int
//!     external fun getVersion(): String
//! }
//! ```
//!
//! State is a shared `AtomicI32` so any thread may query it cheaply.
//! `getState()` returns one of the `RunType` discriminants + 100 (client) /
//! 200 (server) / 0 (idle), see [`state`].

#[cfg(feature = "server")]
use std::sync::atomic::{AtomicI32, Ordering};
#[cfg(feature = "server")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "server")]
use std::thread::JoinHandle;

use jni::objects::JClass;
#[cfg(feature = "server")]
use jni::objects::JString;
#[cfg(feature = "server")]
use jni::sys::jboolean;
use jni::sys::{jint, jstring};
use jni::JNIEnv;

#[cfg(feature = "server")]
use crate::core::config::Config;
#[cfg(feature = "server")]
use crate::core::service::Service;

// ---------------------------------------------------------------------------
// Android logcat bridge
// ---------------------------------------------------------------------------

/// Android log priorities (android/log.h).
const ANDROID_LOG_INFO: i32 = 4;
const ANDROID_LOG_WARN: i32 = 5;
const ANDROID_LOG_ERROR: i32 = 6;

/// `__android_log_print(int prio, const char *tag, const char *fmt, ...)`.
/// Only present on Android; stderr does not reach logcat by default.
#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_print(prio: i32, tag: *const std::os::raw::c_char, fmt: *const std::os::raw::c_char, ...) -> i32;
}

/// Route every trojan log line into Android logcat under the "trojan" tag.
pub fn install_logcat_bridge() {
    #[cfg(target_os = "android")]
    use std::ffi::CString;
    crate::core::log::set_callback(move |message: String, level: crate::core::log::LogLevel| {
        let prio = match level {
            crate::core::log::LogLevel::Error | crate::core::log::LogLevel::Fatal => ANDROID_LOG_ERROR,
            crate::core::log::LogLevel::Warn => ANDROID_LOG_WARN,
            _ => ANDROID_LOG_INFO,
        };
        #[cfg(target_os = "android")]
        unsafe {
            let tag = CString::new("trojan").unwrap_or_default();
            let msg = CString::new(message).unwrap_or_default();
            __android_log_print(prio, tag.as_ptr(), b"%s\0".as_ptr() as *const std::os::raw::c_char, msg.as_ptr());
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (prio, message);
        }
    });
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Process-wide shared state. Guarded by a mutex because the Service object
/// is not Sync; the atomic mirrors the run-type for cheap remote queries.
#[cfg(feature = "server")]
static STATE_ATOMIC: AtomicI32 = AtomicI32::new(STATE_IDLE);

#[cfg(feature = "server")]
const STATE_IDLE: i32 = 0;
#[cfg(feature = "server")]
const STATE_CLIENT_STARTING: i32 = 101;
#[cfg(feature = "server")]
const STATE_CLIENT_RUNNING: i32 = 102;
#[cfg(feature = "server")]
const STATE_SERVER_STARTING: i32 = 201;
#[cfg(feature = "server")]
const STATE_SERVER_RUNNING: i32 = 202;
#[cfg(feature = "server")]
const STATE_STOPPING: i32 = 999;

#[cfg(feature = "server")]
struct Runtime {
    // Kept alive so the service object is never dropped while running.
    #[allow(dead_code)]
    service: Arc<Service>,
    thread: JoinHandle<()>,
    cancel: tokio_util::sync::CancellationToken,
}

#[cfg(feature = "server")]
struct Instance {
    client: Option<Runtime>,
    server: Option<Runtime>,
}

#[cfg(feature = "server")]
static INSTANCE: Mutex<Option<Instance>> = Mutex::new(None);

#[cfg(feature = "server")]
fn set_state(v: i32) {
    STATE_ATOMIC.store(v, Ordering::SeqCst);
}

#[cfg(feature = "server")]
fn get_state() -> i32 {
    STATE_ATOMIC.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------------------
// Runtime helpers
// ---------------------------------------------------------------------------

/// Spawn a dedicated OS thread running a fresh tokio runtime, then start the
/// service on it. Returns a handle that cancels the service and joins the
/// thread.
#[cfg(feature = "server")]
fn spawn_service(config: Config) -> anyhow::Result<Runtime> {
    let (tx, rx) = std::sync::mpsc::channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_thread = cancel.clone();

    let thread = std::thread::Builder::new()
        .name("trojan".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(format!("runtime build failed: {e}")));
                    return;
                }
            };
            let _guard = rt.enter();
            let cancel = cancel_thread;
            rt.block_on(async {
                match Service::new(config, false).await {
                    Ok(svc) => {
                        let svc = Arc::new(svc);
                        let mut runner = tokio::spawn(svc.clone().run());
                        let _ = tx.send(Ok(svc.clone()));
                        // Wait for cancellation, mirroring the CLI's signal
                        // loop. SIGHUP/restart is intentionally not used here;
                        // the caller restarts by stopping and starting again.
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                svc.stop();
                                let _ = runner.await;
                            }
                            result = &mut runner => {
                                if let Err(e) = result {
                                    let _ = tx.send(Err(format!("service task failed: {e}")));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("service failed to start: {e}")));
                    }
                }
            });
        })?;

    let service = rx
        .recv()
        .map_err(|_| anyhow::anyhow!("service thread exited before startup"))?
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // The service task binds the listening socket inside `run`; block until
    // it is actually accepting so callers (and the Java `waitForPort` poll)
    // do not race a slow startup (DNS resolution, TLS config build, ...).
    let addr = service.local_addr();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "service did not start listening on {} within 15s",
                addr
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    Ok(Runtime {
        service,
        thread,
        cancel,
    })
}

// ---------------------------------------------------------------------------
// JNI exports (legacy-compatible + new API)
// ---------------------------------------------------------------------------

/// `JNI_OnLoad` required by the JVM when the library is loaded. We do not
/// need to register native methods manually (the names follow the standard
/// `Java_package_Class_method` scheme), so this just pins the JNI version.
/// The logger is also initialised here so log lines reach stderr (logcat on
/// Android).
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::os::raw::c_void) -> jint {
    let _ = crate::core::log::init();
    install_logcat_bridge();
    jni::sys::JNI_VERSION_1_6
}

/// Legacy: start the client from a config file path (old `JNIHelper.trojan`).
/// Kept so the existing igniter code continues to work unchanged; internally
/// it is identical to `startClient`.
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_JNIHelper_trojan(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) {
    let _ = start_from_env(&mut env, config, true);
}

/// Legacy: stop everything (old `JNIHelper.stop`).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_JNIHelper_stop(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = stop_all();
}

/// Start the client (SOCKS5 listener + TLS + trojan protocol to a remote).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_startClient(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jboolean {
    start_from_env(&mut env, config, true) as jboolean
}

/// Start the server (TLS + trojan server, serving the whole network).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_startServer(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jboolean {
    start_from_env(&mut env, config, false) as jboolean
}

/// Stop the client instance (server keeps running).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_stopClient(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    stop_slot(0) as jboolean
}

/// Stop the server instance (client keeps running).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_stopServer(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    stop_slot(1) as jboolean
}

/// Stop all instances.
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_stopAll(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = stop_all();
}

/// Current run state (see module docs for the encoding).
#[cfg(feature = "server")]
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_getState(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    get_state()
}

/// Version string, e.g. "trojan 0.1.0 (rustls TLS1.3)".
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_freewebmovement_igniter_TrojanNative_getVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let version = format!(
        "trojan {} (rustls {:?})",
        crate::core::version::get_version(),
        rustls::version::TLS13.version
    );
    match env.new_string(version) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[cfg(feature = "server")]
fn start_from_env(env: &mut JNIEnv, config: JString, is_client: bool) -> bool {
    let path: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("JNI: cannot read config string: {e}");
            return false;
        }
    };
    start(path, is_client)
}

#[cfg(feature = "server")]
fn start(path: String, is_client: bool) -> bool {
    set_state(if is_client {
        STATE_CLIENT_STARTING
    } else {
        STATE_SERVER_STARTING
    });

    let config = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("JNI: failed to load config {path}: {e}");
            set_state(STATE_IDLE);
            return false;
        }
    };
    // The JNI caller always wants the run-type implied by the API call, not
    // whatever the config file says (a server config must not silently run
    // the client and vice versa).
    let config = match is_client {
        true => config.force_run_type(crate::core::config::RunType::Client),
        false => config.force_run_type(crate::core::config::RunType::Server),
    };

    let runtime = match spawn_service(config) {
        Ok(r) => r,
        Err(e) => {
            log::error!("JNI: failed to spawn service: {e}");
            set_state(STATE_IDLE);
            return false;
        }
    };

    let mut guard = INSTANCE.lock().unwrap();
    let instance = guard.get_or_insert_with(|| Instance {
        client: None,
        server: None,
    });
    let slot = if is_client {
        &mut instance.client
    } else {
        &mut instance.server
    };
    if slot.is_some() {
        log::warn!("JNI: replacing existing running instance");
    }
    *slot = Some(runtime);
    set_state(if is_client {
        STATE_CLIENT_RUNNING
    } else {
        STATE_SERVER_RUNNING
    });
    true
}

#[cfg(feature = "server")]
fn stop_slot(index: usize) -> bool {
    let mut guard = INSTANCE.lock().unwrap();
    let Some(instance) = guard.as_mut() else {
        return false;
    };
    let slot = if index == 0 {
        &mut instance.client
    } else {
        &mut instance.server
    };
    match slot.take() {
        Some(rt) => {
            set_state(STATE_STOPPING);
            rt.cancel.cancel();
            let _ = rt.thread.join();
            if instance.client.is_none() && instance.server.is_none() {
                set_state(STATE_IDLE);
            } else {
                set_state(STATE_CLIENT_RUNNING.min(STATE_SERVER_RUNNING));
            }
            true
        }
        None => false,
    }
}

#[cfg(feature = "server")]
fn stop_all() -> bool {
    let mut guard = INSTANCE.lock().unwrap();
    let Some(instance) = guard.take() else {
        set_state(STATE_IDLE);
        return false;
    };
    set_state(STATE_STOPPING);
    for rt in [instance.client, instance.server].into_iter().flatten() {
        rt.cancel.cancel();
        let _ = rt.thread.join();
    }
    set_state(STATE_IDLE);
    true
}
