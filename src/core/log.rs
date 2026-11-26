use chrono::Local;
use log::{Level, LevelFilter, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::{Write, stderr};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    All = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4,
    Off = 5,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::All => LevelFilter::Trace,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Fatal => LevelFilter::Error,
            LogLevel::Off => LevelFilter::Off,
        }
    }
}

type LogCallback = Box<dyn Fn(String, LogLevel) + Send + Sync>;

struct TrojanLogger {
    level: Mutex<LevelFilter>,
    output_stream: Mutex<Option<File>>,
    keylog: Mutex<Option<File>>,
    callback: Mutex<Option<LogCallback>>,
}

static LOGGER: OnceLock<Arc<TrojanLogger>> = OnceLock::new();

impl log::Log for TrojanLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= *self.level.lock().unwrap()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let level_str = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };
            let message = format!("{}", record.args());
            let log_line = format!("[{}] [{}] {}\n", timestamp, level_str, message);

            // File or Stderr
            let mut output = self.output_stream.lock().unwrap();
            if let Some(ref mut file) = *output {
                let _ = file.write_all(log_line.as_bytes());
                let _ = file.flush();
            } else {
                let _ = stderr().write_all(log_line.as_bytes());
                let _ = stderr().flush();
            }

            // Callback
            let cb = self.callback.lock().unwrap();
            if let Some(ref cb) = *cb {
                let internal_level = match record.level() {
                    Level::Error => LogLevel::Error,
                    Level::Warn => LogLevel::Warn,
                    Level::Info => LogLevel::Info,
                    Level::Debug | Level::Trace => LogLevel::Info,
                };
                cb(message, internal_level);
            }
        }
    }

    fn flush(&self) {
        if let Some(ref mut file) = *self.output_stream.lock().unwrap() {
            let _ = file.flush();
        }
    }
}

pub fn init() -> Result<(), log::SetLoggerError> {
    let logger = LOGGER.get_or_init(|| {
        Arc::new(TrojanLogger {
            level: Mutex::new(LevelFilter::Info),
            output_stream: Mutex::new(None),
            keylog: Mutex::new(None),
            callback: Mutex::new(None),
        })
    });
    log::set_logger(logger.as_ref())?;
    log::set_max_level(LevelFilter::Trace); // Let the logger internal level decide
    Ok(())
}

pub fn set_level(level: LogLevel) {
    if let Some(logger) = LOGGER.get() {
        *logger.level.lock().unwrap() = level.into();
    }
}

pub fn redirect(filename: &str) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;
    if let Some(logger) = LOGGER.get() {
        *logger.output_stream.lock().unwrap() = Some(file);
    }
    Ok(())
}

pub fn redirect_keylog(filename: &str) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;
    if let Some(logger) = LOGGER.get() {
        *logger.keylog.lock().unwrap() = Some(file);
    }
    Ok(())
}

pub fn keylog_enabled() -> bool {
    LOGGER
        .get()
        .map(|logger| logger.keylog.lock().unwrap().is_some())
        .unwrap_or(false)
}

#[allow(dead_code)]
pub fn set_callback<F>(cb: F)
where
    F: Fn(String, LogLevel) + Send + Sync + 'static,
{
    if let Some(logger) = LOGGER.get() {
        *logger.callback.lock().unwrap() = Some(Box::new(cb));
    }
}

pub fn reset() {
    if let Some(logger) = LOGGER.get() {
        *logger.output_stream.lock().unwrap() = None;
        *logger.keylog.lock().unwrap() = None;
        *logger.callback.lock().unwrap() = None;
    }
}

#[allow(dead_code)]
pub fn log_with_endpoint(endpoint: &SocketAddr, message: &str, level: Level) {
    log::log!(level, "{} {}", endpoint, message);
}

// Helper for rustls keylog
#[derive(Debug)]
pub struct TrojanKeyLog;

impl rustls::KeyLog for TrojanKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        if let Some(logger) = LOGGER.get() {
            if let Some(ref mut file) = *logger.keylog.lock().unwrap() {
                let mut line = format!("{} ", label);
                for b in client_random {
                    line.push_str(&format!("{:02x}", b));
                }
                line.push(' ');
                for b in secret {
                    line.push_str(&format!("{:02x}", b));
                }
                line.push('\n');
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
            }
        }
    }
}
