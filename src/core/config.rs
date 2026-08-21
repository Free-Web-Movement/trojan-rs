use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use sha2::{Sha224, Digest};
use std::env;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunType {
    Server,
    Client,
    Forward,
    Nat,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SSLConfig {
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(default = "default_true")]
    pub verify_hostname: bool,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub key_password: String,
    #[serde(default)]
    pub cipher: String,
    #[serde(default)]
    pub cipher_tls13: String,
    #[serde(default = "default_true")]
    pub prefer_server_cipher: bool,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub alpn_port_override: HashMap<String, u16>,
    #[serde(default = "default_true")]
    pub reuse_session: bool,
    #[serde(default)]
    pub session_ticket: bool,
    #[serde(default = "default_600")]
    pub session_timeout: i64,
    #[serde(default)]
    pub plain_http_response: String,
    #[serde(default)]
    pub curves: String,
    #[serde(default)]
    pub dhparam: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TCPConfig {
    #[serde(default)]
    pub prefer_ipv4: bool,
    #[serde(default = "default_true")]
    pub no_delay: bool,
    #[serde(default = "default_true")]
    pub keep_alive: bool,
    #[serde(default)]
    pub reuse_port: bool,
    #[serde(default)]
    pub fast_open: bool,
    #[serde(default = "default_20")]
    pub fast_open_qlen: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MySQLConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_127_0_0_1")]
    pub server_addr: String,
    #[serde(default = "default_3306")]
    pub server_port: u16,
    #[serde(default = "default_trojan")]
    pub database: String,
    #[serde(default = "default_trojan")]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub ca: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub run_type: RunType,
    pub local_addr: String,
    pub local_port: u16,
    #[serde(default)]
    pub remote_addr: String,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub target_addr: String,
    #[serde(default)]
    pub target_port: u16,
    #[serde(default)]
    pub password: Vec<String>,
    #[serde(default = "default_60")]
    pub udp_timeout: i32,
    #[serde(default = "default_log_level")]
    pub log_level: i32,
    #[serde(default)]
    pub ssl: SSLConfig,
    #[serde(default)]
    pub tcp: TCPConfig,
    #[serde(default)]
    pub mysql: MySQLConfig,

    #[serde(skip)]
    pub hashed_passwords: HashMap<String, String>,
}

// Defaults
fn default_true() -> bool { true }
fn default_600() -> i64 { 600 }
fn default_20() -> i32 { 20 }
fn default_60() -> i32 { 60 }
fn default_127_0_0_1() -> String { "127.0.0.1".to_string() }
fn default_3306() -> u16 { 3306 }
fn default_trojan() -> String { "trojan".to_string() }
fn default_log_level() -> i32 { 1 }

impl Default for SSLConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}
impl Default for TCPConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}
impl Default for MySQLConfig {
    fn default() -> Self {
        serde_json::from_str("{}").unwrap()
    }
}

impl Config {
    pub fn load(filename: &str) -> anyhow::Result<Self> {
        let content = fs::read_to_string(filename)?;
        Self::populate(&content)
    }

    pub fn populate(json: &str) -> anyhow::Result<Self> {
        let mut config: Config = serde_json::from_str(json)?;
        config.hashed_passwords = HashMap::new();
        for p in &config.password {
            let hashed = Self::sha224(p);
            config.hashed_passwords.insert(hashed, p.clone());
        }
        Ok(config)
    }

    pub fn sha224(message: &str) -> String {
        let mut hasher = Sha224::new();
        hasher.update(message);
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn sip003(&mut self) -> anyhow::Result<bool> {
        if let Ok(json) = env::var("SS_PLUGIN_OPTIONS") {
            *self = Self::populate(&json)?;
            match self.run_type {
                RunType::Server => {
                    self.local_addr = env::var("SS_REMOTE_HOST").unwrap_or_default();
                    self.local_port = env::var("SS_REMOTE_PORT").unwrap_or_default().parse().unwrap_or_default();
                }
                RunType::Client | RunType::Nat => {
                    anyhow::bail!("SIP003 with wrong run_type");
                }
                RunType::Forward => {
                    self.remote_addr = env::var("SS_REMOTE_HOST").unwrap_or_default();
                    self.remote_port = env::var("SS_REMOTE_PORT").unwrap_or_default().parse().unwrap_or_default();
                    self.local_addr = env::var("SS_LOCAL_HOST").unwrap_or_default();
                    self.local_port = env::var("SS_LOCAL_PORT").unwrap_or_default().parse().unwrap_or_default();
                }
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
