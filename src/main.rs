mod core;
mod middleware;
mod proto;
mod session;

use std::sync::Arc;

use clap::Parser;

use crate::core::config::Config;
use crate::core::log as trojan_log;
use crate::core::service::Service;

#[derive(Parser)]
#[command(
    name = "trojan-rs",
    version,
    about = "trojan-rs - An unidentifiable mechanism that helps you bypass GFW"
)]
struct Args {
    #[arg(short = 'c', long = "config", value_name = "CONFIG")]
    config: Option<String>,
    #[arg(value_name = "CONFIG")]
    config_positional: Option<String>,
    #[arg(short = 'l', long = "log", value_name = "LOG")]
    log: Option<String>,
    #[arg(short = 'k', long = "keylog", value_name = "KEYLOG")]
    keylog: Option<String>,
    #[arg(short = 't', long = "test")]
    test: bool,
    #[arg(short = 'v', long = "build-info")]
    build_info: bool,
}

async fn wait_for_signal(service: &Service) -> bool {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("failed to install SIGHUP handler");
        let mut sigusr1 =
            signal(SignalKind::user_defined1()).expect("failed to install SIGUSR1 handler");
        loop {
            tokio::select! {
                _ = sigint.recv() => {
                    log::warn!("got signal: SIGINT");
                    service.stop();
                    return false;
                }
                _ = sigterm.recv() => {
                    log::warn!("got signal: SIGTERM");
                    service.stop();
                    return false;
                }
                _ = sighup.recv() => {
                    log::warn!("got signal: SIGHUP");
                    service.stop();
                    return true;
                }
                _ = sigusr1.recv() => {
                    log::warn!("got signal: SIGUSR1, certificate reload is not supported yet");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
        service.stop();
        false
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(e) = trojan_log::init() {
        eprintln!("Failed to initialize logger: {}", e);
        std::process::exit(1);
    }

    if args.build_info {
        println!("trojan-rs {}", core::version::get_version());
        println!("rustls {:?} support", rustls::version::TLS13.version);
        return;
    }

    if let Some(log_file) = &args.log {
        if let Err(e) = trojan_log::redirect(log_file) {
            eprintln!("Failed to open log file {}: {}", log_file, e);
        }
    }
    if let Some(keylog_file) = &args.keylog {
        if let Err(e) = trojan_log::redirect_keylog(keylog_file) {
            eprintln!("Failed to open keylog file {}: {}", keylog_file, e);
        }
    }

    log::info!("Welcome to trojan-rs {}", core::version::get_version());

    let config_file = args
        .config
        .clone()
        .or(args.config_positional.clone())
        .unwrap_or_else(|| "config.json".to_string());

    loop {
        let config = match load_config(&config_file).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("fatal: {}", e);
                log::error!("exiting. . . ");
                std::process::exit(1);
            }
        };

        match Service::new(config, args.test).await {
            Ok(service) => {
                if args.test {
                    log::info!("The config file looks good.");
                    return;
                }
                let service = Arc::new(service);
                let runner = tokio::spawn(service.clone().run());
                let restart = wait_for_signal(&service).await;
                let _ = runner.await;

                if !restart {
                    break;
                }
                log::warn!("trojan service restarting. . . ");
            }
            Err(e) => {
                log::error!("fatal: {}", e);
                log::error!("exiting. . . ");
                std::process::exit(1);
            }
        }
    }

    trojan_log::reset();
}

async fn load_config(config_file: &str) -> anyhow::Result<Config> {
    let mut config = Config::load(config_file)?;
    if config.sip003()? {
        log::warn!("SIP003 is loaded");
    }
    Ok(config)
}
