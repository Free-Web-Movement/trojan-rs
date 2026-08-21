use std::sync::Arc;

use aex::connection::context::Context;
use aex::connection::global::GlobalContext;
use aex::http::types::Executor;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::core::authenticator::Authenticator;
use crate::core::config::{Config, RunType};
use crate::core::log::LogLevel;
use crate::middleware::tls::{RawStream, TlsMiddleware};
use crate::middleware::trojan::TrojanMiddleware;
use crate::session::relay_middleware;

pub struct Service {
    config: Arc<Config>,
    globals: Arc<GlobalContext>,
    listener: TcpListener,
    chain: Vec<Arc<Executor>>,
    cancel: CancellationToken,
}

async fn run_chain(chain: Vec<Arc<Executor>>, mut ctx: Context) {
    for mw in &chain {
        if !mw(&mut ctx).await {
            break;
        }
    }
}

impl Service {
    pub async fn new(config: Config, test: bool) -> anyhow::Result<Self> {
        let level = match config.log_level {
            0 => LogLevel::All,
            1 => LogLevel::Info,
            2 => LogLevel::Warn,
            _ => LogLevel::Error,
        };
        crate::core::log::set_level(level);

        let config = Arc::new(config);
        let chain = match config.run_type {
            RunType::Server => {
                let acceptor = TlsAcceptor::from(Arc::new(
                    crate::middleware::tls::server_config(&config.ssl)?,
                ));
                let auth = if config.mysql.enabled {
                    Some(Arc::new(Authenticator::new(&config).await?))
                } else {
                    None
                };
                vec![
                    TlsMiddleware::accept(acceptor),
                    TrojanMiddleware::server(config.clone(), auth),
                ]
            }
            RunType::Client => {
                let ssl = Arc::new(config.ssl.clone());
                vec![
                    TrojanMiddleware::socks5(config.clone()),
                    TlsMiddleware::connect(
                        ssl,
                        config.tcp.no_delay,
                        config.remote_addr.clone(),
                        config.remote_port,
                    ),
                    TrojanMiddleware::client(config.clone()),
                ]
            }
            RunType::Forward => {
                let ssl = Arc::new(config.ssl.clone());
                vec![
                    TlsMiddleware::connect(
                        ssl,
                        config.tcp.no_delay,
                        config.remote_addr.clone(),
                        config.remote_port,
                    ),
                    relay_middleware(),
                ]
            }
            RunType::Nat => {
                let ssl = Arc::new(config.ssl.clone());
                vec![
                    crate::middleware::nat::original_dst(),
                    TlsMiddleware::connect(
                        ssl,
                        config.tcp.no_delay,
                        config.remote_addr.clone(),
                        config.remote_port,
                    ),
                    TrojanMiddleware::client(config.clone()),
                ]
            }
        };

        if test {
            return Ok(Self {
                config,
                globals: Arc::new(GlobalContext::new(
                    "127.0.0.1:0".parse().unwrap(),
                    None,
                )),
                listener: TcpListener::bind("127.0.0.1:0").await?,
                chain,
                cancel: CancellationToken::new(),
            });
        }

        let addr = format!("{}:{}", config.local_addr, config.local_port);
        let listener = TcpListener::bind(&addr).await?;
        let globals = Arc::new(GlobalContext::new(listener.local_addr()?, None));

        Ok(Self {
            config,
            globals,
            listener,
            chain,
            cancel: CancellationToken::new(),
        })
    }

    pub async fn run(self: Arc<Self>) -> anyhow::Result<()> {
        log::info!(
            "Starting trojan-rs ({:?}) at {}:{}",
            self.config.run_type,
            self.config.local_addr,
            self.config.local_port
        );
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                accepted = self.listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("Accept error: {}", e);
                            continue;
                        }
                    };
                    let mut ctx = Context::new(None, None, self.globals.clone(), peer);
                    match self.config.run_type {
                        RunType::Server | RunType::Nat => {
                            ctx.local.set_value(RawStream::new(stream));
                        }
                        _ => {
                            let (r, w) = stream.into_split();
                            ctx.reader = Some(Box::new(BufReader::new(r)));
                            ctx.writer = Some(Box::new(w));
                        }
                    }
                    let chain = self.chain.clone();
                    tokio::spawn(run_chain(chain, ctx));
                }
            }
        }
        log::info!("Stopping trojan service");
        Ok(())
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
