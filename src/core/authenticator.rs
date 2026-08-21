#[cfg(feature = "mysql")]
use sqlx::mysql::MySqlPool;
use crate::core::config::Config;

pub struct Authenticator {
    #[cfg(feature = "mysql")]
    pool: Option<MySqlPool>,
}

impl Authenticator {
    pub async fn new(config: &Config) -> anyhow::Result<Self> {
        #[cfg(not(feature = "mysql"))]
        let _ = config;

        #[cfg(feature = "mysql")]
        if config.mysql.enabled {
            log::info!("Connecting to MySQL server {}:{}", config.mysql.server_addr, config.mysql.server_port);
            let url = format!("mysql://{}:{}@{}:{}/{}", 
                config.mysql.username, 
                config.mysql.password, 
                config.mysql.server_addr, 
                config.mysql.server_port, 
                config.mysql.database);
            
            // Note: sqlx handle SSL differently, might need more config
            let pool = MySqlPool::connect(&url).await?;
            log::info!("Connected to MySQL server");
            return Ok(Self { pool: Some(pool) });
        }

        #[cfg(feature = "mysql")]
        return Ok(Self { pool: None });

        #[cfg(not(feature = "mysql"))]
        Ok(Self {})
    }

    pub async fn auth(&self, password: &str) -> bool {
        if !Self::is_valid_password(password) {
            return false;
        }

        #[cfg(feature = "mysql")]
        if let Some(ref pool) = self.pool {
            let result = sqlx::query_as::<_, (i64, i64)>("SELECT quota, download + upload FROM users WHERE password = ?")
                .bind(password)
                .fetch_optional(pool)
                .await;

            match result {
                Ok(Some((quota, used))) => {
                    if quota < 0 {
                        return true;
                    }
                    if used >= quota {
                        log::warn!("{} ran out of quota", password);
                        return false;
                    }
                    return true;
                }
                Ok(None) => return false,
                Err(e) => {
                    log::error!("MySQL error: {}", e);
                    return false;
                }
            }
        }

        #[cfg(feature = "mysql")]
        {
            let _ = password;
            false
        }

        #[cfg(not(feature = "mysql"))]
        false
    }

    pub async fn record(&self, password: &str, download: u64, upload: u64) {
        #[cfg(not(feature = "mysql"))]
        let _ = (password, download, upload);

        #[cfg(feature = "mysql")]
        if !Self::is_valid_password(password) {
            return;
        }

        #[cfg(feature = "mysql")]
        if let Some(ref pool) = self.pool {
            let result = sqlx::query("UPDATE users SET download = download + ?, upload = upload + ? WHERE password = ?")
                .bind(download as i64)
                .bind(upload as i64)
                .bind(password)
                .execute(pool)
                .await;

            if let Err(e) = result {
                log::error!("MySQL error during record: {}", e);
            }
        }
    }

    fn is_valid_password(password: &str) -> bool {
        password.len() == 56 && password.chars().all(|c| c.is_ascii_hexdigit())
    }
}
