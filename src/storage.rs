use crate::{config::AppConfig, errors::AppResult};
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct TokenStore {
    conn: Arc<Mutex<Connection>>,
}

impl TokenStore {
    pub fn new(db_path: &str) -> AppResult<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                kind TEXT NOT NULL,
                jti TEXT NOT NULL UNIQUE
            )",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn save_token(&self, token: &str, username: &str, kind: &str, jti: &str) -> AppResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO tokens (token, username, kind, jti) VALUES (?1, ?2, ?3, ?4)",
            params![token, username, kind, jti],
        )?;
        Ok(())
    }

    pub fn get_user_id(&self, token: &str) -> AppResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT username FROM tokens WHERE token = ?1")?;
        let mut rows = stmt.query(params![token])?;

        match rows.next()? {
            Some(row) => row.get::<_, String>(0).map(Some).map_err(Into::into),
            None => Ok(None),
        }
    }

    pub fn has_token(&self, token: &str) -> AppResult<bool> {
        Ok(self.get_user_id(token)?.is_some())
    }

    pub fn revoke_user_tokens(&self, username: &str) -> AppResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tokens WHERE username = ?1", params![username])?;
        Ok(())
    }

    pub fn invalidate_token(&self, token: &str) -> AppResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM tokens WHERE token = ?1", params![token])?;
        Ok(())
    }

    pub fn replace_token_for_user(
        &self,
        token: &str,
        username: &str,
        kind: &str,
        jti: &str,
    ) -> AppResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM tokens WHERE username = ?1 AND kind = ?2",
            params![username, kind],
        )?;
        conn.execute(
            "INSERT INTO tokens (token, username, kind, jti) VALUES (?1, ?2, ?3, ?4)",
            params![token, username, kind, jti],
        )?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct UserStore {
    conn: Arc<Mutex<Connection>>,
}

impl UserStore {
    pub fn new(db_path: &str) -> AppResult<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )",
            [],
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn create_user(&self, username: &str, password_hash: &str) -> AppResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
            params![username, password_hash],
        )?;
        Ok(())
    }

    pub fn find_user(&self, username: &str) -> AppResult<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT password_hash FROM users WHERE username = ?1")?;
        let mut rows = stmt.query(params![username])?;
        match rows.next()? {
            Some(row) => row.get::<_, String>(0).map(Some).map_err(Into::into),
            None => Ok(None),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub users: UserStore,
    pub tokens: TokenStore,
    pub rate_limiter: crate::monitoring::RateLimiter,
    pub metrics: crate::metrics::MetricsStore,
    pub config: AppConfig,
}

impl AppState {
    pub fn new() -> AppResult<Self> {
        Self::new_with_config(AppConfig::default())
    }

    pub fn new_with_config(config: AppConfig) -> AppResult<Self> {
        let tokens = TokenStore::new("tokens.db")?;
        let users = UserStore::new("users.db")?;
        Ok(Self {
            users,
            tokens,
            rate_limiter: crate::monitoring::RateLimiter::new(
                config.rate_limit_max_requests,
                std::time::Duration::from_secs(config.rate_limit_window_secs),
            ),
            metrics: crate::metrics::MetricsStore::new_with_threshold(
                config.metrics_error_threshold,
            ),
            config,
        })
    }
}
