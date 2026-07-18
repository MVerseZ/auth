#[derive(Clone, Debug)]
pub struct AppConfig {
    pub jwt_secret: String,
    pub host: String,
    pub port: u16,
    pub rate_limit_max_requests: usize,
    pub rate_limit_window_secs: u64,
    pub metrics_error_threshold: u64,
    pub log_dir: String,
    pub log_file: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "dev-secret-change-me".to_string(),
            host: "127.0.0.1".to_string(),
            port: 3000,
            rate_limit_max_requests: 60,
            rate_limit_window_secs: 60,
            metrics_error_threshold: 5,
            log_dir: "logs".to_string(),
            log_file: "auth.log".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        Self {
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-secret-change-me".to_string()),
            host: std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(3000),
            rate_limit_max_requests: std::env::var("RATE_LIMIT_MAX_REQUESTS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(60),
            rate_limit_window_secs: std::env::var("RATE_LIMIT_WINDOW_SECS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(60),
            metrics_error_threshold: std::env::var("METRICS_ERROR_THRESHOLD")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5),
            log_dir: std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string()),
            log_file: std::env::var("LOG_FILE").unwrap_or_else(|_| "auth.log".to_string()),
            tls_cert_path: std::env::var("TLS_CERT_PATH").ok(),
            tls_key_path: std::env::var("TLS_KEY_PATH").ok(),
        }
    }

    pub fn jwt_secret_bytes(&self) -> Vec<u8> {
        self.jwt_secret.as_bytes().to_vec()
    }

    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
