mod config;
mod errors;
mod handlers;
mod metrics;
mod models;
mod monitoring;
mod storage;

use axum::{Router, middleware};
use axum_server::tls_rustls::RustlsConfig;
use std::{fs, net::SocketAddr};
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::{
    config::AppConfig,
    handlers::build_router,
    monitoring::{metrics_middleware, rate_limit_middleware, security_headers_middleware},
    storage::AppState,
};

#[tokio::main]
async fn main() {
    let config = AppConfig::from_env();
    let file_appender =
        RollingFileAppender::new(Rotation::DAILY, &config.log_dir, &config.log_file);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(non_blocking))
        .init();

    if let Err(err) = fs::create_dir_all(&config.log_dir) {
        error!("failed to create log directory: {err}");
    }

    let state = match AppState::new_with_config(config.clone()) {
        Ok(state) => state,
        Err(err) => {
            error!("failed to initialize app state: {err}");
            std::process::exit(1);
        }
    };

    let app: Router = build_router(state.clone())
        .layer(middleware::from_fn(security_headers_middleware))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            metrics_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    let _ = config.listen_addr();
    let cert_path = config.tls_cert_path.clone();
    let key_path = config.tls_key_path.clone();

    if let (Some(cert), Some(key)) = (cert_path, key_path) {
        info!("starting https server on https://127.0.0.1:3000");
        let config = RustlsConfig::from_pem_file(cert, key)
            .await
            .expect("load tls config");
        if let Err(err) = axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
        {
            error!("server failed: {err}");
            std::process::exit(1);
        }
    } else {
        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                error!("failed to bind port 3000: {err}");
                std::process::exit(1);
            }
        };

        info!("server listening on http://127.0.0.1:3000");
        if let Err(err) = axum::serve(listener, app).await {
            error!("server failed: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{handlers::validate_credentials, storage::TokenStore};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tower::ServiceExt;

    use super::*;

    static NEXT_DB_ID: AtomicUsize = AtomicUsize::new(0);

    fn unique_test_db_path() -> PathBuf {
        let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("auth-test-{}-{}.db", std::process::id(), id))
    }

    #[test]
    fn validate_credentials_rejects_empty_username() {
        let err = validate_credentials("", "password123").unwrap_err();
        assert_eq!(err.status_code(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok() {
        let state = AppState::new().unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn register_endpoint_rejects_invalid_payload() {
        let state = AppState::new().unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"ab","password":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn token_store_persists_and_reads_tokens() {
        let db_path = unique_test_db_path();
        if db_path.exists() {
            let _ = fs::remove_file(&db_path);
        }

        let store = TokenStore::new(db_path.to_str().unwrap()).unwrap();
        store
            .save_token("abc", "alice", "access", "jti-abc")
            .unwrap();

        assert!(store.has_token("abc").unwrap());
        assert_eq!(store.get_user_id("abc").unwrap().as_deref(), Some("alice"));

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn token_store_replaces_and_revokes_tokens_for_user() {
        let db_path = unique_test_db_path();
        if db_path.exists() {
            let _ = fs::remove_file(&db_path);
        }

        let store = TokenStore::new(db_path.to_str().unwrap()).unwrap();
        store
            .save_token("old-access", "alice", "access", "old-jti-access")
            .unwrap();
        store
            .save_token("old-refresh", "alice", "refresh", "old-jti-refresh")
            .unwrap();

        store.revoke_user_tokens("alice").unwrap();
        assert!(!store.has_token("old-access").unwrap());
        assert!(!store.has_token("old-refresh").unwrap());

        store
            .replace_token_for_user("new-access", "alice", "access", "new-jti-access")
            .unwrap();
        assert!(store.has_token("new-access").unwrap());
        assert!(!store.has_token("old-access").unwrap());

        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn token_store_invalidates_token_without_deleting_other_tokens() {
        let db_path = unique_test_db_path();
        let _ = fs::remove_file(&db_path);

        let store = TokenStore::new(db_path.to_str().unwrap()).unwrap();
        store
            .save_token("token-a", "alice", "access", "jti-a")
            .unwrap();
        store
            .save_token("token-b", "alice", "refresh", "jti-b")
            .unwrap();

        store.invalidate_token("token-a").unwrap();

        assert!(!store.has_token("token-a").unwrap());
        assert!(store.has_token("token-b").unwrap());

        let _ = fs::remove_file(db_path);
    }
}
