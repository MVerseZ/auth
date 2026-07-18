use crate::storage::AppState;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header::HeaderValue},
    middleware::Next,
    response::IntoResponse,
};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::{info, warn};

#[derive(Clone)]
pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    requests: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut requests = self.requests.lock().unwrap();
        let bucket = requests.entry(key.to_string()).or_default();

        while bucket
            .front()
            .is_some_and(|time| now.duration_since(*time) > self.window)
        {
            bucket.pop_front();
        }

        if bucket.len() >= self.max_requests {
            return false;
        }

        bucket.push_back(now);
        true
    }
}

fn client_key(headers: &axum::http::HeaderMap) -> String {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim();

    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .trim();

    format!("{ip}|{user_agent}")
}

pub async fn security_headers_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    Ok(response)
}

pub async fn metrics_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    state.metrics.increment_requests();
    if req.uri().path().starts_with("/login")
        || req.uri().path().starts_with("/register")
        || req.uri().path().starts_with("/refresh")
        || req.uri().path().starts_with("/logout")
        || req.uri().path().starts_with("/me")
    {
        state.metrics.increment_auth_requests();
    }
    let response = next.run(req).await;
    if response.status().is_server_error() || response.status().is_client_error() {
        state.metrics.increment_errors();
    }
    Ok(response)
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let path = req.uri().path().to_string();
    if path == "/health" || path == "/" {
        return Ok(next.run(req).await);
    }

    let key = client_key(req.headers());

    if state.rate_limiter.allow(&key) {
        info!("request allowed for ip {} on {}", key, path);
        Ok(next.run(req).await)
    } else {
        warn!("rate limit exceeded for ip {} on {}", key, path);
        let response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many requests" })),
        )
            .into_response();
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.allow("1.1.1.1"));
        assert!(limiter.allow("1.1.1.1"));
        assert!(!limiter.allow("1.1.1.1"));
    }

    #[test]
    fn client_key_includes_ip_and_user_agent() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
        headers.insert("user-agent", "curl/8.0".parse().unwrap());

        assert_eq!(client_key(&headers), "203.0.113.8|curl/8.0");
    }
}
