use crate::{
    errors::{AppError, AppResult},
    models::{Claims, LoginRequest, MeResponse, RefreshRequest, RegisterRequest, TokenResponse},
    storage::AppState,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::json;
use tracing::{info, warn};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(json_handler))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/alerts", get(alerts))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .with_state(state)
}

pub fn validate_credentials(username: &str, password: &str) -> AppResult<()> {
    let trimmed_username = username.trim();
    let trimmed_password = password.trim();

    if trimmed_username.is_empty() || trimmed_password.is_empty() {
        return Err(AppError::Validation(
            "username and password are required".into(),
        ));
    }

    if trimmed_username.len() < 3 {
        return Err(AppError::Validation(
            "username must be at least 3 characters".into(),
        ));
    }

    if trimmed_password.len() < 6 {
        return Err(AppError::Validation(
            "password must be at least 6 characters".into(),
        ));
    }

    Ok(())
}

pub async fn json_handler() -> Json<serde_json::Value> {
    Json(json!({ "message": "Hello, world!" }))
}

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
        .into_response()
}

pub async fn alerts(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "alerting": state.metrics.maybe_alert(),
        "alerts_total": state.metrics.alerts_total(),
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> AppResult<impl IntoResponse> {
    validate_credentials(&payload.username, &payload.password)?;

    if state.users.find_user(&payload.username)?.is_some() {
        return Err(AppError::Conflict("user already exists".into()));
    }

    let password_hash = hash(&payload.password, DEFAULT_COST)?;
    state.users.create_user(&payload.username, &password_hash)?;

    info!("registered user {}", payload.username);
    Ok((
        StatusCode::CREATED,
        Json(json!({ "message": "user registered" })),
    )
        .into_response())
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> AppResult<impl IntoResponse> {
    validate_credentials(&payload.username, &payload.password)?;

    let Some(password_hash) = state.users.find_user(&payload.username)? else {
        return Err(AppError::Unauthorized("invalid credentials".into()));
    };

    if verify(&payload.password, &password_hash)? {
        let access_expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::minutes(15))
            .ok_or_else(|| AppError::Token("failed to build access expiration".into()))?
            .timestamp()
            .try_into()
            .map_err(|_| AppError::Token("invalid access exp".into()))?;

        let refresh_expiration = chrono::Utc::now()
            .checked_add_signed(chrono::Duration::days(7))
            .ok_or_else(|| AppError::Token("failed to build refresh expiration".into()))?
            .timestamp()
            .try_into()
            .map_err(|_| AppError::Token("invalid refresh exp".into()))?;

        let issued_at = chrono::Utc::now()
            .timestamp()
            .try_into()
            .map_err(|_| AppError::Token("invalid iat".into()))?;

        let access_jti = format!("access-{}", uuid::Uuid::new_v4());
        let refresh_jti = format!("refresh-{}", uuid::Uuid::new_v4());

        let access_claims = Claims {
            username: payload.username.clone(),
            exp: Some(access_expiration),
            iat: Some(issued_at),
            nbf: Some(issued_at),
            jti: access_jti.clone(),
        };
        let refresh_claims = Claims {
            username: payload.username.clone(),
            exp: Some(refresh_expiration),
            iat: Some(issued_at),
            nbf: Some(issued_at),
            jti: refresh_jti.clone(),
        };

        let secret = state.config.jwt_secret_bytes();
        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(&secret),
        )?;
        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &EncodingKey::from_secret(&secret),
        )?;

        state.tokens.replace_token_for_user(
            &access_token,
            &payload.username,
            "access",
            &access_jti,
        )?;
        state.tokens.replace_token_for_user(
            &refresh_token,
            &payload.username,
            "refresh",
            &refresh_jti,
        )?;

        info!("issued tokens for user {}", payload.username);
        return Ok((
            StatusCode::OK,
            Json(TokenResponse {
                access_token,
                refresh_token,
            }),
        )
            .into_response());
    }

    Err(AppError::Unauthorized("invalid credentials".into()))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> AppResult<impl IntoResponse> {
    if !state.tokens.has_token(&payload.refresh_token)? {
        return Err(AppError::Unauthorized("invalid refresh token".into()));
    }

    let decoding_key = DecodingKey::from_secret(&state.config.jwt_secret_bytes());
    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(&payload.refresh_token, &decoding_key, &validation)?;

    let access_expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(15))
        .ok_or_else(|| AppError::Token("failed to build access expiration".into()))?
        .timestamp()
        .try_into()
        .map_err(|_| AppError::Token("invalid access exp".into()))?;

    let issued_at = chrono::Utc::now()
        .timestamp()
        .try_into()
        .map_err(|_| AppError::Token("invalid iat".into()))?;
    let access_jti = format!("access-{}", uuid::Uuid::new_v4());

    let access_claims = Claims {
        username: token_data.claims.username.clone(),
        exp: Some(access_expiration),
        iat: Some(issued_at),
        nbf: Some(issued_at),
        jti: access_jti.clone(),
    };

    let secret = state.config.jwt_secret_bytes();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(&secret),
    )?;
    state.tokens.replace_token_for_user(
        &access_token,
        &token_data.claims.username,
        "access",
        &access_jti,
    )?;

    info!("refreshed token for user {}", token_data.claims.username);
    Ok((
        StatusCode::OK,
        Json(json!({ "access_token": access_token })),
    )
        .into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<impl IntoResponse> {
    let Some(auth_header) = headers.get("authorization") else {
        warn!("logout missing authorization header");
        return Err(AppError::Unauthorized(
            "missing authorization header".into(),
        ));
    };

    let Ok(auth_value) = auth_header.to_str() else {
        return Err(AppError::Unauthorized(
            "invalid authorization header".into(),
        ));
    };

    let Some(token) = auth_value.strip_prefix("Bearer ") else {
        warn!("logout received malformed authorization header");
        return Err(AppError::Unauthorized("expected bearer token".into()));
    };

    if token.trim().is_empty() {
        warn!("logout attempted with empty token");
        return Err(AppError::Unauthorized("token must not be empty".into()));
    }

    state.tokens.invalidate_token(token)?;
    info!("invalidated token");
    Ok((StatusCode::OK, Json(json!({ "message": "logged out" }))).into_response())
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> AppResult<impl IntoResponse> {
    let Some(auth_header) = headers.get("authorization") else {
        warn!("profile lookup missing authorization header");
        return Err(AppError::Unauthorized(
            "missing authorization header".into(),
        ));
    };

    let Ok(auth_value) = auth_header.to_str() else {
        return Err(AppError::Unauthorized(
            "invalid authorization header".into(),
        ));
    };

    let Some(token) = auth_value.strip_prefix("Bearer ") else {
        warn!("profile lookup received malformed authorization header");
        return Err(AppError::Unauthorized("expected bearer token".into()));
    };

    if token.trim().is_empty() {
        warn!("profile lookup attempted with empty token");
        return Err(AppError::Unauthorized("token must not be empty".into()));
    }

    if !state.tokens.has_token(token)? {
        return Err(AppError::Unauthorized("invalid token".into()));
    }

    let decoding_key = DecodingKey::from_secret(&state.config.jwt_secret_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;

    let now = chrono::Utc::now().timestamp() as usize;
    let issued_at = token_data.claims.iat.unwrap_or(0);
    let not_before = token_data.claims.nbf.unwrap_or(0);

    if issued_at > now || not_before > now {
        return Err(AppError::Unauthorized("token not yet valid".into()));
    }

    Ok((
        StatusCode::OK,
        Json(MeResponse {
            username: token_data.claims.username,
        }),
    )
        .into_response())
}
