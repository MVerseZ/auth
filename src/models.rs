use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub username: String,
    pub exp: Option<usize>,
    pub iat: Option<usize>,
    pub nbf: Option<usize>,
    pub jti: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}
