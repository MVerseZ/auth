use axum::{http::StatusCode, response::IntoResponse};
use bcrypt::BcryptError;
use serde_json::json;
use std::{error::Error, fmt};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
pub enum AppError {
    Validation(String),
    Unauthorized(String),
    Conflict(String),
    Database(String),
    Hash(String),
    Token(String),
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_) | Self::Hash(_) | Self::Token(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message)
            | Self::Unauthorized(message)
            | Self::Conflict(message)
            | Self::Database(message)
            | Self::Hash(message)
            | Self::Token(message) => write!(f, "{message}"),
        }
    }
}

impl Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();
        let body = axum::Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<BcryptError> for AppError {
    fn from(err: BcryptError) -> Self {
        Self::Hash(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        Self::Token(err.to_string())
    }
}
