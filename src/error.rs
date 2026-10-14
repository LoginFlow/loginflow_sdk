//! Error types for LoginFlow SDK
//!
//! A single error type, [`LoginFlowError`], covers every fallible SDK operation.

#[cfg(feature = "actix")]
use actix_web::http::StatusCode;
#[cfg(feature = "actix")]
use log::error;
use thiserror::Error;

use crate::config::ConfigError;

/// Main error type for LoginFlow SDK operations
#[derive(Debug, Clone, Error)]
pub enum LoginFlowError {
    /// Configuration error (missing env vars, invalid values, client not registered)
    #[error("Configuration error: {0}")]
    Config(String),

    /// Network/HTTP error
    #[error("Network error: {0}")]
    Network(String),

    /// Authentication failed (invalid credentials, invalid or rejected token)
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Authorization failed (valid token but insufficient permissions)
    #[error("Authorization failed: {0}")]
    Authorization(String),

    /// Validation error (invalid input)
    #[error("Validation error: {0}")]
    Validation(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Server error from LoginFlow
    #[error("Server error: {0}")]
    ServerError(String),

    /// Invalid response format
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Request timeout
    #[error("Request timeout: {0}")]
    Timeout(String),

    /// The LoginFlow signing keys (JWKS) could not be fetched or are unusable
    #[error("Signing key set error: {0}")]
    Jwks(String),
}

impl From<reqwest::Error> for LoginFlowError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            LoginFlowError::Timeout(err.to_string())
        } else if err.is_connect() {
            LoginFlowError::Network(format!("Connection failed: {}", err))
        } else if err.is_decode() {
            LoginFlowError::ParseError(format!("Failed to decode response: {}", err))
        } else {
            LoginFlowError::Network(err.to_string())
        }
    }
}

impl From<serde_json::Error> for LoginFlowError {
    fn from(err: serde_json::Error) -> Self {
        LoginFlowError::ParseError(err.to_string())
    }
}

impl From<ConfigError> for LoginFlowError {
    fn from(err: ConfigError) -> Self {
        LoginFlowError::Config(err.to_string())
    }
}

/// Result type alias for LoginFlow operations
pub type LoginFlowResult<T> = Result<T, LoginFlowError>;

impl LoginFlowError {
    /// Create error from HTTP status code and response body.
    ///
    /// Parses the LoginFlow error format `{ "error": { "code": "...", "message": "..." } }`
    /// to extract structured error messages. Falls back to the raw body if parsing fails.
    pub fn from_status(status: u16, body: &str) -> Self {
        let (error_code, message) = Self::extract_error_fields(body);
        match status {
            400 => LoginFlowError::Validation(message),
            401 => {
                if error_code.as_deref() == Some("UNAUTHORIZED") {
                    LoginFlowError::Authentication(
                        "Authentication is required (token may be expired, revoked, or session inactive)".to_string(),
                    )
                } else {
                    LoginFlowError::Authentication(message)
                }
            }
            403 => LoginFlowError::Authorization(message),
            404 => LoginFlowError::NotFound(message),
            422 => LoginFlowError::Validation(message),
            429 => LoginFlowError::RateLimit(message),
            500..=599 => LoginFlowError::ServerError(message),
            _ => LoginFlowError::Network(format!("HTTP {}: {}", status, message)),
        }
    }

    /// Extract error fields from standardized API response:
    /// `{ "error": { "code": "...", "message": "...", "details": "..." } }`
    pub(crate) fn extract_error_fields(body: &str) -> (Option<String>, String) {
        let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
        let error = parsed.as_ref().and_then(|v| v.get("error"));
        let code = error
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str())
            .map(str::to_string);
        let message = error
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| body.to_string());
        (code, message)
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LoginFlowError::Network(_)
                | LoginFlowError::Timeout(_)
                | LoginFlowError::RateLimit(_)
                | LoginFlowError::ServerError(_)
                | LoginFlowError::Jwks(_)
        )
    }

    /// Returns true when caller should clear local auth state and force login.
    pub fn requires_reauthentication(&self) -> bool {
        matches!(self, LoginFlowError::Authentication(_))
    }

    /// Short variant name, used as `error_type` in HTTP error bodies.
    pub fn kind(&self) -> &'static str {
        match self {
            LoginFlowError::Config(_) => "Config",
            LoginFlowError::Network(_) => "Network",
            LoginFlowError::Authentication(_) => "Authentication",
            LoginFlowError::Authorization(_) => "Authorization",
            LoginFlowError::Validation(_) => "Validation",
            LoginFlowError::NotFound(_) => "NotFound",
            LoginFlowError::RateLimit(_) => "RateLimit",
            LoginFlowError::ServerError(_) => "ServerError",
            LoginFlowError::ParseError(_) => "ParseError",
            LoginFlowError::Timeout(_) => "Timeout",
            LoginFlowError::Jwks(_) => "Jwks",
        }
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for LoginFlowError {
    fn status_code(&self) -> StatusCode {
        match self {
            LoginFlowError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LoginFlowError::Network(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::Authentication(_) => StatusCode::UNAUTHORIZED,
            LoginFlowError::Authorization(_) => StatusCode::FORBIDDEN,
            LoginFlowError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            LoginFlowError::NotFound(_) => StatusCode::NOT_FOUND,
            LoginFlowError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            LoginFlowError::ServerError(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::ParseError(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            LoginFlowError::Jwks(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// 4xx bodies carry the error message. 5xx bodies carry a fixed message:
    /// upstream and configuration details (URLs, transport errors) are logged,
    /// never sent to the client.
    fn error_response(&self) -> actix_web::HttpResponse {
        let message = match self {
            LoginFlowError::Config(_) => {
                error!("LoginFlow SDK misconfigured: {}", self);
                "Authentication is not configured".to_string()
            }
            LoginFlowError::Network(_)
            | LoginFlowError::ServerError(_)
            | LoginFlowError::ParseError(_)
            | LoginFlowError::Timeout(_)
            | LoginFlowError::Jwks(_) => {
                error!("LoginFlow upstream failure: {}", self);
                "Authentication service unavailable".to_string()
            }
            _ => self.to_string(),
        };
        actix_web::HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": message,
            "error_type": self.kind(),
        }))
    }
}
