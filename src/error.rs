//! Error types for LoginFlow SDK
//!
//! Provides comprehensive error handling with detailed error types.

use std::fmt;

/// Main error type for LoginFlow SDK operations
#[derive(Debug, Clone)]
pub enum LoginFlowError {
    /// Configuration error (missing env vars, invalid values)
    Config(String),

    /// Network/HTTP error
    Network(String),

    /// Authentication failed (invalid credentials)
    Authentication(String),

    /// Authorization failed (valid token but insufficient permissions)
    Authorization(String),

    /// Validation error (invalid input)
    Validation(String),

    /// Resource not found
    NotFound(String),

    /// Rate limit exceeded
    RateLimit(String),

    /// Server error from LoginFlow
    ServerError(String),

    /// Invalid response format
    ParseError(String),

    /// Request timeout
    Timeout(String),
}

impl fmt::Display for LoginFlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginFlowError::Config(msg) => write!(f, "Configuration error: {}", msg),
            LoginFlowError::Network(msg) => write!(f, "Network error: {}", msg),
            LoginFlowError::Authentication(msg) => write!(f, "Authentication failed: {}", msg),
            LoginFlowError::Authorization(msg) => write!(f, "Authorization failed: {}", msg),
            LoginFlowError::Validation(msg) => write!(f, "Validation error: {}", msg),
            LoginFlowError::NotFound(msg) => write!(f, "Not found: {}", msg),
            LoginFlowError::RateLimit(msg) => write!(f, "Rate limit exceeded: {}", msg),
            LoginFlowError::ServerError(msg) => write!(f, "Server error: {}", msg),
            LoginFlowError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LoginFlowError::Timeout(msg) => write!(f, "Request timeout: {}", msg),
        }
    }
}

impl std::error::Error for LoginFlowError {}

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

impl From<crate::config::ConfigError> for LoginFlowError {
    fn from(err: crate::config::ConfigError) -> Self {
        LoginFlowError::Config(err.to_string())
    }
}

/// Result type alias for LoginFlow operations
pub type LoginFlowResult<T> = Result<T, LoginFlowError>;

/// HTTP status code to error conversion helper
impl LoginFlowError {
    /// Create error from HTTP status code and response body.
    ///
    /// Parses the AulaMás error format `{ "error": { "code": "...", "message": "..." } }`
    /// to extract structured error messages. Falls back to raw body if parsing fails.
    pub fn from_status(status: u16, body: &str) -> Self {
        let (error_code, message) = Self::extract_error_fields(body);
        match status {
            400 => LoginFlowError::Validation(message),
            401 => {
                if error_code.as_deref() == Some("UNAUTHORIZED") {
                    LoginFlowError::Authentication(
                        "Authentication is required (token may be expired, revoked, or session inactive)"
                            .to_string(),
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
    fn extract_error_fields(body: &str) -> (Option<String>, String) {
        let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
        let code = parsed
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let message = parsed
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .map(|s| s.to_string())
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
        )
    }

    /// Returns true when caller should clear local auth state and force login.
    pub fn requires_reauthentication(&self) -> bool {
        matches!(self, LoginFlowError::Authentication(_))
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for LoginFlowError {
    fn error_response(&self) -> actix_web::HttpResponse {
        use actix_web::http::StatusCode;

        let status = match self {
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
        };

        actix_web::HttpResponse::build(status).json(serde_json::json!({
            "error": self.to_string(),
            "error_type": format!("{:?}", self).split('(').next().unwrap_or("Unknown")
        }))
    }
}
