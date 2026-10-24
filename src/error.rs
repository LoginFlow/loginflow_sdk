//! Error types for LoginFlow SDK
//!
//! A single error type, [`LoginFlowError`], covers every fallible SDK operation.

#[cfg(feature = "actix")]
use actix_web::http::StatusCode;
#[cfg(feature = "actix")]
use actix_web::http::header::{RETRY_AFTER, WWW_AUTHENTICATE};
#[cfg(feature = "actix")]
use log::error;
use thiserror::Error;

use crate::config::ConfigError;

/// `error.code` of a `401` about a one-time code the user typed (a wrong or locked-out TOTP
/// code), not about the access token: it maps to [`LoginFlowError::Validation`].
pub const INVALID_CODE: &str = "INVALID_CODE";

/// Main error type for LoginFlow SDK operations
#[derive(Debug, Clone, Error)]
pub enum LoginFlowError {
    /// Configuration or wiring error: a missing or invalid setting, an HTTP client that cannot
    /// be built, or [`crate::actix::Authorized`] asked for outside the permission gate (`500`).
    #[error("Configuration error: {0}")]
    Config(String),

    /// The request could not be sent or answered (connection, transport), or an unexpected
    /// HTTP status.
    #[error("Network error: {0}")]
    Network(String),

    /// Authentication failed (`401`): the access token or the client credentials were refused
    /// (expired, revoked, ended session, wrong secret). `code` is the server's `error.code` when
    /// it sent a specific one — e.g. `invalid_actor_token` when the person's token a
    /// [`crate::MembersClient`] call forwarded was refused, while the key's own token was fine. A
    /// `401` about a code the user typed is [`Validation`](Self::Validation) instead.
    #[error("Authentication failed: {message}")]
    Authentication {
        /// The server's error message, or the SDK's reason for a check it runs itself
        message: String,
        /// The server's error code (`error.code` of the envelope), when it sent one other than
        /// the generic `UNAUTHORIZED`
        code: Option<String>,
    },

    /// Authorization failed (`403`: a valid token, but the request is refused). `code` is the
    /// server's `error.code` when it sent one: the refusals of a grant or revocation
    /// (`key_role_not_grantable` for the key's ceiling; `role_not_grantable`,
    /// `organization_out_of_reach`, `privilege_exceeds_grantor`, `self_assignment_forbidden` for
    /// the person, ...) tell the caller why without parsing `message`.
    #[error("Authorization failed: {message}")]
    Authorization {
        /// The server's error message
        message: String,
        /// The server's error code (`error.code` of the envelope), when it sent one
        code: Option<String>,
    },

    /// The request was refused for its input (`400`, `422`, or a `401` with code
    /// [`INVALID_CODE`]): `message` is the server's specific reason (`error.details` when it is
    /// text), `code` the envelope's `error.code` (`VALIDATION_ERROR`, `BAD_REQUEST`,
    /// `INVALID_CODE`, `expires_at_in_past`, `role_not_assignable_here`, `actor_token_required`,
    /// `role_not_held_by_principal`, ...). A check the SDK
    /// runs before sending (e.g. [`crate::PermissionManifest::validate`]) has no `code`.
    #[error("Validation error: {message}")]
    Validation {
        /// The server's reason (`error.details` when it is text, otherwise `error.message`)
        message: String,
        /// The server's error code (`error.code` of the envelope), when it sent one
        code: Option<String>,
    },

    /// Not found (`404`): `code` tells what is missing when the server says so
    /// (`member_not_found`, `organization_not_found`, `role_not_found`, `assignment_not_found`,
    /// `NOT_FOUND`).
    #[error("Not found: {message}")]
    NotFound {
        /// The server's error message
        message: String,
        /// The server's error code (`error.code` of the envelope), when it sent one
        code: Option<String>,
    },

    /// The request conflicts with the current state of the resource (`409`), e.g. the email is
    /// already registered, or `code` `"access_codes_disabled"` when the application does not
    /// accept access codes.
    #[error("Conflict: {message}")]
    Conflict {
        /// The server's error message
        message: String,
        /// The server's error code (`error.code` of the envelope), when it sent one
        code: Option<String>,
    },

    /// Rate limit exceeded (`429`)
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        /// The server's error message
        message: String,
        /// Seconds to wait before retrying, from the `Retry-After` header when the server sent one
        retry_after_secs: Option<u64>,
    },

    /// LoginFlow is temporarily unable to serve the request (`503`); try again later
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

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

    /// `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470):
    /// the access token is valid but too old for this operation (e.g. `change_password` requires
    /// `auth_time` within the last 300 s). The caller must re-authenticate (step-up) and retry.
    #[error("Recent authentication required{}", .max_age_secs.map(|s| format!(" (max_age={s}s)")).unwrap_or_default())]
    InsufficientUserAuthentication {
        /// The `max_age` the server asks for, in seconds, when it sent one.
        max_age_secs: Option<u64>,
    },
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
    /// [`Authentication`](Self::Authentication) without a server code: a token the SDK itself
    /// refused, or a `401` whose envelope names no specific code.
    pub fn authentication(message: impl Into<String>) -> Self {
        LoginFlowError::Authentication {
            message: message.into(),
            code: None,
        }
    }

    /// Create error from HTTP status code, response body and `Retry-After` seconds.
    ///
    /// Parses the LoginFlow error envelope `{ "error": { "code", "message", "details"? } }`: the
    /// message is `error.details` when it is text (the specific reason of a `422`, e.g. "The
    /// passwords do not match"), otherwise `error.message`, otherwise the raw body. `code` is
    /// `error.code`. `retry_after_secs` is only kept for a `429`.
    ///
    /// | Status | Variant |
    /// |---|---|
    /// | `400`, `422` | [`Validation`](Self::Validation) |
    /// | `401` with code `INVALID_CODE` (a wrong or locked-out TOTP code) | [`Validation`](Self::Validation) |
    /// | any other `401` | [`Authentication`](Self::Authentication), with the code unless it is the generic `UNAUTHORIZED` |
    /// | `403` | [`Authorization`](Self::Authorization) |
    /// | `404` | [`NotFound`](Self::NotFound) |
    /// | `409` | [`Conflict`](Self::Conflict) |
    /// | `429` | [`RateLimit`](Self::RateLimit) |
    /// | `503` | [`ServiceUnavailable`](Self::ServiceUnavailable) |
    /// | other `5xx` | [`ServerError`](Self::ServerError) |
    /// | anything else | [`Network`](Self::Network) |
    pub fn from_status(status: u16, body: &str, retry_after_secs: Option<u64>) -> Self {
        let (code, message) = Self::extract_error_fields(body);
        match status {
            400 | 422 => LoginFlowError::Validation { message, code },
            401 if code.as_deref() == Some(INVALID_CODE) => {
                LoginFlowError::Validation { message, code }
            }
            401 => {
                if code.as_deref() == Some("UNAUTHORIZED") {
                    LoginFlowError::authentication(
                        "Authentication is required (token may be expired, revoked, or session inactive)",
                    )
                } else {
                    LoginFlowError::Authentication { message, code }
                }
            }
            403 => LoginFlowError::Authorization { message, code },
            404 => LoginFlowError::NotFound { message, code },
            409 => LoginFlowError::Conflict { message, code },
            429 => LoginFlowError::RateLimit {
                message,
                retry_after_secs,
            },
            503 => LoginFlowError::ServiceUnavailable(message),
            500..=599 => LoginFlowError::ServerError(message),
            _ => LoginFlowError::Network(format!("HTTP {}: {}", status, message)),
        }
    }

    /// `(error.code, reason)` of a LoginFlow error envelope
    /// `{ "error": { "code": "...", "message": "...", "details": ... } }`. The reason is
    /// `error.details` when it is text, otherwise `error.message`, otherwise the raw body.
    pub(crate) fn extract_error_fields(body: &str) -> (Option<String>, String) {
        let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
        let error = parsed.as_ref().and_then(|v| v.get("error"));
        let field = |name: &str| {
            error
                .and_then(|e| e.get(name))
                .and_then(|value| value.as_str())
                .filter(|text| !text.trim().is_empty())
                .map(str::to_string)
        };
        let message = field("details")
            .or_else(|| field("message"))
            .unwrap_or_else(|| body.to_string());
        (field("code"), message)
    }

    /// Whether the same call may succeed later: network failures, timeouts, rate limits, `5xx`
    /// and an unavailable key set.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            LoginFlowError::Network(_)
                | LoginFlowError::Timeout(_)
                | LoginFlowError::RateLimit { .. }
                | LoginFlowError::ServiceUnavailable(_)
                | LoginFlowError::ServerError(_)
                | LoginFlowError::Jwks(_)
        )
    }

    /// Whether the caller should clear the person's local session and sign them in again:
    /// `true` for [`Authentication`](Self::Authentication) and
    /// [`InsufficientUserAuthentication`](Self::InsufficientUserAuthentication) only.
    pub fn requires_reauthentication(&self) -> bool {
        matches!(
            self,
            LoginFlowError::Authentication { .. }
                | LoginFlowError::InsufficientUserAuthentication { .. }
        )
    }

    /// Short variant name, used as `error_type` in HTTP error bodies.
    pub fn kind(&self) -> &'static str {
        match self {
            LoginFlowError::Config(_) => "Config",
            LoginFlowError::Network(_) => "Network",
            LoginFlowError::Authentication { .. } => "Authentication",
            LoginFlowError::Authorization { .. } => "Authorization",
            LoginFlowError::Validation { .. } => "Validation",
            LoginFlowError::NotFound { .. } => "NotFound",
            LoginFlowError::Conflict { .. } => "Conflict",
            LoginFlowError::RateLimit { .. } => "RateLimit",
            LoginFlowError::ServiceUnavailable(_) => "ServiceUnavailable",
            LoginFlowError::ServerError(_) => "ServerError",
            LoginFlowError::ParseError(_) => "ParseError",
            LoginFlowError::Timeout(_) => "Timeout",
            LoginFlowError::Jwks(_) => "Jwks",
            LoginFlowError::InsufficientUserAuthentication { .. } => {
                "InsufficientUserAuthentication"
            }
        }
    }
}

#[cfg(feature = "actix")]
impl actix_web::ResponseError for LoginFlowError {
    fn status_code(&self) -> StatusCode {
        match self {
            LoginFlowError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LoginFlowError::Network(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::Authentication { .. } => StatusCode::UNAUTHORIZED,
            LoginFlowError::Authorization { .. } => StatusCode::FORBIDDEN,
            LoginFlowError::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            LoginFlowError::NotFound { .. } => StatusCode::NOT_FOUND,
            LoginFlowError::Conflict { .. } => StatusCode::CONFLICT,
            LoginFlowError::RateLimit { .. } => StatusCode::TOO_MANY_REQUESTS,
            LoginFlowError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            LoginFlowError::ServerError(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::ParseError(_) => StatusCode::BAD_GATEWAY,
            LoginFlowError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            LoginFlowError::Jwks(_) => StatusCode::SERVICE_UNAVAILABLE,
            LoginFlowError::InsufficientUserAuthentication { .. } => StatusCode::UNAUTHORIZED,
        }
    }

    /// 4xx bodies carry the error message. 5xx bodies carry a fixed message:
    /// upstream and configuration details (URLs, transport errors) are logged,
    /// never sent to the client. A rate limit with a known wait forwards it as
    /// `Retry-After`.
    fn error_response(&self) -> actix_web::HttpResponse {
        let message = match self {
            LoginFlowError::Config(_) => {
                error!("LoginFlow SDK misconfigured: {}", self);
                "Authentication is not configured".to_string()
            }
            LoginFlowError::Network(_)
            | LoginFlowError::ServiceUnavailable(_)
            | LoginFlowError::ServerError(_)
            | LoginFlowError::ParseError(_)
            | LoginFlowError::Timeout(_)
            | LoginFlowError::Jwks(_) => {
                error!("LoginFlow upstream failure: {}", self);
                "Authentication service unavailable".to_string()
            }
            _ => self.to_string(),
        };
        let mut response = actix_web::HttpResponse::build(self.status_code());
        if let LoginFlowError::RateLimit {
            retry_after_secs: Some(seconds),
            ..
        } = self
        {
            response.insert_header((RETRY_AFTER, *seconds));
        }
        // RFC 9470: a 401 for this reason carries the step-up challenge in `WWW-Authenticate`,
        // not just the JSON body — otherwise a caller cannot tell "insufficient_user_authentication"
        // apart from any other rejected-token 401 without parsing the message string.
        if let LoginFlowError::InsufficientUserAuthentication { max_age_secs } = self {
            let header_value = match max_age_secs {
                Some(seconds) => {
                    format!("Bearer error=\"insufficient_user_authentication\", max_age={seconds}")
                }
                None => "Bearer error=\"insufficient_user_authentication\"".to_string(),
            };
            if let Ok(value) = actix_web::http::header::HeaderValue::from_str(&header_value) {
                response.insert_header((WWW_AUTHENTICATE, value));
            }
        }
        response.json(serde_json::json!({
            "error": message,
            "error_type": self.kind(),
        }))
    }
}
