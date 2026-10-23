//! Authentication models for LoginFlow SDK.
//!
//! SDK v0.6.0 removes the ROPC-like REST login surface
//! (`register`, `login`, `refresh_token`, `logout`, email verification, OTP login, OAuth login,
//! password reset, delegated auth): those flows move to the hosted/native OIDC challenge. Only
//! the generic response envelope and the userinfo answer remain here; the verified caller of a
//! resource server is [`crate::actix::Authorized`].

use serde::{Deserialize, Serialize};

/// Metadata from LoginFlow API responses (LoginFlow standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// The HTTP status.
    pub status: u16,
    /// When the answer was built (RFC 3339).
    pub timestamp: String,
    /// The request's id, for support; `null` on the error of some handlers.
    pub request_id: Option<String>,
    /// The request's path; `null` on the error of some handlers.
    pub path: Option<String>,
}

/// Generic LoginFlow response wrapper (LoginFlow standard)
///
/// All success responses follow: `{ "data": T, "meta": { status, timestamp, request_id, path } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowResponseWrapper<T> {
    /// The answer itself.
    pub data: T,
    /// The answer's metadata.
    pub meta: ResponseMeta,
}

/// Structured error response from LoginFlow API (LoginFlow standard)
///
/// All error responses follow: `{ "error": { code, message, details? }, "meta": { ... } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorResponse {
    /// What went wrong.
    pub error: LoginFlowErrorDetail,
    /// The answer's metadata.
    pub meta: ResponseMeta,
}

/// Error detail from a LoginFlow API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorDetail {
    /// Stable error code (`VALIDATION_ERROR`, `role_not_grantable`, ...).
    pub code: String,
    /// Human-readable message; generic for `UNAUTHORIZED`, `FORBIDDEN` and `VALIDATION_ERROR`.
    pub message: String,
    /// The specific reason of a validation error, or a structured payload of a coded refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

// ============================================================================
// USERINFO (OIDC Core §5.3.2)
// ============================================================================

/// `GET /oauth2/userinfo` response. `sub` is always present; the rest is resolved live from the
/// repository and shaped by the token's scope — `user_id` needs `profile`, `email` needs
/// `email`. This is the SDK's one sanctioned way to read a user's email: never off an access
/// token claim (the access token itself carries no PII).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    /// The token's `sub` (`company_users` id).
    pub sub: String,
    /// The person's profile id; only with scope `profile`.
    #[serde(default)]
    pub user_id: Option<String>,
    /// The person's email; only with scope `email`.
    #[serde(default)]
    pub email: Option<String>,
}
