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
    pub status: u16,
    pub timestamp: String,
    pub request_id: String,
    pub path: String,
}

/// Generic LoginFlow response wrapper (LoginFlow standard)
///
/// All success responses follow: `{ "data": T, "meta": { status, timestamp, request_id, path } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowResponseWrapper<T> {
    pub data: T,
    pub meta: ResponseMeta,
}

/// Structured error response from LoginFlow API (LoginFlow standard)
///
/// All error responses follow: `{ "error": { code, message, details? }, "meta": { ... } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorResponse {
    pub error: LoginFlowErrorDetail,
    pub meta: ResponseMeta,
}

/// Error detail from a LoginFlow API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
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
    pub sub: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}
