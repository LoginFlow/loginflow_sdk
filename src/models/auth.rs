//! Authentication models for LoginFlow SDK.
//!
//! SDK v0.6.0 removes the ROPC-like REST login surface
//! (`register`, `login`, `refresh_token`, `logout`, email verification, OTP login, OAuth login,
//! password reset, delegated auth): those flows move to the hosted/native OIDC challenge. Only
//! the generic response envelope and the claims-derived [`AuthenticatedUser`] remain here.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::jwt::JwtClaims;

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
// AUTHENTICATED USER (extracted from JWT)
// ============================================================================

/// User data taken from a verified access token.
///
/// No email: the access token carries no PII. Resolve it, when actually needed, through
/// [`crate::LoginFlowClient::userinfo`] (scope `email`) instead of caching it off a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub company_user_id: Uuid,
    pub role: String,
    pub company_id: Uuid,
    pub application_id: Uuid,
    /// Federations: the company whose credential actually authenticated this user, present
    /// ONLY when it differs from `company_id` (a `session`-level federation reuse or a
    /// cross-company Native SSO exchange). `None` on every ordinary, non-federated token —
    /// authorization decisions must key off `company_id`, never this field.
    pub auth_cid: Option<Uuid>,
}

impl AuthenticatedUser {
    /// Build the user from verified claims.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when `sub`, `company_id`, `application_id` or (when
    /// present) `auth_cid` is not a UUID.
    pub fn from_claims(claims: &JwtClaims) -> LoginFlowResult<Self> {
        Ok(Self {
            company_user_id: parse_claim_uuid(&claims.sub, "subject")?,
            role: claims.role.clone(),
            company_id: parse_claim_uuid(&claims.company_id, "company ID")?,
            application_id: parse_claim_uuid(&claims.application_id, "application ID")?,
            auth_cid: claims
                .auth_cid
                .as_deref()
                .map(|value| parse_claim_uuid(value, "auth_cid"))
                .transpose()?,
        })
    }

    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.role == "app_admin" || self.role == "master"
    }

    /// Check if user has master role
    pub fn is_master(&self) -> bool {
        self.role == "master"
    }
}

fn parse_claim_uuid(value: &str, name: &str) -> LoginFlowResult<Uuid> {
    Uuid::parse_str(value)
        .map_err(|_| LoginFlowError::Authentication(format!("Invalid {name} format in token")))
}

// ============================================================================
// USERINFO (OIDC Core §5.3.2)
// ============================================================================

/// `GET /oauth2/userinfo` response. `sub` is always present; the rest is resolved live from the
/// repository and shaped by the token's scope — `role`/`user_id` need `profile`, `email` needs
/// `email`. This is the SDK's one sanctioned way to read a user's email: never off an access
/// token claim (the access token itself carries no PII).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}
