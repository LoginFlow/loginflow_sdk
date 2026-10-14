//! Delegated authentication models for LoginFlow SDK
//!
//! Supports the delegated auth flow where one user (e.g. parent) creates a
//! short-lived token that someone they trust (e.g. child) redeems, together
//! with the creator's email, to sign in as the creator.

use serde::{Deserialize, Serialize};

/// Request for creating a delegated authentication token
///
/// The SDK automatically adds `company_id` and `application_id` from config.
/// The `creator_user_id` is extracted server-side from the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDelegatedTokenRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Internal request sent to the LoginFlow API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowCreateDelegatedTokenRequest {
    pub company_id: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Response from creating a delegated token
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateDelegatedTokenResponse {
    pub success: bool,
    pub message: String,
    /// 8-character token to share with the delegate, drawn from
    /// `23456789ABCDEFGHJKMNPQRSTUVWXYZ` (case-insensitive when redeemed)
    pub code: String,
    /// Expiration timestamp (15 minutes after creation)
    pub expires_at: String,
    /// Minutes until expiration
    pub expires_in_minutes: i64,
}

debug_redacted!(CreateDelegatedTokenResponse {
    public: [success, message, expires_at, expires_in_minutes],
    secret: [code]
});

/// Request for validating a delegated token and logging in
///
/// The SDK automatically adds `company_id` and `application_id` from config.
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidateDelegatedTokenRequest {
    /// 8-character token received from the token creator (case-insensitive)
    pub code: String,
    /// Email of the user who created the token (required by the server)
    pub email: String,
}

debug_redacted!(ValidateDelegatedTokenRequest {
    public: [email],
    secret: [code]
});

/// Internal request sent to the LoginFlow API
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowValidateDelegatedTokenRequest {
    pub code: String,
    pub email: String,
    pub company_id: String,
    pub application_id: String,
}

debug_redacted!(LoginFlowValidateDelegatedTokenRequest {
    public: [email, company_id, application_id],
    secret: [code]
});
