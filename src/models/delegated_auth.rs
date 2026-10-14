//! Delegated authentication models for LoginFlow SDK
//!
//! Supports the delegated auth flow where one user (e.g. parent) creates a
//! temporary code that another user (e.g. child) can use to log in.

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
    /// 6-digit code to share with the delegate
    pub code: String,
    /// Expiration timestamp (24 hours from creation)
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
    /// 6-digit code received from the token creator
    pub code: String,
}

debug_redacted!(ValidateDelegatedTokenRequest {
    public: [],
    secret: [code]
});

/// Internal request sent to the LoginFlow API
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowValidateDelegatedTokenRequest {
    pub code: String,
    pub company_id: String,
    pub application_id: String,
}

debug_redacted!(LoginFlowValidateDelegatedTokenRequest {
    public: [company_id, application_id],
    secret: [code]
});
