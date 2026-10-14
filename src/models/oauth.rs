//! OAuth login models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// Request to login with an OAuth provider (Google or Microsoft)
///
/// The frontend handles the OAuth redirect flow and obtains an ID token
/// from the provider. This request sends that token to LoginFlow for
/// validation and session creation.
///
/// # Example
/// ```rust
/// use loginflow_sdk::OAuthLoginRequest;
///
/// let req = OAuthLoginRequest {
///     provider: "google".to_string(),
///     id_token: "eyJhbGciOiJSUzI1Ni...".to_string(),
/// };
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthLoginRequest {
    /// OAuth provider: "google" or "microsoft"
    pub provider: String,
    /// ID token (JWT) obtained from the OAuth provider
    pub id_token: String,
}

debug_redacted!(OAuthLoginRequest {
    public: [provider],
    secret: [id_token]
});

/// Internal request sent to `POST /v1/public/oauth-login`
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowOAuthLoginRequest {
    pub provider: String,
    pub id_token: String,
    pub company_id: String,
    pub application_id: String,
}

debug_redacted!(LoginFlowOAuthLoginRequest {
    public: [provider, company_id, application_id],
    secret: [id_token]
});
