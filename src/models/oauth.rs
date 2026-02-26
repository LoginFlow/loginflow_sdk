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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthLoginRequest {
    /// OAuth provider: "google" or "microsoft"
    pub provider: String,
    /// ID token (JWT) obtained from the OAuth provider
    pub id_token: String,
}
