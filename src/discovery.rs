//! `GET /.well-known/openid-configuration` (OIDC Discovery 1.0).
//!
//! The server's own contract is explicit: "a client is never expected to hardcode a path"
//! (`loginflow_api`'s `discovery_document.rs`). Every endpoint this SDK calls beyond the
//! versioned `/v{n}/...` REST surface (which has no discovery entry of its own) is resolved from
//! here, not assembled from `base_url` by convention.

use serde::Deserialize;

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::read_capped;

/// Maximum size of a discovery document response body.
const DISCOVERY_BODY_LIMIT: usize = 32 * 1024;

/// The fields of the discovery document this SDK actually resolves endpoints from. Unknown
/// fields (vendor extensions, future additions) are ignored rather than rejected.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    /// The issuer: the `iss` of every LoginFlow token.
    pub issuer: String,
    /// The signing keys (`/oauth2/jwks`).
    pub jwks_uri: String,
    /// The browser authorization endpoint (`/oauth2/authorize`).
    pub authorization_endpoint: String,
    /// The token endpoint (`/oauth2/token`), for [`crate::ClientCredentialsClient`] and the
    /// `/v1/service` clients.
    pub token_endpoint: String,
    /// `/oauth2/userinfo`, for [`crate::LoginFlowClient::userinfo`].
    pub userinfo_endpoint: String,
    /// `/oauth2/introspect`, for [`crate::IntrospectionClient`].
    pub introspection_endpoint: String,
    /// `/oauth2/revoke`, for [`crate::RevocationClient`].
    pub revocation_endpoint: String,
    /// `/oauth2/end-session` (RP-initiated logout).
    pub end_session_endpoint: String,
    /// The first-party challenge endpoint (`/oauth2/authorize-challenge`), when published.
    #[serde(default)]
    pub authorization_challenge_endpoint: Option<String>,
    /// LoginFlow's login-options endpoint, when published.
    #[serde(rename = "loginflow_login_options_endpoint", default)]
    pub login_options_endpoint: Option<String>,
    /// LoginFlow's device-logout endpoint, when published.
    #[serde(rename = "loginflow_device_logout_endpoint", default)]
    pub device_logout_endpoint: Option<String>,
    /// LoginFlow's logout-everywhere endpoint, when published.
    #[serde(rename = "loginflow_global_logout_endpoint", default)]
    pub global_logout_endpoint: Option<String>,
}

/// Downloads and parses the discovery document at `{base_url}/.well-known/openid-configuration`.
///
/// # Errors
/// [`LoginFlowError::Network`] when the request fails or the body exceeds 32 KiB;
/// [`LoginFlowError::ParseError`] when the body is not a valid discovery document.
pub async fn fetch(http: &reqwest::Client, base_url: &str) -> LoginFlowResult<DiscoveryDocument> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        base_url.trim_end_matches('/')
    );
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|e| LoginFlowError::Network(format!("fetching discovery document: {e}")))?;
    if !response.status().is_success() {
        return Err(LoginFlowError::Network(format!(
            "discovery document endpoint answered {}",
            response.status()
        )));
    }
    let body = read_capped(response, DISCOVERY_BODY_LIMIT)
        .await
        .map_err(|e| LoginFlowError::Network(e.to_string()))?;
    if body.exceeded {
        return Err(LoginFlowError::Network(format!(
            "discovery document exceeds {DISCOVERY_BODY_LIMIT} bytes"
        )));
    }
    serde_json::from_slice(&body.bytes)
        .map_err(|e| LoginFlowError::ParseError(format!("invalid discovery document: {e}")))
}
