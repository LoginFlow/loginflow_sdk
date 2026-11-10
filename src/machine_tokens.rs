//! The calling side of machine access: a system that calls another product's API with no person
//! behind the call asks LoginFlow for a short-lived access token for THAT API
//! (`grant_type=client_credentials&resource=<the API's audience>`) and presents it as
//! `Authorization: Bearer <token>`.

use std::fmt;

use reqwest::Client;

use crate::discovery::DiscoveryDocument;
use crate::error::LoginFlowResult;
use crate::oauth2::{ClientCredentialsClient, ClientSecret};

/// Machine tokens for ONE receiving API: `client_credentials` with `resource` = that API's
/// audience, against the issuer's token endpoint, authenticated with `client_secret_basic`.
///
/// - The token is cached and fetched again shortly (30 s) before its `expires_in` runs out (at
///   most 600 s on LoginFlow); concurrent callers past a stale cache share one request
///   (single-flight).
/// - The tokens are plain `Bearer` tokens: this SDK does not create DPoP proofs, so it never
///   asks for a DPoP-bound token.
/// - The secret is a [`ClientSecret`] (wiped on drop, never printed); neither the secret nor a
///   token is ever logged, and `Debug` shows only the client id, the resource and the scope.
///
/// Another API needs another `MachineTokens`: one token is for one audience. Cloning is cheap:
/// clones share the cached token and the HTTP connection pool.
///
/// # Errors of [`access_token`](Self::access_token)
/// | LoginFlow answer | Error |
/// |---|---|
/// | `401 invalid_client` (unknown client, wrong or expired secret, disabled client) | [`crate::LoginFlowError::Authentication`] `{ code: Some("invalid_client") }` |
/// | `400 invalid_target` (no live grant on that API) | [`crate::LoginFlowError::Validation`] `{ code: Some("invalid_target") }` |
/// | `400 invalid_scope` (a `scope` value not granted) | [`crate::LoginFlowError::Validation`] `{ code: Some("invalid_scope") }` |
#[derive(Clone)]
pub struct MachineTokens {
    tokens: ClientCredentialsClient,
    resource: String,
    scope: Option<String>,
}

impl MachineTokens {
    /// Tokens for the API whose audience is `resource` (`app_apis.audience`, exactly), from
    /// `token_url` (the issuer's full `/oauth2/token` URL).
    pub fn new(
        http: Client,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: ClientSecret,
        resource: impl Into<String>,
    ) -> Self {
        let resource = resource.into();
        let tokens = ClientCredentialsClient::new(http, token_url, client_id, client_secret)
            .with_resource(resource.clone());
        Self {
            tokens,
            resource,
            scope: None,
        }
    }

    /// Same as [`new`](Self::new), reading `token_endpoint` from the issuer's discovery document.
    pub fn from_discovery(
        http: Client,
        discovery: &DiscoveryDocument,
        client_id: impl Into<String>,
        client_secret: ClientSecret,
        resource: impl Into<String>,
    ) -> Self {
        Self::new(
            http,
            discovery.token_endpoint.clone(),
            client_id,
            client_secret,
            resource,
        )
    }

    /// Narrow every token to some of the granted permissions (space-delimited). Without it the
    /// token carries every permission the client is granted on the API.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        let scope = scope.into();
        self.tokens = self.tokens.with_scope(scope.clone());
        self.scope = Some(scope);
        self
    }

    /// The audience of the API the tokens are for.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The machine client the tokens are requested as.
    pub fn client_id(&self) -> &str {
        self.tokens.client_id()
    }

    /// A valid access token for the API: the cached one while it is fresh, a new one otherwise.
    ///
    /// # Errors
    /// See the type's documentation; network and parse errors otherwise.
    pub async fn access_token(&self) -> LoginFlowResult<String> {
        self.tokens.access_token().await
    }

    /// The `Authorization` header value for a request to the API: `Bearer <token>`.
    ///
    /// # Errors
    /// Same as [`access_token`](Self::access_token).
    pub async fn authorization_header(&self) -> LoginFlowResult<String> {
        Ok(format!("Bearer {}", self.access_token().await?))
    }

    /// Drop the cached token, so the next call fetches a new one.
    pub async fn invalidate(&self) {
        self.tokens.invalidate().await;
    }

    /// Drop the cached token only if it is still `rejected` (the API answered `401` to it): a
    /// concurrent caller may already have replaced it with a fresh one.
    pub async fn invalidate_if_current(&self, rejected: &str) {
        self.tokens.invalidate_if_current(rejected).await;
    }
}

impl fmt::Debug for MachineTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachineTokens")
            .field("client_id", &self.tokens.client_id())
            .field("resource", &self.resource)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
