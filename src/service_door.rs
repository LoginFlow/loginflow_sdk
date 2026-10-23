//! The machine door shared by the `/v1/service/*` clients ([`crate::ServiceUsersClient`],
//! [`crate::MembersClient`], [`crate::OrganizationsClient`], [`crate::CatalogClient`],
//! [`crate::AccessCodesClient`]): a cached `client_credentials` token requested with the
//! exact permissions of the client's routes, and exactly one retry with a fresh token when the
//! API rejects the cached one.

use log::warn;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;

use crate::config::LoginFlowConfig;
use crate::discovery::DiscoveryDocument;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{build_http_client, data_of, error_from_body, expect_success, read_error_body};
use crate::oauth2::ClientCredentialsClient;

/// Envelope `error.code` of a `401` caused by the access token itself (expired, revoked,
/// insufficient scope). A `401` with another code (e.g. `INVALID_CODE` for a wrong email-change
/// code) is about the request, and is never retried.
const TOKEN_REJECTED_CODE: &str = "UNAUTHORIZED";

/// HTTP client, configuration and scoped token cache of one service client. Cloning is cheap:
/// clones share the HTTP connection pool and the cached token.
#[derive(Clone)]
pub(crate) struct ServiceDoor {
    http: Client,
    config: LoginFlowConfig,
    tokens: ClientCredentialsClient,
}

impl ServiceDoor {
    /// Door against `{base_url}/oauth2/token`.
    pub(crate) fn new(
        config: LoginFlowConfig,
        client_id: String,
        client_secret: String,
        scopes: &[&str],
    ) -> LoginFlowResult<Self> {
        let token_url = format!("{}/oauth2/token", config.base_url.trim_end_matches('/'));
        Self::build(config, token_url, client_id, client_secret, scopes)
    }

    /// Door against the discovery document's `token_endpoint`.
    pub(crate) fn from_discovery(
        config: LoginFlowConfig,
        discovery: &DiscoveryDocument,
        client_id: String,
        client_secret: String,
        scopes: &[&str],
    ) -> LoginFlowResult<Self> {
        let token_url = discovery.token_endpoint.clone();
        Self::build(config, token_url, client_id, client_secret, scopes)
    }

    fn build(
        config: LoginFlowConfig,
        token_url: String,
        client_id: String,
        client_secret: String,
        scopes: &[&str],
    ) -> LoginFlowResult<Self> {
        config.validate()?;
        let http = build_http_client(&config)?;
        let tokens =
            ClientCredentialsClient::new(http.clone(), token_url, client_id, client_secret)
                .with_scope(scopes.join(" "));
        Ok(Self {
            http,
            config,
            tokens,
        })
    }

    pub(crate) fn http(&self) -> &Client {
        &self.http
    }

    pub(crate) fn config(&self) -> &LoginFlowConfig {
        &self.config
    }

    /// Versioned API URL of `path` (e.g. `service/users`).
    pub(crate) fn url(&self, path: &str) -> String {
        self.config.build_url(path)
    }

    /// Drop the cached access token; the next call fetches a new one.
    pub(crate) async fn invalidate_token(&self) {
        self.tokens.invalidate().await;
    }

    /// Send `request(token)` and return the envelope's `data`.
    pub(crate) async fn send_for_data<T: DeserializeOwned>(
        &self,
        context: &str,
        request: impl Fn(&str) -> RequestBuilder,
    ) -> LoginFlowResult<T> {
        data_of(self.send_authorized(context, request).await?, context).await
    }

    /// Send `request(token)` and only check that it succeeded (e.g. a `204`).
    pub(crate) async fn send_for_unit(
        &self,
        context: &str,
        request: impl Fn(&str) -> RequestBuilder,
    ) -> LoginFlowResult<()> {
        let response = self.send_authorized(context, request).await?;
        expect_success(response, context).await.map(|_| ())
    }

    /// Send `request(token)` with the cached token; when the API rejects that token, drop it and
    /// send the request once more with a fresh one. A `401` about the request itself is returned
    /// as an error at once.
    async fn send_authorized(
        &self,
        context: &str,
        request: impl Fn(&str) -> RequestBuilder,
    ) -> LoginFlowResult<Response> {
        let token = self.tokens.access_token().await?;
        let response = request(&token).send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        let body = read_error_body(response).await;
        if !is_token_rejection(&body) {
            return Err(error_from_body(
                StatusCode::UNAUTHORIZED,
                &body,
                None,
                context,
            ));
        }
        warn!("{context}: access token rejected, retrying once with a fresh token");
        self.tokens.invalidate_if_current(&token).await;
        let fresh = self.tokens.access_token().await?;
        Ok(request(&fresh).send().await?)
    }
}

/// Whether a `401` body says the access token was rejected (rather than the request).
fn is_token_rejection(body: &str) -> bool {
    let (code, _) = LoginFlowError::extract_error_fields(body);
    code.is_none_or(|code| code == TOKEN_REJECTED_CODE)
}

/// The constructors, `invalidate_token` and the `Debug` impl every `/v1/service/*` client shares:
/// a struct with one field `door: ServiceDoor`, whose token is requested with every permission of
/// `[$scope, ...]` (space-delimited, RFC 6749 §3.3).
macro_rules! service_door_client {
    ($client:ident, [$($scope:expr),+ $(,)?]) => {
        impl $client {
            /// Build the client against `{base_url}/oauth2/token` and the versioned API of
            /// `config`.
            ///
            /// # Errors
            /// [`crate::LoginFlowError::Config`] when `config` is invalid (see
            /// [`crate::LoginFlowConfig::validate`]) or the HTTP client cannot be built.
            pub fn new(
                config: $crate::config::LoginFlowConfig,
                client_id: impl Into<String>,
                client_secret: impl Into<String>,
            ) -> $crate::error::LoginFlowResult<Self> {
                let door = $crate::service_door::ServiceDoor::new(
                    config,
                    client_id.into(),
                    client_secret.into(),
                    &[$($scope),+],
                )?;
                Ok(Self { door })
            }

            /// Same as [`new`](Self::new), reading `token_endpoint` from a discovery document
            /// instead of a hardcoded path.
            ///
            /// # Errors
            /// Same as [`new`](Self::new).
            pub fn from_discovery(
                config: $crate::config::LoginFlowConfig,
                discovery: &$crate::discovery::DiscoveryDocument,
                client_id: impl Into<String>,
                client_secret: impl Into<String>,
            ) -> $crate::error::LoginFlowResult<Self> {
                let door = $crate::service_door::ServiceDoor::from_discovery(
                    config,
                    discovery,
                    client_id.into(),
                    client_secret.into(),
                    &[$($scope),+],
                )?;
                Ok(Self { door })
            }

            /// Drop the cached access token; the next call fetches a new one.
            pub async fn invalidate_token(&self) {
                self.door.invalidate_token().await;
            }
        }

        impl ::std::fmt::Debug for $client {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.debug_struct(stringify!($client))
                    .field("base_url", &self.door.config().base_url)
                    .field("api_version", &self.door.config().api_version)
                    .finish()
            }
        }
    };
}

pub(crate) use service_door_client;
