//! Machine-to-machine user management (`/v1/service/users`).
//!
//! A confidential OAuth client holding the `client_credentials` grant and the `users:manage`
//! scope manages the users of its own company and application. The company and application are
//! never sent: the server takes them from the token, so this client cannot reach another
//! tenant's users.

use std::fmt;

use log::warn;
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;

use crate::config::LoginFlowConfig;
use crate::discovery::DiscoveryDocument;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{build_http_client, data_of, error_from_body, read_error_body, urlencoded};
use crate::models::{
    ConfirmServiceUserEmailChangeRequest, CreateServiceUserRequest, EmailChangeRequested,
    ServiceUser, ServiceUserEmailChangeRequest, SetServiceUserActiveRequest, USERS_MANAGE_SCOPE,
};
use crate::oauth2::ClientCredentialsClient;

/// Envelope `error.code` of a `401` caused by the access token itself (expired, revoked,
/// insufficient scope). A `401` with another code (e.g. `INVALID_CODE` for a wrong email-change
/// code) is about the request, and is never retried.
const TOKEN_REJECTED_CODE: &str = "UNAUTHORIZED";

/// Client for `/v1/service/users`, authenticated with a cached `client_credentials` token
/// requested with scope `users:manage`.
///
/// When the API rejects the access token (`401` with envelope code `UNAUTHORIZED`, or no
/// envelope: the cached token was revoked, or the client's scopes changed before it expired) the
/// token is dropped and the request is retried exactly once with a fresh one; a second `401` is
/// returned as [`crate::LoginFlowError::Authentication`]. A `401` about the request itself (a
/// wrong email-change code, `INVALID_CODE`) is returned at once, never resent.
///
/// Cloning is cheap: clones share the HTTP connection pool and the cached token.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{
///     CreateServiceUserRequest, LoginFlowConfig, LoginFlowResult, ServiceUserRole,
///     ServiceUsersClient,
/// };
///
/// async fn onboard(config: LoginFlowConfig) -> LoginFlowResult<String> {
///     let users = ServiceUsersClient::new(config, "billing-service", "client-secret")?;
///     let user = users
///         .create(CreateServiceUserRequest {
///             email: "ana@example.com".into(),
///             first_name: Some("Ana".into()),
///             last_name: None,
///             role: ServiceUserRole::User,
///         })
///         .await?;
///     Ok(user.id)
/// }
/// ```
#[derive(Clone)]
pub struct ServiceUsersClient {
    http: Client,
    config: LoginFlowConfig,
    tokens: ClientCredentialsClient,
}

impl ServiceUsersClient {
    /// Build the client against `{base_url}/oauth2/token` and the versioned API of `config`.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Config`] when `config` is invalid (see
    /// [`LoginFlowConfig::validate`]) or the HTTP client cannot be built.
    pub fn new(
        config: LoginFlowConfig,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> LoginFlowResult<Self> {
        let token_url = format!("{}/oauth2/token", config.base_url.trim_end_matches('/'));
        Self::build(config, token_url, client_id.into(), client_secret.into())
    }

    /// Same as [`new`](Self::new), reading `token_endpoint` from a discovery document instead
    /// of a hardcoded path.
    ///
    /// # Errors
    /// Same as [`new`](Self::new).
    pub fn from_discovery(
        config: LoginFlowConfig,
        discovery: &DiscoveryDocument,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> LoginFlowResult<Self> {
        Self::build(
            config,
            discovery.token_endpoint.clone(),
            client_id.into(),
            client_secret.into(),
        )
    }

    fn build(
        config: LoginFlowConfig,
        token_url: String,
        client_id: String,
        client_secret: String,
    ) -> LoginFlowResult<Self> {
        config.validate()?;
        let http = build_http_client(&config)?;
        let tokens =
            ClientCredentialsClient::new(http.clone(), token_url, client_id, client_secret)
                .with_scope(USERS_MANAGE_SCOPE);
        Ok(Self {
            http,
            config,
            tokens,
        })
    }

    /// Drop the cached access token; the next call fetches a new one.
    pub async fn invalidate_token(&self) {
        self.tokens.invalidate().await;
    }

    /// `POST /v1/service/users`: create a user in the token's company and application.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] when the email is already registered in this
    /// application; [`crate::LoginFlowError::Validation`] for an invalid email or role.
    pub async fn create(&self, request: CreateServiceUserRequest) -> LoginFlowResult<ServiceUser> {
        let url = self.config.build_url("service/users");
        self.send("Create service user", |token| {
            self.http.post(&url).bearer_auth(token).json(&request)
        })
        .await
    }

    /// `GET /v1/service/users`: every user of the token's company and application.
    pub async fn list(&self) -> LoginFlowResult<Vec<ServiceUser>> {
        let url = self.config.build_url("service/users");
        self.send("List service users", |token| {
            self.http.get(&url).bearer_auth(token)
        })
        .await
    }

    /// `GET /v1/service/users/{id}`.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when `id` is not a user of this company and
    /// application.
    pub async fn get(&self, id: &str) -> LoginFlowResult<ServiceUser> {
        let url = self.user_url(id, "");
        self.send("Get service user", |token| {
            self.http.get(&url).bearer_auth(token)
        })
        .await
    }

    /// `PATCH /v1/service/users/{id}`: activate or deactivate. Deactivating revokes the user's
    /// sessions.
    pub async fn set_active(&self, id: &str, is_active: bool) -> LoginFlowResult<ServiceUser> {
        let url = self.user_url(id, "");
        let body = SetServiceUserActiveRequest { is_active };
        self.send("Set service user active", |token| {
            self.http.patch(&url).bearer_auth(token).json(&body)
        })
        .await
    }

    /// `POST /v1/service/users/{id}/email-change`: email a confirmation code to `new_email`.
    pub async fn request_email_change(
        &self,
        id: &str,
        new_email: &str,
    ) -> LoginFlowResult<EmailChangeRequested> {
        let url = self.user_url(id, "/email-change");
        let body = ServiceUserEmailChangeRequest {
            new_email: new_email.to_string(),
        };
        self.send("Request service user email change", |token| {
            self.http.post(&url).bearer_auth(token).json(&body)
        })
        .await
    }

    /// `POST /v1/service/users/{id}/email-change/confirm`: apply the email change with the code
    /// sent to the new address.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] with `code: Some("email_shared")` when the profile
    /// has memberships in other companies, or when the new email belongs to another profile;
    /// [`crate::LoginFlowError::Authentication`] / [`crate::LoginFlowError::Validation`] for a
    /// wrong or expired code.
    pub async fn confirm_email_change(&self, id: &str, code: &str) -> LoginFlowResult<ServiceUser> {
        let url = self.user_url(id, "/email-change/confirm");
        let body = ConfirmServiceUserEmailChangeRequest {
            code: code.to_string(),
        };
        self.send("Confirm service user email change", |token| {
            self.http.post(&url).bearer_auth(token).json(&body)
        })
        .await
    }

    fn user_url(&self, id: &str, suffix: &str) -> String {
        self.config
            .build_url(&format!("service/users/{}{suffix}", urlencoded(id)))
    }

    /// Send `request(token)` with the cached token; when the API rejects that token, drop it and
    /// send the request once more with a fresh one. Returns the envelope's `data`.
    async fn send<T: DeserializeOwned>(
        &self,
        context: &str,
        request: impl Fn(&str) -> RequestBuilder,
    ) -> LoginFlowResult<T> {
        let token = self.tokens.access_token().await?;
        let response = request(&token).send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return data_of(response, context).await;
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
        data_of(request(&fresh).send().await?, context).await
    }
}

/// Whether a `401` body says the access token was rejected (rather than the request).
fn is_token_rejection(body: &str) -> bool {
    let (code, _) = LoginFlowError::extract_error_fields(body);
    code.is_none_or(|code| code == TOKEN_REJECTED_CODE)
}

impl fmt::Debug for ServiceUsersClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceUsersClient")
            .field("base_url", &self.config.base_url)
            .field("api_version", &self.config.api_version)
            .finish()
    }
}
