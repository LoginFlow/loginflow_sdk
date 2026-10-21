//! Machine-to-machine user management (`/v1/service/users`).
//!
//! A confidential OAuth client holding the `client_credentials` grant and the `users:manage`
//! scope manages the users of its own company and application. The company and application are
//! never sent: the server takes them from the token, so this client cannot reach another
//! tenant's users.

use std::fmt;

use crate::config::LoginFlowConfig;
use crate::discovery::DiscoveryDocument;
use crate::error::LoginFlowResult;
use crate::http::urlencoded;
use crate::models::{
    ConfirmServiceUserEmailChangeRequest, CreateServiceUserRequest, EmailChangeRequested,
    ServiceUser, ServiceUserDeleted, ServiceUserEmailChangeRequest, SetServiceUserActiveRequest,
    USERS_MANAGE_SCOPE,
};
use crate::service_door::ServiceDoor;

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
    door: ServiceDoor,
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
        let door = ServiceDoor::new(
            config,
            client_id.into(),
            client_secret.into(),
            USERS_MANAGE_SCOPE,
        )?;
        Ok(Self { door })
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
        let door = ServiceDoor::from_discovery(
            config,
            discovery,
            client_id.into(),
            client_secret.into(),
            USERS_MANAGE_SCOPE,
        )?;
        Ok(Self { door })
    }

    /// Drop the cached access token; the next call fetches a new one.
    pub async fn invalidate_token(&self) {
        self.door.invalidate_token().await;
    }

    /// `POST /v1/service/users`: create a user in the token's company and application.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] when the email is already registered in this
    /// application; [`crate::LoginFlowError::Validation`] for an invalid email or role.
    pub async fn create(&self, request: CreateServiceUserRequest) -> LoginFlowResult<ServiceUser> {
        let url = self.door.url("service/users");
        self.door
            .send_for_data("Create service user", |token| {
                self.door
                    .http()
                    .post(&url)
                    .bearer_auth(token)
                    .json(&request)
            })
            .await
    }

    /// `GET /v1/service/users`: every user of the token's company and application.
    pub async fn list(&self) -> LoginFlowResult<Vec<ServiceUser>> {
        let url = self.door.url("service/users");
        self.door
            .send_for_data("List service users", |token| {
                self.door.http().get(&url).bearer_auth(token)
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
        self.door
            .send_for_data("Get service user", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `PATCH /v1/service/users/{id}`: activate or deactivate. Deactivating revokes the user's
    /// sessions.
    pub async fn set_active(&self, id: &str, is_active: bool) -> LoginFlowResult<ServiceUser> {
        let url = self.user_url(id, "");
        let body = SetServiceUserActiveRequest { is_active };
        self.door
            .send_for_data("Set service user active", |token| {
                self.door.http().patch(&url).bearer_auth(token).json(&body)
            })
            .await
    }

    /// `DELETE /v1/service/users/{id}`: permanently delete the person's membership in this
    /// application (and their profile when it was their last account). Their sessions in this
    /// application end.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] when other data depends on the membership (nothing is
    /// deleted); [`crate::LoginFlowError::NotFound`] when `id` is not a user of this company and
    /// application, or was already deleted.
    pub async fn delete(&self, id: &str) -> LoginFlowResult<ServiceUserDeleted> {
        let url = self.user_url(id, "");
        self.door
            .send_for_data("Delete service user", |token| {
                self.door.http().delete(&url).bearer_auth(token)
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
        self.door
            .send_for_data("Request service user email change", |token| {
                self.door.http().post(&url).bearer_auth(token).json(&body)
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
        self.door
            .send_for_data("Confirm service user email change", |token| {
                self.door.http().post(&url).bearer_auth(token).json(&body)
            })
            .await
    }

    fn user_url(&self, id: &str, suffix: &str) -> String {
        self.door
            .url(&format!("service/users/{}{suffix}", urlencoded(id)))
    }
}

impl fmt::Debug for ServiceUsersClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceUsersClient")
            .field("base_url", &self.door.config().base_url)
            .field("api_version", &self.door.config().api_version)
            .finish()
    }
}
