//! Machine-to-machine user management (`/v1/service/users`).
//!
//! A confidential OAuth client holding the `client_credentials` grant and the
//! `loginflow.users.read` (the `GET` routes) and `loginflow.users.write` (every other route)
//! permissions manages the users of its own company and application. The company and application are
//! never sent: the server takes them from the token, so this client cannot reach another
//! tenant's users.

use crate::error::LoginFlowResult;
use crate::http::urlencoded;
use crate::models::{
    CreateServiceUserRequest, ServiceUser, ServiceUserDeleted, SetServiceUserActiveRequest,
    USERS_READ_SCOPE, USERS_WRITE_SCOPE,
};
use crate::service_door::{ServiceDoor, service_door_client};

/// Client for `/v1/service/users`, authenticated with a cached `client_credentials` token
/// requested with scope `loginflow.users.read loginflow.users.write`. A user's permissions are not part of the
/// account: grant roles with [`crate::MembersClient`].
///
/// When the API rejects the access token (`401` with envelope code `UNAUTHORIZED`, or no
/// envelope: the cached token was revoked, or the client's scopes changed before it expired) the
/// token is dropped and the request is retried exactly once with a fresh one; a second `401` is
/// returned as [`crate::LoginFlowError::Authentication`]. A `401` with any other envelope code
/// is about the request itself, and is returned at once, never resent.
///
/// Cloning is cheap: clones share the HTTP connection pool and the cached token.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{
///     CreateServiceUserRequest, LoginFlowConfig, LoginFlowResult, ServiceUsersClient,
/// };
///
/// async fn onboard(config: LoginFlowConfig) -> LoginFlowResult<String> {
///     let users = ServiceUsersClient::new(config, "billing-service", "client-secret")?;
///     let user = users
///         .create(CreateServiceUserRequest {
///             email: "ana@example.com".into(),
///             first_name: Some("Ana".into()),
///             last_name: None,
///             send_invitation: true,
///         })
///         .await?;
///     Ok(user.id)
/// }
/// ```
#[derive(Clone)]
pub struct ServiceUsersClient {
    door: ServiceDoor,
}

service_door_client!(ServiceUsersClient, [USERS_READ_SCOPE, USERS_WRITE_SCOPE]);

impl ServiceUsersClient {
    /// `POST /v1/service/users`: create a user in the token's company and application.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] when the email is already registered in this
    /// application; [`crate::LoginFlowError::Validation`] for an invalid email.
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

    /// `GET /v1/service/users`: every user of the token's company and application, active and
    /// inactive, in no particular order (no pagination).
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

    /// `PATCH /v1/service/users/{id}`: activate or deactivate the membership in this
    /// application. Deactivating revokes the user's sessions in it (access tokens already issued
    /// stop within 30 s).
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when `id` is not a user of this company and
    /// application; [`crate::LoginFlowError::Authorization`] when the person is out of the key's
    /// reach: `code` `principal_outranks_client` (they hold a role the key may not grant), or a
    /// LoginFlow panel principal.
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
    /// application, or was already deleted; [`crate::LoginFlowError::Authorization`] for a
    /// LoginFlow panel principal (managed only from the panel).
    pub async fn delete(&self, id: &str) -> LoginFlowResult<ServiceUserDeleted> {
        let url = self.user_url(id, "");
        self.door
            .send_for_data("Delete service user", |token| {
                self.door.http().delete(&url).bearer_auth(token)
            })
            .await
    }

    fn user_url(&self, id: &str, suffix: &str) -> String {
        self.door
            .url(&format!("service/users/{}{suffix}", urlencoded(id)))
    }
}
