//! Founding an organization (`POST /v1/service/organizations/founded`): a signed-in person who
//! belongs to no organization yet creates one of the application (e.g. "create my company" in a
//! self-service product) and receives the application's founder role there, in one step.
//!
//! It is the only way a person acquires a role for themselves: the server creates the
//! organization and grants the founder role in one transaction, never grants anything on an
//! organization that already exists, and caps foundings per person.

use serde::Serialize;
use thiserror::Error;

use crate::error::LoginFlowError;
use crate::models::{
    ASSIGNMENTS_WRITE_SCOPE, FOUNDER_ROLE_NOT_CONFIGURED_CODE, FOUNDING_RATE_LIMITED_CODE,
    FoundOrganizationRequest, FoundedOrganization, KEY_ROLE_NOT_GRANTABLE_CODE,
    ORGANIZATION_EXISTS_CODE, ORGANIZATIONS_WRITE_SCOPE,
};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the founding route.
const FOUNDED_PATH: &str = "service/organizations/founded";

/// `POST /v1/service/organizations/founded` body: what to found and the person it is founded
/// for.
#[derive(Serialize)]
struct FoundBody<'a> {
    #[serde(flatten)]
    request: &'a FoundOrganizationRequest,
    actor_token: &'a str,
}

/// Why a founding was refused. The four refusals a product answers differently are typed; any
/// other one keeps the server's code in [`LoginFlowError`].
#[derive(Debug, Clone, Error)]
pub enum FoundingError {
    /// `409 organization_exists`: an organization with that `external_id` exists and the person
    /// does not hold the founder role there. Nothing was granted; pick another `external_id`.
    #[error("an organization with that external id already exists")]
    OrganizationExists,
    /// `409 founder_role_not_configured`: the application has no founder role (set it on the
    /// LoginFlow panel).
    #[error("the application has no founder role configured")]
    FounderRoleNotConfigured,
    /// `429 founding_rate_limited`: at most 5 foundings per person and application in a rolling
    /// 24 hours.
    #[error("too many foundings by this person")]
    RateLimited {
        /// Seconds to wait before founding again, from the `Retry-After` header.
        retry_after_secs: Option<u64>,
    },
    /// `403 key_role_not_grantable`: the founder role is not among the roles listed for this key
    /// on the LoginFlow panel.
    #[error("the founder role is not grantable by this key")]
    KeyRoleNotGrantable,
    /// Any other failure, with the server's `code` where it sent one: `Validation`
    /// `actor_token_required` / `VALIDATION_ERROR`, `Authentication` `invalid_actor_token`,
    /// `Authorization` `permission_denied` (the key lacks `loginflow.organizations.write` or
    /// `loginflow.assignments.write`), `NotFound` `member_not_found`, a network failure, ...
    #[error(transparent)]
    LoginFlow(LoginFlowError),
}

impl From<LoginFlowError> for FoundingError {
    /// Type the refusals of the founding route by their `error.code`; anything else stays a
    /// [`LoginFlowError`].
    fn from(error: LoginFlowError) -> Self {
        match &error {
            LoginFlowError::Conflict {
                code: Some(code), ..
            } if code == ORGANIZATION_EXISTS_CODE => FoundingError::OrganizationExists,
            LoginFlowError::Conflict {
                code: Some(code), ..
            } if code == FOUNDER_ROLE_NOT_CONFIGURED_CODE => {
                FoundingError::FounderRoleNotConfigured
            }
            LoginFlowError::RateLimit {
                code: Some(code),
                retry_after_secs,
                ..
            } if code == FOUNDING_RATE_LIMITED_CODE => FoundingError::RateLimited {
                retry_after_secs: *retry_after_secs,
            },
            LoginFlowError::Authorization {
                code: Some(code), ..
            } if code == KEY_ROLE_NOT_GRANTABLE_CODE => FoundingError::KeyRoleNotGrantable,
            _ => FoundingError::LoginFlow(error),
        }
    }
}

/// Client for `POST /v1/service/organizations/founded`, authenticated with a cached
/// `client_credentials` token requested with scope `loginflow.organizations.write
/// loginflow.assignments.write`: the route needs both, and the key must hold both. A separate
/// client so that [`crate::OrganizationsClient`] and [`crate::MembersClient`] keep requesting
/// only their own permissions (a key without `loginflow.assignments.write` still uses
/// `OrganizationsClient`). Same token handling as [`crate::ServiceUsersClient`].
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{
///     FoundOrganizationRequest, FoundingClient, FoundingError, LoginFlowConfig,
/// };
///
/// /// `person_token`: the access token of the signed-in person's request
/// /// (`loginflow_sdk::actix::SignedIn::access_token`).
/// async fn create_my_company(
///     config: LoginFlowConfig,
///     tenant_id: &str,
///     person_token: &str,
/// ) -> Result<String, FoundingError> {
///     let founding = FoundingClient::new(config, "turnosqr-api", "client-secret")?;
///     let founded = founding
///         .found(
///             &FoundOrganizationRequest {
///                 external_id: tenant_id.into(),
///                 name: "Barbería Central".into(),
///             },
///             person_token,
///         )
///         .await?;
///     Ok(founded.organization.id)
/// }
/// ```
#[derive(Clone)]
pub struct FoundingClient {
    door: ServiceDoor,
}

service_door_client!(
    FoundingClient,
    [ORGANIZATIONS_WRITE_SCOPE, ASSIGNMENTS_WRITE_SCOPE]
);

impl FoundingClient {
    /// `POST /v1/service/organizations/founded`: found the organization `request.external_id`
    /// for the person of `actor_token` (the access token that person's request to the product
    /// carried, forwarded untouched) and grant them the application's founder role there.
    /// `201` creates both ([`FoundedOrganization::created`] `true`); `200` answers a retry by
    /// the same founder (`created` `false`). An organization that exists otherwise is never
    /// touched.
    ///
    /// # Errors
    /// [`FoundingError::OrganizationExists`], [`FoundingError::FounderRoleNotConfigured`],
    /// [`FoundingError::RateLimited`] or [`FoundingError::KeyRoleNotGrantable`]; any other
    /// refusal is [`FoundingError::LoginFlow`] with the server's `code`:
    /// - `Validation` `actor_token_required`, or the `422` of an invalid `external_id` / `name`
    ///   (same rules as [`crate::OrganizationsClient::ensure`]);
    /// - `Authentication` `invalid_actor_token`: the person's token is expired, revoked, of
    ///   another application or company, or not a person's (an access-code subject's or a
    ///   `client_credentials` token);
    /// - `Authorization` `permission_denied`: the key lacks one of the two permissions;
    /// - `NotFound` `member_not_found`: the person has no active membership in the application.
    pub async fn found(
        &self,
        request: &FoundOrganizationRequest,
        actor_token: &str,
    ) -> Result<FoundedOrganization, FoundingError> {
        let url = self.door.url(FOUNDED_PATH);
        let body = FoundBody {
            request,
            actor_token,
        };
        let founded = self
            .door
            .send_for_data("Found organization", |token| {
                self.door.http().post(&url).bearer_auth(token).json(&body)
            })
            .await?;
        Ok(founded)
    }
}
