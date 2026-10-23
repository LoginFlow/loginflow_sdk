//! Members of the machine door (`/v1/service/members`): a role of the application granted to a
//! person or an access-code subject in one organization of the caller's company and application.
//! A key grants and revokes ONLY the roles listed for it on the LoginFlow panel
//! ([`MembersClient::grantable_roles`]); a new key has none.

use crate::error::LoginFlowResult;
use crate::http::{urlencoded, with_query};
use crate::models::{
    ASSIGNMENTS_READ_SCOPE, ASSIGNMENTS_WRITE_SCOPE, GrantMember, GrantableRole, MemberAssignment,
    MemberFilter, Page,
};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the members collection.
const MEMBERS_PATH: &str = "service/members";

/// Client for `/v1/service/members`, authenticated with a cached `client_credentials` token
/// requested with scope `loginflow.assignments.read loginflow.assignments.write`. Same token handling as
/// [`crate::ServiceUsersClient`].
///
/// Meant for provisioning the system starts itself (drivers by access code, for example). A
/// grant a PERSON starts goes through `/v1/app/members` with that person's own token, from the
/// product's frontend (`loginflow_auth`), never through the backend's key.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{GrantMember, LoginFlowConfig, LoginFlowResult, MembersClient, Principal};
///
/// async fn make_driver(config: LoginFlowConfig, org_id: &str, driver: &str) -> LoginFlowResult<()> {
///     let members = MembersClient::new(config, "rutafacil-api", "client-secret")?;
///     members
///         .grant(&GrantMember {
///             organization_id: org_id.into(),
///             role_key: "driver".into(),
///             principal: Principal::AccessSubject { external_subject: format!("driver:{driver}") },
///             expires_at: None,
///         })
///         .await?;
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct MembersClient {
    door: ServiceDoor,
}

service_door_client!(
    MembersClient,
    [ASSIGNMENTS_READ_SCOPE, ASSIGNMENTS_WRITE_SCOPE]
);

impl MembersClient {
    /// `GET /v1/service/members/grantable-roles`: the roles this key may grant (empty for a key
    /// nobody configured).
    pub async fn grantable_roles(&self) -> LoginFlowResult<Vec<GrantableRole>> {
        let url = self.door.url(&format!("{MEMBERS_PATH}/grantable-roles"));
        self.door
            .send_for_data("List grantable roles", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `GET /v1/service/members`: the assignments matching every filter set.
    pub async fn list(&self, filter: &MemberFilter) -> LoginFlowResult<Page<MemberAssignment>> {
        let url = with_query(
            self.door.url(MEMBERS_PATH),
            &[
                ("organization_id", filter.organization_id.clone()),
                ("principal_id", filter.principal_id.clone()),
                ("external_subject", filter.external_subject.clone()),
                ("role_key", filter.role_key.clone()),
            ],
        );
        self.door
            .send_for_data("List members", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `POST /v1/service/members`: grant the role. An identical assignment that already exists
    /// is answered as it is. The permissions reach the principal's tokens at their next
    /// refresh.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Authorization`] with `code` `role_not_grantable` when the role
    /// is not in this key's list; [`crate::LoginFlowError::NotFound`] when the organization, the
    /// role or the principal is not of this company and application, or the person has no
    /// active membership in it; [`crate::LoginFlowError::Validation`] for a past `expires_at` or
    /// a role not assignable in that kind of organization.
    pub async fn grant(&self, grant: &GrantMember) -> LoginFlowResult<MemberAssignment> {
        let url = self.door.url(MEMBERS_PATH);
        self.door
            .send_for_data("Grant role", |token| {
                self.door.http().post(&url).bearer_auth(token).json(grant)
            })
            .await
    }

    /// `DELETE /v1/service/members/assignments/{id}` (`204`). The principal's sessions whose
    /// sign-in gate no longer passes are revoked.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when `assignment_id` is not an assignment of this
    /// company and application; [`crate::LoginFlowError::Authorization`] with `code`
    /// `role_not_grantable` when its role is not in this key's list (a key never revokes what it
    /// could not grant).
    pub async fn revoke(&self, assignment_id: &str) -> LoginFlowResult<()> {
        let url = self.door.url(&format!(
            "{MEMBERS_PATH}/assignments/{}",
            urlencoded(assignment_id)
        ));
        self.door
            .send_for_unit("Revoke role", |token| {
                self.door.http().delete(&url).bearer_auth(token)
            })
            .await
    }
}
