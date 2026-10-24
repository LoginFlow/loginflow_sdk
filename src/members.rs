//! Members of the machine door (`/v1/service/members`): a role of the application granted to a
//! person or an access-code subject in one organization of the caller's company and application.
//! A key never grants on its own: every grant and revocation is made FOR a person, named by the
//! access token that person sent to the product (`actor_token`). It passes only when the role is
//! listed for the key on the LoginFlow panel ([`MembersClient::grantable_roles`], its ceiling; a
//! new key has none) AND the person's own role lists it in "Can grant" there.

use crate::error::LoginFlowResult;
use crate::http::{urlencoded, with_query};
use crate::models::{
    ASSIGNMENTS_READ_SCOPE, ASSIGNMENTS_WRITE_SCOPE, GrantMember, GrantableRole, MemberAssignment,
    MemberFilter, Page,
};
use crate::service_door::{ServiceDoor, service_door_client};
use serde::Serialize;

/// Versioned path of the members collection.
const MEMBERS_PATH: &str = "service/members";

/// `POST /v1/service/members` body: the grant and the person it is made for.
#[derive(Serialize)]
struct GrantBody<'a> {
    #[serde(flatten)]
    grant: &'a GrantMember,
    actor_token: &'a str,
}

/// `DELETE /v1/service/members/assignments/{id}` body: the person the revocation is made for.
#[derive(Serialize)]
struct RevokeBody<'a> {
    actor_token: &'a str,
}

/// Client for `/v1/service/members`, authenticated with a cached `client_credentials` token
/// requested with scope `loginflow.assignments.read loginflow.assignments.write`. Same token handling as
/// [`crate::ServiceUsersClient`].
///
/// Meant for the grants a person makes through the product (a client admin creating a driver,
/// an owner creating a recorder): the product backend forwards the caller's access token — the
/// same bearer its API verified for that request, untouched; no DPoP proof is needed for it. A
/// person managing members with no product in between uses `/v1/app/members` from the frontend
/// (`loginflow_auth`) with their own token.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{GrantMember, LoginFlowConfig, LoginFlowResult, MembersClient, Principal};
///
/// /// `caller_token`: the access token the client admin's request carried.
/// async fn make_driver(
///     config: LoginFlowConfig,
///     org_id: &str,
///     driver: &str,
///     caller_token: &str,
/// ) -> LoginFlowResult<()> {
///     let members = MembersClient::new(config, "rutafacil-api", "client-secret")?;
///     members
///         .grant(
///             &GrantMember {
///                 organization_id: org_id.into(),
///                 role_key: "driver".into(),
///                 principal: Principal::AccessSubject { external_subject: format!("driver:{driver}") },
///                 expires_at: None,
///             },
///             caller_token,
///         )
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
    /// `GET /v1/service/members/grantable-roles`: the roles listed for this key — its ceiling,
    /// each with who holds it (empty for a key nobody configured). A grant also needs a person who
    /// may grant the role.
    pub async fn grantable_roles(&self) -> LoginFlowResult<Vec<GrantableRole>> {
        let url = self.door.url(&format!("{MEMBERS_PATH}/grantable-roles"));
        self.door
            .send_for_data("List grantable roles", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `GET /v1/service/members`: the assignments matching every filter set (all of them, in one
    /// page: `total` is the number of `items`).
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Validation`] (`code` `BAD_REQUEST`) for an `organization_id`
    /// that is not an organization id.
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

    /// `POST /v1/service/members`: grant the role for the person of `actor_token` (the access
    /// token that person's request to the product carried). An identical assignment that already
    /// exists is answered as it is. The permissions reach the principal's tokens at their next
    /// refresh.
    ///
    /// # Errors
    /// Each refusal carries the server's `code`:
    /// - [`crate::LoginFlowError::Validation`] `actor_token_required` (an empty token),
    ///   `role_not_held_by_principal` (a people role to an access-code subject, or the reverse),
    ///   `expires_at_in_past` or `role_not_assignable_here`;
    /// - [`crate::LoginFlowError::Authentication`] `invalid_actor_token`: the person's token is
    ///   expired, revoked, of another application or for LoginFlow itself, or not a person's;
    /// - [`crate::LoginFlowError::Authorization`] `key_role_not_grantable` when the role is not in
    ///   this key's list; `role_not_grantable`, `organization_out_of_reach`,
    ///   `self_assignment_forbidden` or `privilege_exceeds_grantor` when the PERSON may not grant
    ///   it there;
    /// - [`crate::LoginFlowError::NotFound`] `organization_not_found`, `role_not_found` or
    ///   `member_not_found` (the principal is not of this company and application, or the person
    ///   has no active membership in it);
    /// - [`crate::LoginFlowError::Conflict`] `system_application` for a role LoginFlow itself
    ///   manages.
    pub async fn grant(
        &self,
        grant: &GrantMember,
        actor_token: &str,
    ) -> LoginFlowResult<MemberAssignment> {
        let url = self.door.url(MEMBERS_PATH);
        let body = GrantBody { grant, actor_token };
        self.door
            .send_for_data("Grant role", |token| {
                self.door.http().post(&url).bearer_auth(token).json(&body)
            })
            .await
    }

    /// `DELETE /v1/service/members/assignments/{id}` (`204`) for the person of `actor_token`.
    /// The principal's sessions whose sign-in gate no longer passes are revoked.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] with `code` `assignment_not_found` when
    /// `assignment_id` is not an assignment of this company and application;
    /// [`crate::LoginFlowError::Authorization`] with `code` `key_role_not_grantable` when its
    /// role is not in this key's list, `role_not_grantable` / `organization_out_of_reach` /
    /// `self_assignment_forbidden` when the person could not grant it there (nobody revokes what
    /// they could not grant); `actor_token_required` and `invalid_actor_token` as in
    /// [`Self::grant`]. An access token already issued keeps the role's permissions until it
    /// expires.
    pub async fn revoke(&self, assignment_id: &str, actor_token: &str) -> LoginFlowResult<()> {
        let url = self.door.url(&format!(
            "{MEMBERS_PATH}/assignments/{}",
            urlencoded(assignment_id)
        ));
        self.door
            .send_for_unit("Revoke role", |token| {
                self.door
                    .http()
                    .delete(&url)
                    .bearer_auth(token)
                    .json(&RevokeBody { actor_token })
            })
            .await
    }
}
