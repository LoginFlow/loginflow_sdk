//! Role assignments (`/v1/service/assignments`): a role of the application granted to a person
//! or an access-code subject in one organization of the caller's company and application.

use crate::error::LoginFlowResult;
use crate::http::{urlencoded, with_query};
use crate::models::{ASSIGNMENTS_WRITE_SCOPE, Assignment, AssignmentFilter, GrantAssignment, Page};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the assignment collection.
const ASSIGNMENTS_PATH: &str = "service/assignments";

/// Client for `/v1/service/assignments`, authenticated with a cached `client_credentials` token
/// requested with scope `loginflow.assignments.write`. Same token handling as
/// [`crate::ServiceUsersClient`].
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{
///     AssignmentsClient, GrantAssignment, LoginFlowConfig, LoginFlowResult, Principal,
/// };
///
/// async fn make_driver(config: LoginFlowConfig, org_id: &str, driver: &str) -> LoginFlowResult<()> {
///     let assignments = AssignmentsClient::new(config, "rutafacil-api", "client-secret")?;
///     assignments
///         .grant(GrantAssignment {
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
pub struct AssignmentsClient {
    door: ServiceDoor,
}

service_door_client!(AssignmentsClient, ASSIGNMENTS_WRITE_SCOPE);

impl AssignmentsClient {
    /// `POST /v1/service/assignments`: grant the role. An identical assignment that already
    /// exists is answered as it is. The permissions reach the principal's tokens at their next
    /// refresh.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when the organization, the role or the principal is
    /// not of this company and application; [`crate::LoginFlowError::Validation`] when the
    /// principal has no active membership in the application or `expires_at` is past.
    pub async fn grant(&self, request: GrantAssignment) -> LoginFlowResult<Assignment> {
        let url = self.door.url(ASSIGNMENTS_PATH);
        self.door
            .send_for_data("Grant role assignment", |token| {
                self.door
                    .http()
                    .post(&url)
                    .bearer_auth(token)
                    .json(&request)
            })
            .await
    }

    /// `DELETE /v1/service/assignments/{id}` (`204`). The principal's sessions whose sign-in
    /// gate no longer passes are revoked.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when `id` is not an assignment of this company and
    /// application.
    pub async fn revoke(&self, id: &str) -> LoginFlowResult<()> {
        let url = self
            .door
            .url(&format!("{ASSIGNMENTS_PATH}/{}", urlencoded(id)));
        self.door
            .send_for_unit("Revoke role assignment", |token| {
                self.door.http().delete(&url).bearer_auth(token)
            })
            .await
    }

    /// `GET /v1/service/assignments`: the assignments matching every filter set.
    pub async fn list(&self, filter: AssignmentFilter) -> LoginFlowResult<Page<Assignment>> {
        let url = with_query(
            self.door.url(ASSIGNMENTS_PATH),
            &[
                ("organization_id", filter.organization_id),
                ("principal_id", filter.principal_id),
                ("external_subject", filter.external_subject),
                ("role_key", filter.role_key),
            ],
        );
        self.door
            .send_for_data("List role assignments", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }
}
