//! Organizations of the caller's company and application (`/v1/service/organizations`).
//!
//! The product creates one organization per unit it grants roles in (a client company, a
//! school), keyed by its own id (`external_id`), and grants roles in it with
//! [`crate::MembersClient`]. The root organization stands for the whole application.

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{urlencoded, with_query};
use crate::models::{
    EnsureOrganizationRequest, ORGANIZATIONS_READ_SCOPE, ORGANIZATIONS_WRITE_SCOPE, Organization,
    OrganizationKind, Page, PageRequest,
};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the organization collection.
const ORGANIZATIONS_PATH: &str = "service/organizations";

/// Page size [`OrganizationsClient::root`] reads the listing with.
const ROOT_SCAN_PAGE: u32 = 100;

/// Client for `/v1/service/organizations`, authenticated with a cached `client_credentials`
/// token requested with scope `loginflow.organizations.read loginflow.organizations.write`. Same token handling as
/// [`crate::ServiceUsersClient`].
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{LoginFlowConfig, LoginFlowResult, OrganizationsClient};
///
/// async fn on_client_created(config: LoginFlowConfig, client_id: &str) -> LoginFlowResult<String> {
///     let organizations = OrganizationsClient::new(config, "rutafacil-api", "client-secret")?;
///     let organization = organizations.ensure(client_id, "Transportes Ruiz").await?;
///     Ok(organization.id)
/// }
/// ```
#[derive(Clone)]
pub struct OrganizationsClient {
    door: ServiceDoor,
}

service_door_client!(
    OrganizationsClient,
    [ORGANIZATIONS_READ_SCOPE, ORGANIZATIONS_WRITE_SCOPE]
);

impl OrganizationsClient {
    /// `PUT /v1/service/organizations/external/{external_id}`: the organization the product
    /// knows as `external_id`, created when missing (`201`) or renamed to `name` (`200`).
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] for an invalid `external_id` (1 to 128 characters of
    /// `[A-Za-z0-9:._@-]`) or `name` (1 to 120 characters).
    pub async fn ensure(&self, external_id: &str, name: &str) -> LoginFlowResult<Organization> {
        let url = self.door.url(&format!(
            "{ORGANIZATIONS_PATH}/external/{}",
            urlencoded(external_id)
        ));
        let body = EnsureOrganizationRequest {
            name: name.to_string(),
        };
        self.door
            .send_for_data("Ensure organization", |token| {
                self.door.http().put(&url).bearer_auth(token).json(&body)
            })
            .await
    }

    /// `GET /v1/service/organizations/{id}`.
    ///
    /// # Errors
    /// [`LoginFlowError::NotFound`] when `id` is not an organization of this company and
    /// application; [`LoginFlowError::Validation`] (`code` `BAD_REQUEST`) when `id` is not an
    /// organization id at all.
    pub async fn get(&self, id: &str) -> LoginFlowResult<Organization> {
        let url = self.organization_url(id);
        self.door
            .send_for_data("Get organization", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `GET /v1/service/organizations?external_id=`: the organization the product knows as
    /// `external_id`, `None` when there is none.
    pub async fn find_by_external_id(
        &self,
        external_id: &str,
    ) -> LoginFlowResult<Option<Organization>> {
        let url = with_query(
            self.door.url(ORGANIZATIONS_PATH),
            &[("external_id", Some(external_id.to_string()))],
        );
        let page: Page<Organization> = self
            .door
            .send_for_data("Find organization", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await?;
        Ok(page
            .items
            .into_iter()
            .find(|organization| organization.external_id.as_deref() == Some(external_id)))
    }

    /// `GET /v1/service/organizations?limit=&offset=`: one page of the organizations, the root
    /// first. `limit` is 1 to 200 (the server's default is 50).
    pub async fn list(&self, page: PageRequest) -> LoginFlowResult<Page<Organization>> {
        let url = with_query(
            self.door.url(ORGANIZATIONS_PATH),
            &[
                ("limit", page.limit.map(|limit| limit.to_string())),
                ("offset", page.offset.map(|offset| offset.to_string())),
            ],
        );
        self.door
            .send_for_data("List organizations", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// The root organization: the whole application within the company.
    ///
    /// # Errors
    /// [`LoginFlowError::NotFound`] when the listing has no root (the application is not linked
    /// to the company).
    pub async fn root(&self) -> LoginFlowResult<Organization> {
        let mut offset = 0u64;
        loop {
            let page = self
                .list(PageRequest {
                    limit: Some(ROOT_SCAN_PAGE),
                    offset: Some(offset),
                })
                .await?;
            let read = page.items.len() as u64;
            if let Some(root) = page
                .items
                .into_iter()
                .find(|organization| organization.kind == OrganizationKind::Root)
            {
                return Ok(root);
            }
            offset += read;
            if read == 0 || offset >= page.total {
                return Err(LoginFlowError::NotFound {
                    message: "the application has no root organization".to_string(),
                    code: None,
                });
            }
        }
    }

    /// `DELETE /v1/service/organizations/{id}` (`204`): every assignment in it goes, and the
    /// sessions that depended on them are revoked first.
    ///
    /// # Errors
    /// [`LoginFlowError::Conflict`] with `code` `root_organization` for the root;
    /// [`LoginFlowError::NotFound`] when `id` is not an organization of this company and
    /// application; [`LoginFlowError::Validation`] (`code` `BAD_REQUEST`) when `id` is not an
    /// organization id at all.
    pub async fn delete(&self, id: &str) -> LoginFlowResult<()> {
        let url = self.organization_url(id);
        self.door
            .send_for_unit("Delete organization", |token| {
                self.door.http().delete(&url).bearer_auth(token)
            })
            .await
    }

    fn organization_url(&self, id: &str) -> String {
        self.door
            .url(&format!("{ORGANIZATIONS_PATH}/{}", urlencoded(id)))
    }
}
