//! The permission catalog of the caller's API (`/v1/service/catalog`).
//!
//! The API's key (a `client_credentials` client bound to one API, scope
//! `loginflow.catalog.write`) syncs the API's [`PermissionManifest`] — usually at start-up or on
//! deploy. The server takes the application and the API from the token: a sync adds, reactivates
//! and obsoletes the permissions of THAT API only, never those of another API of the same
//! application.

use crate::authorization::manifest::PermissionManifest;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::{CATALOG_WRITE_SCOPE, Catalog, CatalogSyncReport};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the catalog.
const CATALOG_PATH: &str = "service/catalog";

/// Client for `/v1/service/catalog`, authenticated with a cached `client_credentials` token
/// requested with scope `loginflow.catalog.write`. Same token handling as
/// [`crate::ServiceUsersClient`].
///
/// # Example
/// ```rust,no_run
/// use std::path::Path;
///
/// use loginflow_sdk::{CatalogClient, LoginFlowConfig, LoginFlowResult, PermissionManifest};
///
/// async fn sync(config: LoginFlowConfig) -> LoginFlowResult<()> {
///     let manifest = PermissionManifest::load(Path::new("permissions.yaml"))
///         .map_err(|e| loginflow_sdk::LoginFlowError::Config(e.to_string()))?;
///     let catalog = CatalogClient::new(config, "rutafacil-api", "client-secret")?;
///     let report = catalog.sync(&manifest).await?;
///     println!("catalog {}: +{:?} -{:?}", report.catalog_hash, report.added, report.obsoleted);
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct CatalogClient {
    door: ServiceDoor,
}

service_door_client!(CatalogClient, CATALOG_WRITE_SCOPE);

impl CatalogClient {
    /// `PUT /v1/service/catalog`: make the API's catalog the manifest's. Idempotent: the same
    /// manifest again changes nothing.
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] for a manifest that breaks
    /// [`PermissionManifest::validate`] (nothing is sent) or that the server refuses (`422`);
    /// [`LoginFlowError::Conflict`] with `code` `catalog_app_mismatch` (the prefix is not the
    /// key's application's), `catalog_prefix_taken`, `resource_owned_by_other_api` or
    /// `permission_used_by_sign_in_gate` (the sync would obsolete a permission a client's
    /// sign-in gate requires).
    pub async fn sync(&self, manifest: &PermissionManifest) -> LoginFlowResult<CatalogSyncReport> {
        manifest
            .validate()
            .map_err(|e| LoginFlowError::Validation(e.to_string()))?;
        let url = self.door.url(CATALOG_PATH);
        let body = manifest.catalog_request();
        self.door
            .send_for_data("Sync permission catalog", |token| {
                self.door.http().put(&url).bearer_auth(token).json(&body)
            })
            .await
    }

    /// `GET /v1/service/catalog`: the API's catalog, obsolete permissions included.
    pub async fn get(&self) -> LoginFlowResult<Catalog> {
        let url = self.door.url(CATALOG_PATH);
        self.door
            .send_for_data("Get permission catalog", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }
}
