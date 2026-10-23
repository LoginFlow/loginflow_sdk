//! Models of the permission catalog API (`/v1/service/catalog`), used by
//! [`crate::CatalogClient`]. The catalog is the one of the API whose key calls it: the server
//! takes the application and the API from the `client_credentials` token, never from the body.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How much a permission lets its holder do on a resource. `write` includes `read` only in the
/// panel's role editor; in a token every permission is listed on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLevel {
    /// Reads the resource.
    Read,
    /// Changes the resource.
    Write,
    /// An action that is neither reading nor writing the resource (e.g. issuing a code).
    Special,
}

impl PermissionLevel {
    /// The wire value (`read` / `write` / `special`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            PermissionLevel::Read => "read",
            PermissionLevel::Write => "write",
            PermissionLevel::Special => "special",
        }
    }
}

impl fmt::Display for PermissionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a catalog permission can still be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    /// In the API's manifest: assignable and effective.
    Active,
    /// No longer in the API's manifest: not assignable, purged after 30 days.
    Obsolete,
}

/// One resource of `PUT /v1/service/catalog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogResource {
    /// The resource key (`drivers`): `[a-z][a-zA-Z0-9_]*`, at most 60 characters.
    pub key: String,
    /// What the resource is, 1 to 500 characters.
    pub description: String,
    /// Personal or otherwise sensitive data: the panel's "Support" template leaves it out.
    pub sensitive: bool,
}

/// One permission of `PUT /v1/service/catalog`: `key` is `{app}.{resource}.{action}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogPermission {
    /// `{app}.{resource}.{action}`, of a resource of the same request.
    pub key: String,
    /// `read`, `write` or `special`.
    pub level: PermissionLevel,
    /// What the permission allows, 1 to 500 characters.
    pub description: String,
}

/// `PUT /v1/service/catalog` body, built from the manifest by [`crate::CatalogClient::sync`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSyncRequest {
    /// The application's permission prefix: it must be the key's own.
    pub app: String,
    /// Every resource of the API (1 to 200).
    pub resources: Vec<CatalogResource>,
    /// Every permission of the API (1 to 500).
    pub permissions: Vec<CatalogPermission>,
}

/// Answer of `PUT /v1/service/catalog`. Syncing the same manifest again changes nothing: the
/// three lists come back empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSyncReport {
    /// SHA-256 (hex) of the API's catalog after the sync.
    pub catalog_hash: String,
    /// Permissions new to the API's catalog.
    pub added: Vec<String>,
    /// Obsolete permissions that came back; they keep their place in every role.
    pub reactivated: Vec<String>,
    /// Permissions no longer in the manifest: no longer assignable nor granted.
    pub obsoleted: Vec<String>,
    /// How many permissions were already there as they are.
    pub unchanged: u64,
}

/// A permission as `GET /v1/service/catalog` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntryInfo {
    /// `{app}.{resource}.{action}`.
    pub key: String,
    /// The resource key it belongs to.
    pub resource: String,
    /// `read`, `write` or `special`.
    pub level: PermissionLevel,
    /// What the permission allows.
    pub description: String,
    /// Whether its resource is sensitive.
    pub sensitive: bool,
    /// `active`, or `obsolete` once it left the manifest.
    pub status: PermissionStatus,
}

/// Answer of `GET /v1/service/catalog`: the catalog of the key's API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    /// The application's slug; `None` until the application's first sync.
    #[serde(default)]
    pub app: Option<String>,
    /// `None` until the API's first sync.
    #[serde(default)]
    pub catalog_hash: Option<String>,
    /// UTC date-time, ISO 8601 WITHOUT an offset; `None` until the first sync.
    #[serde(default)]
    pub synced_at: Option<String>,
    /// Every permission of the API, obsolete ones included.
    pub permissions: Vec<CatalogEntryInfo>,
}
