//! Models of the organization API (`/v1/service/organizations`), used by
//! [`crate::OrganizationsClient`]. An organization is the unit a role is granted in (a client
//! company, a school); it belongs to the token's company and application.

use serde::{Deserialize, Serialize};

/// What an organization stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationKind {
    /// The whole application within the company: exactly one, created with the application,
    /// without an `external_id`, never deleted while the application exists.
    Root,
    /// One the product created, keyed by its own `external_id`.
    Regular,
}

/// An organization of the token's company and application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// The organization's LoginFlow id (the `org_id` of tokens issued in it).
    pub id: String,
    /// `root` or `regular`.
    pub kind: OrganizationKind,
    /// The product's own id of the organization; `None` for the root.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Display name.
    pub name: String,
    /// UTC date-time, ISO 8601 WITHOUT an offset.
    pub created_at: String,
}

/// `PUT /v1/service/organizations/external/{external_id}` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnsureOrganizationRequest {
    /// Display name, 1 to 120 characters.
    pub name: String,
}

/// One page of a listing: `items` from `offset`, `total` across every page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// The items of this page.
    pub items: Vec<T>,
    /// How many items there are across every page.
    pub total: u64,
}

/// Which page of a listing to read. `None` leaves the server's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PageRequest {
    /// Page size (the server accepts 1 to 200; default 50).
    pub limit: Option<u32>,
    /// How many items to skip.
    pub offset: Option<u64>,
}
