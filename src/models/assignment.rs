//! Models of the role assignment API (`/v1/service/assignments`), used by
//! [`crate::AssignmentsClient`]: a role of the application granted to one principal in one
//! organization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Who a role is granted to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "PrincipalWire", into = "PrincipalWire")]
pub enum Principal {
    /// A person with an account (`company_users` id, the `sub` of their tokens).
    CompanyUser(String),
    /// An access-code subject, by the issuer's own id (its `ext_sub`).
    AccessSubject { external_subject: String },
}

/// The wire shape: `{"kind": "company_user", "id"}` or
/// `{"kind": "access_subject", "external_subject"}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PrincipalWire {
    CompanyUser { id: String },
    AccessSubject { external_subject: String },
}

impl From<PrincipalWire> for Principal {
    fn from(wire: PrincipalWire) -> Self {
        match wire {
            PrincipalWire::CompanyUser { id } => Principal::CompanyUser(id),
            PrincipalWire::AccessSubject { external_subject } => {
                Principal::AccessSubject { external_subject }
            }
        }
    }
}

impl From<Principal> for PrincipalWire {
    fn from(principal: Principal) -> Self {
        match principal {
            Principal::CompanyUser(id) => PrincipalWire::CompanyUser { id },
            Principal::AccessSubject { external_subject } => {
                PrincipalWire::AccessSubject { external_subject }
            }
        }
    }
}

/// Who granted an assignment: `kind` is `principal`, `client` or `system`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrantedBy {
    pub kind: String,
    pub id: String,
}

/// A role granted to a principal in an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub id: String,
    pub organization_id: String,
    pub role_key: String,
    pub principal: Principal,
    pub granted_by: GrantedBy,
    /// UTC date-time, ISO 8601 WITHOUT an offset; `None` for an assignment that never expires.
    #[serde(default)]
    pub expires_at: Option<String>,
    pub created_at: String,
}

/// `POST /v1/service/assignments` body. Granting an identical assignment again answers the
/// existing one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantAssignment {
    pub organization_id: String,
    /// The role's immutable key (e.g. `driver`).
    pub role_key: String,
    pub principal: Principal,
    /// The instant the assignment expires, in the future; `None` never expires. Sent as RFC 3339
    /// with its offset (`2026-12-31T00:00:00Z`): LoginFlow refuses a date-time without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filters of `GET /v1/service/assignments`; every one set must match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssignmentFilter {
    pub organization_id: Option<String>,
    /// A `company_users` id.
    pub principal_id: Option<String>,
    /// An access-code subject's `ext_sub`.
    pub external_subject: Option<String>,
    pub role_key: Option<String>,
}
