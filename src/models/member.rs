//! Models of the members API of the machine door (`/v1/service/members`), used by
//! [`crate::MembersClient`]: a role of the application granted to one principal in one
//! organization, by a key that may grant only the roles listed for it.

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
/// `{"kind": "access_subject", "external_subject"}`. An answer also carries the subject's
/// LoginFlow `id`, which a request never sends.
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

/// A role the key may grant (`GET /v1/service/members/grantable-roles`). The list is set on the
/// LoginFlow panel; a new key has none.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrantableRole {
    pub id: String,
    /// The role's immutable key: what [`GrantMember::role_key`] names.
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A role granted to a principal in an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAssignment {
    pub id: String,
    pub organization_id: String,
    pub role_key: String,
    pub principal: Principal,
    pub granted_by: GrantedBy,
    /// UTC date-time, ISO 8601 WITHOUT an offset (same format as
    /// [`crate::ServiceUser::created_at`]); `None` for an assignment that never expires.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Same format as `expires_at`.
    pub created_at: String,
}

/// `POST /v1/service/members` body. Granting an identical assignment again answers the existing
/// one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMember {
    pub organization_id: String,
    /// The role's immutable key (e.g. `driver`); one of the key's [`GrantableRole`]s.
    pub role_key: String,
    pub principal: Principal,
    /// The instant the assignment expires, in the future; `None` never expires. Sent as RFC 3339
    /// with its offset (`2026-12-31T00:00:00Z`): LoginFlow refuses a date-time without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filters of `GET /v1/service/members`; every one set must match. The route takes no other
/// parameter (an unknown one is a `400`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberFilter {
    pub organization_id: Option<String>,
    /// A `company_users` id, or the LoginFlow id of an access-code subject.
    pub principal_id: Option<String>,
    /// An access-code subject's `ext_sub`.
    pub external_subject: Option<String>,
    pub role_key: Option<String>,
}
