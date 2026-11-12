//! Models of the founding call of the machine door (`POST /v1/service/organizations/founded`),
//! used by [`crate::FoundingClient`]: a signed-in person founds an organization of the
//! application and receives its founder role there, in one step.

use serde::{Deserialize, Serialize};

use crate::models::{MemberAssignment, Organization};

/// `error.code` of a `409`: an organization with that `external_id` exists and the person does
/// not hold the founder role there. Nothing was granted.
pub const ORGANIZATION_EXISTS_CODE: &str = "organization_exists";

/// `error.code` of a `409`: the application has no founder role configured on the LoginFlow
/// panel.
pub const FOUNDER_ROLE_NOT_CONFIGURED_CODE: &str = "founder_role_not_configured";

/// `error.code` of a `429` (with `Retry-After`): the person founded too many organizations of
/// the application in the last 24 hours.
pub const FOUNDING_RATE_LIMITED_CODE: &str = "founding_rate_limited";

/// `error.code` of a `403`: the founder role is not among the roles the key may grant.
pub const KEY_ROLE_NOT_GRANTABLE_CODE: &str = "key_role_not_grantable";

/// What to found: the product's own id of the new organization and its display name. Validated
/// like [`crate::OrganizationsClient::ensure`]: `external_id` 1 to 128 characters of
/// `[A-Za-z0-9:._@-]`, `name` 1 to 120 characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FoundOrganizationRequest {
    /// The product's own id of the organization (its tenant id).
    pub external_id: String,
    /// Display name.
    pub name: String,
}

/// The answer of a founding: the organization, the founder's assignment in it, and whether this
/// call created them (`201`) or found them from an earlier founding by the same person (`200`, a
/// safe retry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundedOrganization {
    /// The organization, as [`crate::OrganizationsClient::ensure`] returns it.
    pub organization: Organization,
    /// The founder role granted to the person there, as [`crate::MembersClient::grant`] returns
    /// it.
    pub assignment: MemberAssignment,
    /// `true` when this call created the organization; `false` for a retry of a founding that
    /// already happened.
    pub created: bool,
}
