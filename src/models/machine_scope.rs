//! The `client_credentials` scopes of LoginFlow's machine door (`/v1/service/*`). Each one is a
//! LoginFlow permission (`loginflow.<resource>.<action>`). The API checks every route's EXACT
//! permission both in the token's `scope` and among the key's own permissions, so each service
//! client requests the read and write permissions of its routes (see [`crate::MembersClient`] and
//! the other `/v1/service` clients); the key must hold every one of them.

/// `GET /v1/service/users*`: [`crate::ServiceUsersClient`].
pub const USERS_READ_SCOPE: &str = "loginflow.users.read";

/// Every other `/v1/service/users` route: [`crate::ServiceUsersClient`].
pub const USERS_WRITE_SCOPE: &str = "loginflow.users.write";

/// `POST /v1/service/access-codes`: [`crate::AccessCodesClient`].
pub const ACCESS_CODES_ISSUE_SCOPE: &str = "loginflow.accessCodes.issue";

/// `GET /v1/service/access-codes`: [`crate::AccessCodesClient`].
pub const ACCESS_CODES_READ_SCOPE: &str = "loginflow.accessCodes.read";

/// `DELETE /v1/service/access-codes/{id}` and `POST /v1/service/access-subjects/revoke`:
/// [`crate::AccessCodesClient`].
pub const ACCESS_CODES_REVOKE_SCOPE: &str = "loginflow.accessCodes.revoke";

/// `GET /v1/service/catalog`, the permission catalog of the key's own API: [`crate::CatalogClient`].
pub const CATALOG_READ_SCOPE: &str = "loginflow.catalog.read";

/// `PUT /v1/service/catalog`: [`crate::CatalogClient`].
pub const CATALOG_WRITE_SCOPE: &str = "loginflow.catalog.write";

/// `GET /v1/service/organizations*`: [`crate::OrganizationsClient`].
pub const ORGANIZATIONS_READ_SCOPE: &str = "loginflow.organizations.read";

/// Every other `/v1/service/organizations` route: [`crate::OrganizationsClient`].
pub const ORGANIZATIONS_WRITE_SCOPE: &str = "loginflow.organizations.write";

/// `GET /v1/service/members*`: [`crate::MembersClient`].
pub const ASSIGNMENTS_READ_SCOPE: &str = "loginflow.assignments.read";

/// Grant and revoke on `/v1/service/members`: [`crate::MembersClient`].
pub const ASSIGNMENTS_WRITE_SCOPE: &str = "loginflow.assignments.write";
