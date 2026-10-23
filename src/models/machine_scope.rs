//! The `client_credentials` scopes of LoginFlow's machine door (`/v1/service/*`). Each one is a
//! LoginFlow permission (`loginflow.<resource>.<action>`): an API's key is granted only the ones
//! it needs, and every service client requests exactly one.

/// `/v1/service/users`: [`crate::ServiceUsersClient`].
pub const USERS_WRITE_SCOPE: &str = "loginflow.users.write";

/// `/v1/service/access-codes` and `/v1/service/access-subjects`: [`crate::AccessCodesClient`].
pub const ACCESS_CODES_ISSUE_SCOPE: &str = "loginflow.accessCodes.issue";

/// `/v1/service/catalog`, the permission catalog of the key's own API: [`crate::CatalogClient`].
pub const CATALOG_WRITE_SCOPE: &str = "loginflow.catalog.write";

/// `/v1/service/organizations`: [`crate::OrganizationsClient`].
pub const ORGANIZATIONS_WRITE_SCOPE: &str = "loginflow.organizations.write";

/// `/v1/service/assignments`: [`crate::AssignmentsClient`].
pub const ASSIGNMENTS_WRITE_SCOPE: &str = "loginflow.assignments.write";
