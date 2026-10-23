//! # LoginFlow SDK
//!
//! How a Rust backend (a product's API) consumes LoginFlow, the OIDC provider. Signing a person
//! in is not part of it: that is the hosted login or the first-party OIDC challenge, driven by
//! the product's frontend (`loginflow_auth`). This crate covers what the API itself does:
//!
//! - **Declare its permissions**: [`PermissionManifest`] (`permissions.yaml`, every permission
//!   `{app}.{resource}.{action}`), synced to the catalog of the API's own audience by
//!   [`CatalogClient`].
//! - **Authorize every request**: [`actix::PermissionRouter`] declares each route with its
//!   permission (or as public) and its gate verifies the request with a [`TokenVerifier`]: an
//!   ES256 RFC 9068 access token (`typ: at+jwt`) of the configured issuer, for THIS API (`aud` =
//!   `LOGINFLOW_API`), of the configured company (`company_id` = `LOGINFLOW_COMPANY`), not
//!   expired, with its DPoP binding (RFC 9449, single-use proofs through a [`JtiReplayCache`])
//!   and, for an overage token, its permissions read live by introspection (fails closed). The
//!   handler reads the caller from [`actix::Authorized`] and scopes every query by its
//!   organization. A route outside the table is refused (`403 permission_unmapped`).
//! - **Provision through its machine key** (`client_credentials`, the `/v1/service/*` door):
//!   [`OrganizationsClient`], [`MembersClient`], [`ServiceUsersClient`], [`AccessCodesClient`].
//!   Each requests exactly the `loginflow.*` permissions of its routes; the key must hold them.
//! - **Account calls on behalf of a person** with that person's access token: TOTP enrollment,
//!   [`LoginFlowClient::change_password`], [`LoginFlowClient::userinfo`], plus
//!   [`LoginFlowClient::request_account_recovery`] (no token) and
//!   [`LoginFlowClient::verify_logout_token`] (back-channel logout).
//! - **OAuth plumbing**: [`ClientCredentialsClient`], [`IntrospectionClient`],
//!   [`RevocationClient`], [`DiscoveryDocument`].
//! - **Tests** (`testing` feature): route coverage assertions, a [`TokenVerifier`] stand-in that
//!   needs no LoginFlow server, and signed test tokens.
//!
//! Every fallible call returns [`LoginFlowResult`]; [`LoginFlowError`] keeps the server's
//! `error.code` on every refusal a caller may need to tell apart (`403`, `404`, `409`, `422`).
//!
//! The step-by-step integration guide is `TUTORIAL.md`; the release notes, `CHANGELOG.md`.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginFlowResult};
//!
//! fn build() -> LoginFlowResult<LoginFlowClient> {
//!     // Required: LOGINFLOW_URL, LOGINFLOW_COMPANY, LOGINFLOW_API, LOGINFLOW_ISSUER
//!     LoginFlowClient::from_env()
//! }
//! ```
//!
//! ### With explicit configuration
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginFlowConfig, LoginFlowResult};
//!
//! fn build() -> LoginFlowResult<LoginFlowClient> {
//!     LoginFlowClient::new(LoginFlowConfig {
//!         base_url: "https://api.loginflow.dev".into(),
//!         api_version: 1,
//!         company_id: "CP-your-company".into(),
//!         api_audience: "https://api.your-product.example".into(),
//!         timeout_secs: 30,
//!         user_agent: None,
//!         issuer: "https://api.loginflow.dev".into(),
//!         jwks_url: None, // defaults to {base_url}/oauth2/jwks
//!         jwks_cache_ttl_secs: 600,
//!         resource_base_url: None, // DPoP `htu` base; None = derived from the request
//!     })
//! }
//! ```
//!
//! ### Protecting an Actix-web API
//!
//! See [`actix`]: a [`actix::PermissionRouter`] declares every route with its permission and
//! its gate verifies each request with a [`TokenVerifier`].
//!
//! ## Environment variables
//!
//! | Variable | Description | Required |
//! |----------|-------------|----------|
//! | `LOGINFLOW_URL` | Base URL without version (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGINFLOW_VERSION` | API version number (default: 1) | No |
//! | `LOGINFLOW_COMPANY` | Company ID from LoginFlow (`CP-...`) | Yes |
//! | `LOGINFLOW_API` | Audience of this API (expected `aud` of access tokens) | Yes |
//! | `LOGINFLOW_ISSUER` | Expected `iss` of tokens (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGINFLOW_JWKS_URL` | JWKS endpoint (default: `{LOGINFLOW_URL}/oauth2/jwks`) | No |
//! | `LOGINFLOW_JWKS_CACHE_TTL_SECS` | JWKS cache lifetime in seconds (default: 600) | No |
//! | `LOGINFLOW_TIMEOUT` | Request timeout in seconds (default: 30) | No |
//! | `LOGINFLOW_USER_AGENT` | Custom User-Agent header | No |
//! | `LOGINFLOW_RESOURCE_BASE_URL` | Public base URL of this resource server, for the DPoP `htu` (default: derived from the request) | No |
//!
//! The API's machine key (`client_id` / `client_secret`) is not part of [`LoginFlowConfig`]:
//! read it yourself and pass it to the service clients and to the [`IntrospectionClient`] of the
//! [`TokenVerifier`].
//!
//! ## Feature flags
//!
//! - `actix` (default): the Actix-web permission router, gate and `Authorized` extractor.
//! - `testing`: helpers for a product's tests (enable it in `[dev-dependencies]` only); implies
//!   `actix`.

#![warn(missing_docs)]

// Core modules
mod access_codes;
pub mod authorization;
mod catalog;
pub mod client;
pub mod config;
pub mod discovery;
pub mod dpop;
pub mod error;
mod http;
pub mod jwks;
mod members;
pub mod models;
mod oauth2;
mod organizations;
mod service_door;
mod service_users;

// Actix integration (feature-gated)
#[cfg(feature = "actix")]
pub mod actix;

// Test helpers for products (feature-gated)
#[cfg(feature = "testing")]
pub mod testing;

// Re-exports for convenience
pub use access_codes::AccessCodesClient;
pub use authorization::manifest::{
    ActionSpec, CatalogEntry, ManifestError, PermissionManifest, ResourceSpec,
};
pub use authorization::replay::{InMemoryJtiReplayCache, JtiReplayCache};
pub use authorization::verifier::{
    AccessVerifier, PresentedToken, TokenVerifier, VerifiedAccess, VerifyError, VerifyFuture,
};
pub use catalog::CatalogClient;
pub use client::LoginFlowClient;
pub use config::{ConfigError, LoginFlowConfig};
pub use discovery::DiscoveryDocument;
pub use error::{INVALID_CODE, LoginFlowError, LoginFlowResult};
pub use jwks::JwksCache;
pub use members::MembersClient;
pub use oauth2::{
    ClientCredentialsClient, INTROSPECTION_CACHE_MAX_ENTRIES, INTROSPECTION_CACHE_TTL,
    IntrospectionClient, IntrospectionResponse, RevocationClient,
};
pub use organizations::OrganizationsClient;
pub use service_users::ServiceUsersClient;

// Re-export commonly used models
pub use models::{
    // Access codes
    ACCESS_CODES_DISABLED_CODE,
    // Machine scopes
    ACCESS_CODES_ISSUE_SCOPE,
    ACCESS_CODES_READ_SCOPE,
    ACCESS_CODES_REVOKE_SCOPE,
    ASSIGNMENTS_READ_SCOPE,
    ASSIGNMENTS_WRITE_SCOPE,
    // Access token
    AccessClaims,
    AccessCodeInfo,
    AccessSubjectClaims,
    // Account Recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    CATALOG_READ_SCOPE,
    CATALOG_WRITE_SCOPE,
    // Catalog
    Catalog,
    CatalogEntryInfo,
    CatalogPermission,
    CatalogResource,
    CatalogSyncReport,
    CatalogSyncRequest,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    CnfClaim,
    // Service users
    CreateServiceUserRequest,
    EnsureOrganizationRequest,
    // Members
    GrantMember,
    GrantableRole,
    GrantedBy,
    // Service users: the invitation outcome of a create
    InvitationStatus,
    IssueAccessCodeRequest,
    IssuedAccessCode,
    LoginFlowErrorDetail,
    LoginFlowErrorResponse,
    LogoutTokenClaims,
    MemberAssignment,
    MemberFilter,
    ORGANIZATIONS_READ_SCOPE,
    ORGANIZATIONS_WRITE_SCOPE,
    // Organizations
    Organization,
    OrganizationKind,
    Page,
    PageRequest,
    PermissionLevel,
    PermissionStatus,
    Principal,
    ResponseMeta,
    RevokeAccessSubjectRequest,
    RevokedSessions,
    ServiceUser,
    ServiceUserDeleted,
    SetServiceUserActiveRequest,
    SubjectKind,
    TokenPermissions,
    // TOTP 2FA
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    USERS_READ_SCOPE,
    USERS_WRITE_SCOPE,
    UserInfoResponse,
    VerifyTotpSetupRequest,
};

/// The types most integrations name, in one import.
///
/// ```rust
/// use loginflow_sdk::prelude::*;
/// ```
pub mod prelude {
    pub use crate::LoginFlowClient;
    pub use crate::LoginFlowConfig;
    pub use crate::LoginFlowError;
    pub use crate::LoginFlowResult;
    pub use crate::{
        AccessCodesClient, CatalogClient, ClientCredentialsClient, InMemoryJtiReplayCache,
        IntrospectionClient, MembersClient, OrganizationsClient, PermissionManifest,
        ServiceUsersClient, TokenVerifier,
    };

    pub use crate::models::{
        AccessClaims, ChangePasswordRequest, CreateServiceUserRequest, GrantMember,
        IssueAccessCodeRequest, IssuedAccessCode, Principal, ServiceUser, SubjectKind,
        TokenPermissions,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AccessDenied, Authorized, PermissionRouter};
}
