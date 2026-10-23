//! # LoginFlow SDK
//!
//! A Rust SDK for integrating with the LoginFlow OIDC provider.
//!
//! ## v0.11.0: permissions
//!
//! A product authorizes every request with LoginFlow permissions, and nothing else:
//!
//! - [`PermissionManifest`]: the API's `permissions.yaml` (`{app}.{resource}.{action}`), synced to
//!   LoginFlow by [`CatalogClient`] (scope `loginflow.catalog.write`, the catalog of the key's own
//!   API only).
//! - [`OrganizationsClient`] and [`AssignmentsClient`]: the product creates its organizations and
//!   grants roles in them to a person or an access-code subject ([`Principal`]).
//! - [`TokenVerifier`]: an access token for THIS API (`aud` = `LOGINFLOW_API`), ES256 only,
//!   `iss`/`exp`/`typ at+jwt`, DPoP with single-use proofs ([`JtiReplayCache`]), and the
//!   permissions of an overage token read live (fails closed with `503`).
//! - [`actix::PermissionRouter`]: every route with its permission, denied by default
//!   (`403 permission_unmapped`, `organization_required`, `permission_denied`); handlers read
//!   [`actix::Authorized`] and scope every query by its `org_id`.
//! - `testing` feature: route-coverage assertions, signed test tokens and a `FakeVerifier`.
//!
//! Gone: the role claim and every role-based helper, the extractors that verified a token
//! outside the route table, and the application as audience (the audience is the API's). The
//! machine scopes are the `loginflow.*` permissions. See `CHANGELOG.md`.
//!
//! ## v0.7.0
//!
//! - Every id is an opaque `String`/`&str`, never a UUID: companies are `CP-...`, applications
//!   `APP-...`, a `client_credentials` `sub` is the client_id.
//! - [`ServiceUsersClient`]: machine-to-machine user management (`/v1/service/users`).
//! - [`LoginFlowError::Conflict`] for `409`, with the server's error code.
//!
//! ## v0.6.0: OIDC cutover
//!
//! The REST login surface (`register`, `login`, `refresh_token`, `logout`, email verification,
//! OTP login, OAuth login, password reset, delegated auth) moved to the first-party OIDC
//! challenge / hosted login (RFC 9700 §2.4, draft-ietf-oauth-first-party-apps). This SDK release covers
//! what a backend resource server needs:
//!
//! - **Access token verification**: RFC 9068 (`typ: at+jwt`) tokens verified locally against the
//!   issuer's JWKS (`kid`). The token carries no PII: `sub` is the `company_users` id.
//! - **`GET /oauth2/userinfo`**: the one sanctioned way to resolve an email live, by scope.
//! - **OIDC Back-Channel Logout 1.0**: `verify_logout_token` for an RP's own
//!   `backchannel_logout_uri`.
//! - **DPoP (RFC 9449)**: `dpop` module, the proof checks [`TokenVerifier`] applies.
//! - **`client_credentials`**: a confidential-client token client with caching (refreshed shortly
//!   before expiry) and single-flight refresh.
//! - **Introspection**: an RFC 7662 `/oauth2/introspect` client.
//! - **Account/profile management**: `change_password` (reshaped to `{new_password}`, now
//!   subject to RFC 9470 step-up), the master user-accounts/user-profiles CRUD, TOTP enrollment
//!   (`setup_totp`/`verify_totp_setup`/`get_totp_status`/`disable_totp`), account recovery.
//! - **Actix-web Integration**: the permission router and gate (feature: `actix`)
//!
//! ## Quick Start
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
//! ### With Explicit Configuration
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
//! ## Environment Variables
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
//! ## Feature Flags
//!
//! - `actix` (default): the Actix-web permission router, gate and `Authorized` extractor
//! - `testing`: helpers for a product's tests (enable it in `[dev-dependencies]` only)

// Core modules
mod access_codes;
mod assignments;
pub mod authorization;
mod catalog;
pub mod client;
pub mod config;
pub mod discovery;
pub mod dpop;
pub mod error;
mod http;
pub mod jwks;
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
pub use assignments::AssignmentsClient;
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
pub use error::{LoginFlowError, LoginFlowResult};
pub use jwks::JwksCache;
pub use oauth2::{
    ClientCredentialsClient, IntrospectionClient, IntrospectionResponse, RevocationClient,
};
pub use organizations::OrganizationsClient;
pub use service_users::ServiceUsersClient;

// Re-export commonly used models
pub use models::{
    // Access codes
    ACCESS_CODES_DISABLED_CODE,
    // Machine scopes
    ACCESS_CODES_ISSUE_SCOPE,
    ASSIGNMENTS_WRITE_SCOPE,
    // Access token
    AccessClaims,
    AccessCodeInfo,
    AccessSubjectClaims,
    // Account Recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    // Assignments
    Assignment,
    AssignmentFilter,
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
    ConfirmServiceUserEmailChangeRequest,
    CreateServiceUserRequest,
    EmailChangeRequested,
    EnsureOrganizationRequest,
    // User Account
    FullUserAccountResponse,
    GrantAssignment,
    GrantedBy,
    // Service users: the invitation outcome of a create
    InvitationStatus,
    IssueAccessCodeRequest,
    IssuedAccessCode,
    LoginFlowErrorDetail,
    LoginFlowErrorResponse,
    LogoutTokenClaims,
    ORGANIZATIONS_WRITE_SCOPE,
    OperationResponse,
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
    ServiceUserEmailChangeRequest,
    SetServiceUserActiveRequest,
    SubjectKind,
    TokenPermissions,
    // TOTP 2FA
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    USERS_WRITE_SCOPE,
    UpdateUserAccountRequest,
    // User Profile
    UpdateUserProfileRequest,
    UserAccountResponse,
    UserInfoResponse,
    UserProfileResponse,
    VerifyTotpSetupRequest,
};

/// Prelude module for convenient imports
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
        AccessCodesClient, AssignmentsClient, CatalogClient, ClientCredentialsClient,
        InMemoryJtiReplayCache, IntrospectionClient, OrganizationsClient, PermissionManifest,
        ServiceUsersClient, TokenVerifier,
    };

    pub use crate::models::{
        AccessClaims, ChangePasswordRequest, CreateServiceUserRequest, GrantAssignment,
        IssueAccessCodeRequest, IssuedAccessCode, Principal, ServiceUser, SubjectKind,
        TokenPermissions, UpdateUserAccountRequest, UpdateUserProfileRequest,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AccessDenied, Authorized, PermissionRouter};
}
