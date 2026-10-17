//! # LoginFlow SDK
//!
//! A Rust SDK for integrating with the LoginFlow OIDC provider.
//!
//! ## v0.6.0: OIDC cutover
//!
//! The REST login surface (`register`, `login`, `refresh_token`, `logout`, email verification,
//! OTP login, OAuth login, password reset, delegated auth) moved to the first-party OIDC
//! challenge / hosted login (RFC 9700 §2.4, draft-ietf-oauth-first-party-apps). This SDK release covers
//! what a backend resource server needs:
//!
//! - **Access token verification**: RFC 9068 (`typ: at+jwt`) tokens verified locally against the
//!   issuer's JWKS (`kid`), with header `typ`, issuer, audience and expiration checks. The token
//!   carries no PII (no email, no profile `user_id`, no account status): `sub` is the
//!   `company_users` id, with `sid`, `client_id`, `scope`, `auth_time`, `amr`, `acr` and —
//!   when DPoP-bound — `cnf.jkt` ([`dpop::verify_proof_matches_cnf`]).
//! - **`GET /oauth2/userinfo`**: the one sanctioned way to resolve an email live, by scope.
//! - **OIDC Back-Channel Logout 1.0**: `verify_logout_token` for an RP's own
//!   `backchannel_logout_uri`.
//! - **DPoP (RFC 9449)**: `dpop` module, for a resource server validating a presented proof
//!   against a token's `cnf.jkt`.
//! - **`client_credentials`**: a confidential-client token client with caching (refreshed shortly
//!   before expiry) and single-flight refresh.
//! - **Introspection**: an RFC 7662 `/oauth2/introspect` client.
//! - **Account/profile management**: `change_password` (reshaped to `{new_password}`, now
//!   subject to RFC 9470 step-up), the master user-accounts/user-profiles CRUD, TOTP enrollment
//!   (`setup_totp`/`verify_totp_setup`/`get_totp_status`/`disable_totp`), account recovery.
//! - **Actix-web Integration**: Ready-to-use extractors (feature: `actix`)
//!
//! ## Quick Start
//!
//! ### From Environment Variables
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginFlowResult};
//!
//! fn build() -> LoginFlowResult<LoginFlowClient> {
//!     // Required: LOGINFLOW_URL, LOGINFLOW_COMPANY, LOGINFLOW_APPLICATION, LOGINFLOW_ISSUER
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
//!         company_id: "your-company-uuid".into(),
//!         application_id: "your-app-uuid".into(),
//!         timeout_secs: 30,
//!         user_agent: None,
//!         issuer: "https://api.loginflow.dev".into(),
//!         jwks_url: None, // defaults to {base_url}/oauth2/jwks
//!         jwks_cache_ttl_secs: 600,
//!     })
//! }
//! ```
//!
//! ### Verifying an access token
//!
//! ```rust,no_run
//! use loginflow_sdk::LoginFlowClient;
//!
//! async fn check(client: &LoginFlowClient, bearer_token: &str) {
//!     match client.verify_token(bearer_token).await {
//!         Ok(claims) => println!("sub={} client_id={} scope={}", claims.sub, claims.client_id, claims.scope),
//!         Err(e) => eprintln!("rejected: {e}"),
//!     }
//! }
//! ```
//!
//! ### `client_credentials`
//!
//! ```rust,no_run
//! use loginflow_sdk::{ClientCredentialsClient, LoginFlowResult};
//!
//! async fn call(client: &ClientCredentialsClient) -> LoginFlowResult<()> {
//!     let token = client.access_token().await?;
//!     println!("app token: {}", token);
//!     Ok(())
//! }
//! ```
//!
//! ### Actix-web Integration
//!
//! Requires the `actix` feature (enabled by default).
//!
//! ```rust,ignore
//! use actix_web::{web, App, HttpServer, HttpResponse, post};
//! use loginflow_sdk::LoginFlowClient;
//! use loginflow_sdk::actix::AuthMiddleware;
//!
//! #[post("/protected")]
//! async fn protected_endpoint(auth: AuthMiddleware) -> HttpResponse {
//!     HttpResponse::Ok().json(serde_json::json!({
//!         "company_user_id": auth.company_user_id().to_string(),
//!     }))
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let client = LoginFlowClient::from_env().map_err(std::io::Error::other)?;
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             // Required: the extractors verify tokens with this client.
//!             .app_data(web::Data::new(client.clone()))
//!             .service(protected_endpoint)
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## Environment Variables
//!
//! | Variable | Description | Required |
//! |----------|-------------|----------|
//! | `LOGINFLOW_URL` | Base URL without version (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGINFLOW_VERSION` | API version number (default: 1) | No |
//! | `LOGINFLOW_COMPANY` | Company UUID from LoginFlow | Yes |
//! | `LOGINFLOW_APPLICATION` | Application UUID (expected `aud` of access tokens) | Yes |
//! | `LOGINFLOW_ISSUER` | Expected `iss` of tokens (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGINFLOW_JWKS_URL` | JWKS endpoint (default: `{LOGINFLOW_URL}/oauth2/jwks`) | No |
//! | `LOGINFLOW_JWKS_CACHE_TTL_SECS` | JWKS cache lifetime in seconds (default: 600) | No |
//! | `LOGINFLOW_TIMEOUT` | Request timeout in seconds (default: 30) | No |
//! | `LOGINFLOW_USER_AGENT` | Custom User-Agent header | No |
//!
//! ## Feature Flags
//!
//! - `actix` (default): Enables Actix-web extractors

// Core modules
pub mod client;
pub mod config;
pub mod discovery;
pub mod dpop;
pub mod error;
mod http;
pub mod jwks;
pub mod models;
mod oauth2;

// Actix integration (feature-gated)
#[cfg(feature = "actix")]
pub mod actix;

// Re-exports for convenience
pub use client::LoginFlowClient;
pub use config::{ConfigError, LoginFlowConfig};
pub use discovery::DiscoveryDocument;
pub use error::{LoginFlowError, LoginFlowResult};
pub use jwks::JwksCache;
pub use oauth2::{
    ClientCredentialsClient, IntrospectionClient, IntrospectionResponse, RevocationClient,
};

// Re-export commonly used models
pub use models::{
    // Account Recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    // Auth
    AuthenticatedUser,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    // JWT
    CnfClaim,
    // User Account
    FullUserAccountResponse,
    JwtClaims,
    LoginFlowErrorDetail,
    LoginFlowErrorResponse,
    LogoutTokenClaims,
    OperationResponse,
    ResponseMeta,
    // TOTP 2FA
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
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
    pub use crate::{ClientCredentialsClient, IntrospectionClient};

    pub use crate::models::{
        AuthenticatedUser, ChangePasswordRequest, UpdateUserAccountRequest,
        UpdateUserProfileRequest,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
}

#[cfg(feature = "actix")]
pub use actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
