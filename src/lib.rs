//! # LoginFlow SDK
//!
//! A Rust SDK for integrating with the LoginFlow authentication service.
//!
//! ## Features
//!
//! - **Authentication**: Register, login, logout
//! - **OTP login**: one-time code by email (single flow)
//! - **TOTP 2FA**: Optional time-based one-time password for two-factor authentication
//! - **Session Refresh**: Refresh the session with the refresh token + session ID
//! - **Password Management**: Reset password (3-step flow), change password
//! - **Email Verification**: Verify user email with code
//! - **Token verification**: ES256 access tokens verified locally against the
//!   issuer's JWKS (`kid`), with issuer, audience, expiration and `token_type` checks
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
//!     // Required: LOGIN_FLOW_URL, LOGIN_FLOW_COMPANY, LOGIN_FLOW_APPLICATION, LOGINFLOW_ISSUER
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
//! ### Login Example
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult};
//!
//! async fn login_user(client: &LoginFlowClient, email: &str, password: &str) {
//!     let result = client.login(LoginRequest {
//!         email: email.to_string(),
//!         password: password.to_string(),
//!     }).await;
//!
//!     match result {
//!         Ok(LoginResult::Success(response)) => {
//!             println!("Access token: {}", response.jwt);
//!             println!("Refresh token: {}", response.refresh_token);
//!         }
//!         Ok(LoginResult::TotpRequired(challenge)) => {
//!             println!("2FA required! Token: {}", challenge.totp_token);
//!             // Prompt user for TOTP code, then:
//!             // client.verify_totp_login(VerifyTotpLoginRequest { ... }).await
//!         }
//!         Err(e) => eprintln!("Login failed: {}", e),
//!     }
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
//!         "user_id": auth.user_id().to_string(),
//!         "email": auth.email()
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
//! | Variable | Alternative | Description | Required |
//! |----------|-------------|-------------|----------|
//! | `LOGIN_FLOW_URL` | `LOGIN_URL` | Base URL without version (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGIN_FLOW_VERSION` | `LOGIN_VERSION` | API version number (default: 1) | No |
//! | `LOGIN_FLOW_COMPANY` | `COMPANY` | Company UUID from LoginFlow | Yes |
//! | `LOGIN_FLOW_APPLICATION` | `APPLICATION` | Application UUID (expected `aud` of access tokens) | Yes |
//! | `LOGINFLOW_ISSUER` | - | Expected `iss` of tokens (e.g., `https://api.loginflow.dev`) | Yes |
//! | `LOGINFLOW_JWKS_URL` | - | JWKS endpoint (default: `{LOGIN_FLOW_URL}/oauth2/jwks`) | No |
//! | `LOGINFLOW_JWKS_CACHE_TTL_SECS` | - | JWKS cache lifetime in seconds (default: 600) | No |
//! | `LOGIN_FLOW_TIMEOUT` | - | Request timeout in seconds (default: 30) | No |
//! | `LOGINFLOW_USER_AGENT` | - | Custom User-Agent header | No |
//!
//! ## Feature Flags
//!
//! - `actix` (default): Enables Actix-web extractors
//! - `multi-tenant`: Enables multi-tenant support with dynamic company_id
//!
//! ```toml
//! [dependencies]
//! loginflow_sdk = { version = "0.5", features = ["multi-tenant"] }
//! ```

// Core modules
pub mod client;
pub mod config;
pub mod error;
mod http;
pub mod jwks;
pub mod models;
mod refresh_flight;

// Multi-tenant support (feature-gated)
#[cfg(feature = "multi-tenant")]
pub mod multi_tenant;

// Actix integration (feature-gated)
#[cfg(feature = "actix")]
pub mod actix;

// Re-exports for convenience
pub use client::LoginFlowClient;
pub use config::{ConfigError, LoginFlowConfig};
pub use error::{LoginFlowError, LoginFlowResult};
pub use jwks::JwksCache;

// Re-export commonly used models
pub use models::{
    // JWT
    ACCESS_TOKEN_TYPE,
    // Account Recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    ApplicationInfo,
    // Auth
    AuthenticatedUser,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    CompanyInfo,
    CompleteResetRequest,
    // Delegated Auth
    CreateDelegatedTokenRequest,
    CreateDelegatedTokenResponse,
    DisableTotpRequest,
    FlexibleDateTime,
    // User Account
    FullUserAccountResponse,
    JwtClaims,
    LoginFlowErrorDetail,
    LoginFlowErrorResponse,
    LoginRequest,
    LoginResponse,
    LoginResult,
    LogoutRequest,
    // OAuth
    OAuthLoginRequest,
    OperationResponse,
    // OTP
    OtpLoginRequest,
    OtpLoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    // Email Verification
    RequestEmailVerificationRequest,
    RequestEmailVerificationResponse,
    RequestOtpRequest,
    RequestOtpResponse,
    ResendVerificationRequest,
    ResponseMeta,
    SessionInfo,
    TotpChallengeResponse,
    // TOTP 2FA
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    UpdateUserAccountRequest,
    // User Profile
    UpdateUserProfileRequest,
    UserAccountResponse,
    UserInfo,
    UserProfileResponse,
    ValidateDelegatedTokenRequest,
    VerifyEmailRequest,
    VerifyResetCodeRequest,
    VerifyResetCodeResponse,
    VerifyTotpCodeRequest,
    VerifyTotpLoginRequest,
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

    pub use crate::models::{
        AuthenticatedUser, ChangePasswordRequest, CompleteResetRequest, LoginRequest, LoginResult,
        LogoutRequest, OAuthLoginRequest, OtpLoginRequest, RefreshTokenRequest, RegisterRequest,
        RequestOtpRequest, TotpChallengeResponse, UpdateUserAccountRequest,
        UpdateUserProfileRequest, VerifyResetCodeRequest, VerifyTotpLoginRequest,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
}

#[cfg(feature = "actix")]
pub use actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
