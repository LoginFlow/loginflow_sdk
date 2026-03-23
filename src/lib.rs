//! # LoginFlow SDK
//!
//! A Rust SDK for integrating with the LoginFlow authentication service.
//!
//! ## Features
//!
//! - **Authentication**: Register, login, logout
//! - **TOTP 2FA**: Optional time-based one-time password for two-factor authentication
//! - **Session Refresh**: Refresh access token with refresh token + session ID
//! - **Password Management**: Reset password (3-step flow), change password
//! - **Email Verification**: Verify user email with code
//! - **JWT Handling**: Decode and extract user information from JWT tokens
//! - **Actix-web Integration**: Ready-to-use middleware and extractors (feature: `actix`)
//!
//! ## Quick Start
//!
//! ### From Environment Variables
//!
//! ```rust,no_run
//! use loginflow_sdk::LoginFlowClient;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Set these environment variables:
//!     // LOGIN_FLOW_URL or LOGIN_URL
//!     // LOGIN_FLOW_COMPANY or COMPANY
//!     // LOGIN_FLOW_APPLICATION or APPLICATION
//!
//!     let client = LoginFlowClient::from_env().expect("Failed to create client");
//! }
//! ```
//!
//! ### With Explicit Configuration
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = LoginFlowClient::new(LoginFlowConfig {
//!         base_url: "https://your-loginflow-server.com".into(),
//!         api_version: 1,
//!         company_id: "your-company-uuid".into(),
//!         application_id: "your-app-uuid".into(),
//!         timeout_secs: 30,
//!         user_agent: None,
//!         signing_secret: Some("your-signing-secret".into()), // enables local JWT verification
//!     }).expect("Failed to create client");
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
//!             println!("JWT: {}", response.jwt);
//!             println!("User: {:?}", response.user);
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
//! ```rust,no_run
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
//!     let client = LoginFlowClient::from_env().unwrap();
//!
//!     HttpServer::new(move || {
//!         App::new()
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
//! | `LOGIN_FLOW_URL` | `LOGIN_URL` | Base URL without version (e.g., `https://your-loginflow-server.com`) | Yes |
//! | `LOGIN_FLOW_VERSION` | `LOGIN_VERSION` | API version number (default: 1) | No |
//! | `LOGIN_FLOW_COMPANY` | `COMPANY` | Company UUID from LoginFlow | Yes |
//! | `LOGIN_FLOW_APPLICATION` | `APPLICATION` | Application UUID from LoginFlow | Yes |
//! | `LOGIN_FLOW_TIMEOUT` | - | Request timeout in seconds (default: 30) | No |
//! | `LOGINFLOW_USER_AGENT` | - | Custom User-Agent header | No |
//! | `LOGINFLOW_SIGNING_SECRET` | - | Per-app signing secret for local JWT verification | No |
//!
//! ## Feature Flags
//!
//! - `actix` (default): Enables Actix-web middleware and extractors
//! - `multi-tenant`: Enables multi-tenant support with dynamic company_id
//!
//! To disable actix support:
//! ```toml
//! [dependencies]
//! loginflow_sdk = { version = "0.1", default-features = false }
//! ```
//!
//! To enable multi-tenant support:
//! ```toml
//! [dependencies]
//! loginflow_sdk = { version = "0.1", features = ["multi-tenant"] }
//! ```
//!
//! ### Multi-tenant Usage
//!
//! For applications where each user may belong to different companies:
//!
//! ```rust,ignore
//! use loginflow_sdk::{LoginFlowClient, LoginResult};
//! use loginflow_sdk::multi_tenant::{MultiTenantLoginRequest, MultiTenantExt};
//!
//! async fn login_to_company(client: &LoginFlowClient, email: &str, password: &str, company_id: &str) {
//!     let request = MultiTenantLoginRequest {
//!         email: email.to_string(),
//!         password: password.to_string(),
//!         company_id: company_id.to_string(),
//!     };
//!
//!     match client.login_with_company(request).await {
//!         Ok(LoginResult::Success(response)) => println!("Logged in: {}", response.user.id),
//!         Ok(LoginResult::TotpRequired(_)) => println!("2FA required"),
//!         Err(e) => eprintln!("Login failed: {}", e),
//!     }
//! }
//! ```

// Core modules
pub mod config;
pub mod error;
pub mod client;
pub mod models;

// Multi-tenant support (feature-gated)
#[cfg(feature = "multi-tenant")]
pub mod multi_tenant;

// Actix integration (feature-gated)
#[cfg(feature = "actix")]
pub mod actix;

// Re-exports for convenience
pub use config::{LoginFlowConfig, ConfigError};
pub use error::{LoginFlowError, LoginFlowResult};
pub use client::LoginFlowClient;

// Re-export commonly used models
pub use models::{
    // Auth
    RegisterRequest, RegisterResponse,
    LoginRequest, LoginResponse, LoginResult,
    LogoutRequest, RefreshTokenRequest, RefreshTokenResponse,
    VerifyEmailRequest, ResendVerificationRequest,
    AuthenticatedUser,
    UserInfo, CompanyInfo, SessionInfo, ApplicationInfo,
    ResponseMeta, LoginFlowErrorResponse, LoginFlowErrorDetail,

    // OAuth
    OAuthLoginRequest,

    // OTP
    RequestOtpRequest, RequestOtpResponse,
    OtpLoginRequest, OtpLoginResponse,
    RequestPasswordlessCodeRequest, RequestPasswordlessCodeResponse,
    PasswordlessAuthRequest, PasswordlessAuthResponse,

    // TOTP 2FA
    TotpSetupResponse, TotpChallengeResponse, TotpStatusResponse,
    VerifyTotpSetupRequest, VerifyTotpLoginRequest, DisableTotpRequest,

    // Password
    ResetPasswordRequest, VerifyResetCodeRequest, VerifyResetCodeResponse,
    CompleteResetRequest, ChangePasswordRequest, ChangePasswordResponse,
    MessageResponse,

    // JWT
    JwtClaims, JwtDecodeError, decode_jwt_claims, verify_jwt_claims,

    // User Account
    FullUserAccountResponse, UserAccountResponse, UpdateUserAccountRequest, OperationResponse,

    // User Profile
    UserProfileResponse, UpdateUserProfileRequest,

    // Delegated Auth
    CreateDelegatedTokenRequest, CreateDelegatedTokenResponse, ValidateDelegatedTokenRequest,

    // Account Recovery
    AccountRecoveryRequest, AccountRecoveryResponse,

    // Email Verification
    RequestEmailVerificationRequest, RequestEmailVerificationResponse,
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
        RegisterRequest, LoginRequest, LoginResult, LogoutRequest, RefreshTokenRequest,
        AuthenticatedUser,
        RequestOtpRequest, OtpLoginRequest,
        RequestPasswordlessCodeRequest, PasswordlessAuthRequest,
        OAuthLoginRequest,
        VerifyTotpLoginRequest, TotpChallengeResponse,
        ResetPasswordRequest, VerifyResetCodeRequest, CompleteResetRequest,
        ChangePasswordRequest,
        UpdateUserAccountRequest, UpdateUserProfileRequest,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
}

#[cfg(feature = "actix")]
pub use actix::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
