//! # LoginFlow SDK
//!
//! A Rust SDK for integrating with the LoginFlow authentication service.
//!
//! ## Features
//!
//! - **Authentication**: Register, login, logout
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
//!     // LOGINFLOW_URL or LOGIN_URL
//!     // LOGINFLOW_COMPANY or COMPANY
//!     // LOGINFLOW_APPLICATION or APPLICATION
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
//!     }).expect("Failed to create client");
//! }
//! ```
//!
//! ### Login Example
//!
//! ```rust,no_run
//! use loginflow_sdk::{LoginFlowClient, LoginRequest};
//!
//! async fn login_user(client: &LoginFlowClient, email: &str, password: &str) {
//!     let response = client.login(LoginRequest {
//!         email: email.to_string(),
//!         password: password.to_string(),
//!     }).await;
//!
//!     match response {
//!         Ok(login_response) => {
//!             println!("JWT: {}", login_response.jwt);
//!             println!("User: {:?}", login_response.user);
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
//! | `LOGINFLOW_URL` | `LOGIN_URL` | Base URL without version (e.g., `https://your-loginflow-server.com`) | Yes |
//! | `LOGINFLOW_VERSION` | `LOGIN_VERSION` | API version number (default: 1) | No |
//! | `LOGINFLOW_COMPANY` | `COMPANY` | Company UUID from LoginFlow | Yes |
//! | `LOGINFLOW_APPLICATION` | `APPLICATION` | Application UUID from LoginFlow | Yes |
//! | `LOGINFLOW_TIMEOUT` | - | Request timeout in seconds (default: 30) | No |
//! | `LOGINFLOW_USER_AGENT` | - | Custom User-Agent header | No |
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
//! ```rust,no_run
//! use loginflow_sdk::LoginFlowClient;
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
//!         Ok(response) => println!("Logged in: {}", response.user.id),
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
    LoginRequest, LoginResponse,
    LogoutRequest, VerifyEmailRequest,
    AuthenticatedUser,
    UserInfo, CompanyInfo, SessionInfo, ApplicationInfo,

    // Password
    ResetPasswordRequest, VerifyResetCodeRequest, VerifyResetCodeResponse,
    CompleteResetRequest, ChangePasswordRequest, ChangePasswordResponse,
    MessageResponse,

    // JWT
    JwtClaims, JwtDecodeError, decode_jwt_claims,

    // User Account
    FullUserAccountResponse, UserAccountResponse, UpdateUserAccountRequest, OperationResponse,

    // User Profile
    UserProfileResponse, UpdateUserProfileRequest,
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
        RegisterRequest, LoginRequest, LogoutRequest,
        AuthenticatedUser,
        ResetPasswordRequest, VerifyResetCodeRequest, CompleteResetRequest,
        ChangePasswordRequest,
        UpdateUserAccountRequest, UpdateUserProfileRequest,
    };

    #[cfg(feature = "actix")]
    pub use crate::actix::{AuthMiddleware, OptionalAuth};
}

#[cfg(feature = "actix")]
pub use actix::{AuthMiddleware, OptionalAuth};
