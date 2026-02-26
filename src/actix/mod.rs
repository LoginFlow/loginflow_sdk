//! Actix-web integration for LoginFlow SDK
//!
//! Provides middleware and extractors for easy integration with Actix-web applications.
//!
//! # Example
//! ```rust
//! use actix_web::{web, App, HttpServer, HttpResponse, post};
//! use loginflow_sdk::actix::AuthMiddleware;
//!
//! #[post("/protected")]
//! async fn protected(auth: AuthMiddleware) -> HttpResponse {
//!     HttpResponse::Ok().json(serde_json::json!({
//!         "user_id": auth.user_id().to_string(),
//!         "email": auth.email()
//!     }))
//! }
//! ```

mod middleware;
mod extractor;

pub use middleware::{AuthMiddleware, OptionalAuth};
pub use extractor::{extract_token_from_request, extract_user_from_request, verify_token_with_secret};
