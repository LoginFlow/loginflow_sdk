//! Actix-web integration for LoginFlow SDK
//!
//! Provides extractors that verify LoginFlow access tokens. Register the
//! client once with `App::app_data(web::Data::new(client))`; without it every
//! extractor fails with a configuration error (HTTP 500).
//!
//! # Example
//! ```rust
//! use actix_web::{HttpResponse, post};
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

mod extractor;
mod middleware;

pub use extractor::{extract_token_from_request, extract_user_from_request, registered_client};
pub use middleware::{AdminAuth, AuthMiddleware, MasterAuth, OptionalAuth};
