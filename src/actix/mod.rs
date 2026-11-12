//! Actix-web integration: every route of the API is declared in a [`PermissionRouter`] with
//! the permission it requires (or as public), and the [`PermissionGate`] it builds verifies
//! each request before any handler runs.
//!
//! - A request whose route (method + matched pattern) is not in the table is refused with
//!   `403 permission_unmapped`: a route registered outside the router is denied by default.
//! - A public route passes without a token.
//! - Any other request needs a verified access token for this API ([`crate::TokenVerifier`]),
//!   an active organization (`403 organization_required`) and the route's permission there
//!   (`403 permission_denied`); the handler then reads the caller from [`Authorized`].
//! - A route declared with [`PermissionRouter::signed_in`] verifies the token the same way but
//!   requires no organization and no permission: any signed-in person of the application passes
//!   (e.g. to found their first organization), a machine token is `403 machine_not_allowed` and
//!   an access-code subject's `403 access_subject_not_allowed`. Its handler reads [`SignedIn`].
//! - A machine token (another system, [`crate::models::AccessClaims::is_machine`]) passes only
//!   a route declared with [`PermissionRouter::machine`] or [`PermissionRouter::person_or_machine`]
//!   (`403 machine_not_allowed` elsewhere), with the route's permission and no organization; its
//!   handler reads [`MachineAuthorized`] or [`Caller`]. A person's token on a machine-only route
//!   is `403 person_not_allowed`.
//!
//! # Example
//! ```rust,no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use actix_web::http::Method;
//! use actix_web::{App, HttpResponse, HttpServer};
//! use loginflow_sdk::actix::{Authorized, PermissionRouter};
//! use loginflow_sdk::{
//!     InMemoryJtiReplayCache, IntrospectionClient, LoginFlowClient, PermissionManifest,
//!     TokenVerifier,
//! };
//!
//! async fn list_drivers(auth: Authorized) -> HttpResponse {
//!     // Filter by the token's organization, never by an id from the body.
//!     HttpResponse::Ok().json(serde_json::json!({ "org": auth.org_id() }))
//! }
//!
//! async fn health() -> HttpResponse {
//!     HttpResponse::Ok().finish()
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let manifest =
//!         PermissionManifest::load(Path::new("permissions.yaml")).map_err(std::io::Error::other)?;
//!     let client = LoginFlowClient::from_env().map_err(std::io::Error::other)?;
//!     let discovery = client.discovery().await.map_err(std::io::Error::other)?.clone();
//!     let introspection = IntrospectionClient::from_discovery(
//!         reqwest::Client::new(), &discovery, "rutafacil-api", "client-secret",
//!     );
//!     let verifier = Arc::new(TokenVerifier::new(
//!         client, Arc::new(InMemoryJtiReplayCache::new()), introspection,
//!     ));
//!     let router = PermissionRouter::new(Arc::new(manifest))
//!         .public(Method::GET, "/health", health)
//!         .route(Method::GET, "/drivers", "rutafacil.drivers.list", list_drivers)
//!         .build()
//!         .map_err(std::io::Error::other)?;
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .wrap(router.gate(verifier.clone()))
//!             .configure(|cfg| router.configure(cfg))
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```

mod authorized;
mod extractor;
mod gate;
mod router;

pub use crate::authorization::header::{AuthScheme, AuthorizationHeader};
pub use authorized::{AccessDenied, Authorized, Caller, MachineAuthorized, SignedIn};
pub use extractor::{extract_authorization, extract_token_from_request};
pub use gate::{PermissionGate, PermissionGateMiddleware};
pub use router::{BuiltRouter, PermissionRouter, RouteAccess, RouteMapError};
