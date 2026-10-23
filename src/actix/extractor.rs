//! `Authorization` header extraction for Actix-web.

use actix_web::HttpRequest;
use log::warn;

use crate::authorization::header::{AuthorizationHeader, parse_authorization};
use crate::error::LoginFlowError;

/// Parse the request's `Authorization` header as `Bearer <token>` or `DPoP <token>` (scheme
/// matched case-insensitively). Any other scheme (e.g. `Basic`) is rejected.
///
/// # Errors
/// [`LoginFlowError::Authentication`] when the header is missing, not ASCII, uses another
/// scheme, or carries no token.
pub fn extract_authorization(req: &HttpRequest) -> Result<AuthorizationHeader, LoginFlowError> {
    let value = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            warn!("Missing Authorization header");
            LoginFlowError::Authentication("Missing Authorization header".to_string())
        })?;
    parse_authorization(value).inspect_err(|_| warn!("Invalid Authorization header format"))
}

/// The access token of the `Authorization` header (`Bearer` or `DPoP` scheme), e.g. to forward
/// it to another service. This only parses the header: verification is the permission gate's
/// ([`crate::actix::BuiltRouter::gate`]).
pub fn extract_token_from_request(req: &HttpRequest) -> Result<String, LoginFlowError> {
    extract_authorization(req).map(|header| header.token)
}
