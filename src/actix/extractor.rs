//! Token extraction and verification utilities for Actix-web

use actix_web::{HttpRequest, web};
use log::warn;

use crate::client::LoginFlowClient;
use crate::error::LoginFlowError;
use crate::models::AuthenticatedUser;

/// Extract the Bearer token from the Authorization header
///
/// # Returns
/// The token without the "Bearer " prefix
pub fn extract_token_from_request(req: &HttpRequest) -> Result<String, LoginFlowError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            warn!("Missing Authorization header");
            LoginFlowError::Authentication("Missing Authorization header".to_string())
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        warn!("Invalid Authorization header format");
        LoginFlowError::Authentication(
            "Invalid Authorization header format. Expected 'Bearer <token>'".to_string(),
        )
    })?;

    Ok(token.to_string())
}

/// The `LoginFlowClient` registered with `App::app_data(web::Data::new(client))`.
///
/// # Errors
/// [`LoginFlowError::Config`] (HTTP 500) when no client is registered: tokens
/// are never decoded without verifying them.
pub fn registered_client(req: &HttpRequest) -> Result<web::Data<LoginFlowClient>, LoginFlowError> {
    req.app_data::<web::Data<LoginFlowClient>>().cloned().ok_or_else(|| {
        LoginFlowError::Config(
            "LoginFlowClient is not registered: add App::app_data(web::Data::new(client)) to verify tokens".to_string(),
        )
    })
}

/// Verify the request's access token and return the authenticated user.
///
/// Uses the `LoginFlowClient` registered in Actix `app_data` (ES256 via JWKS,
/// issuer, audience, expiration, `token_type == "access"`, active status).
pub async fn extract_user_from_request(
    req: &HttpRequest,
) -> Result<AuthenticatedUser, LoginFlowError> {
    verify_request(req).await.map(|(user, _)| user)
}

/// Verify the request's token; returns the user and the raw token.
pub(crate) async fn verify_request(
    req: &HttpRequest,
) -> Result<(AuthenticatedUser, String), LoginFlowError> {
    let client = registered_client(req)?;
    let token = extract_token_from_request(req)?;
    let user = client
        .extract_user_from_token(&token)
        .await
        .inspect_err(|e| warn!("Authentication failed: {}", e))?;
    Ok((user, token))
}
