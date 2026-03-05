//! JWT extraction utilities for Actix-web

use actix_web::HttpRequest;
use actix_web::web;
use uuid::Uuid;

use crate::client::LoginFlowClient;
use crate::error::LoginFlowError;
use crate::models::{AuthenticatedUser, JwtClaims, decode_jwt_claims, verify_jwt_claims};

/// Extract Bearer token from Authorization header
///
/// # Arguments
/// * `req` - Actix HttpRequest
///
/// # Returns
/// The JWT token string without "Bearer " prefix
pub fn extract_token_from_request(req: &HttpRequest) -> Result<String, LoginFlowError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            log::warn!("Missing Authorization header");
            LoginFlowError::Authentication("Missing Authorization header".to_string())
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            log::warn!("Invalid Authorization header format");
            LoginFlowError::Authentication("Invalid Authorization header format. Expected 'Bearer <token>'".to_string())
        })?;

    Ok(token.to_string())
}

/// Extract and validate JWT claims from a token.
///
/// If a `LoginFlowClient` with `signing_secret` is registered in Actix app_data,
/// this verifies the HMAC-SHA256 signature. Otherwise falls back to decode-only.
fn extract_claims(req: &HttpRequest, token: &str) -> Result<JwtClaims, LoginFlowError> {
    // Try to get LoginFlowClient from app_data for signature verification
    if let Some(client) = req.app_data::<web::Data<LoginFlowClient>>()
        && client.can_verify_locally()
    {
        return client.verify_token(token);
    }

    // Fallback: decode without signature verification
    decode_jwt_claims(token)
        .map_err(|e| {
            log::error!("Failed to decode JWT: {}", e);
            LoginFlowError::Authentication(format!("Invalid token: {}", e))
        })
}

/// Extract authenticated user from request
///
/// When a `LoginFlowClient` with `signing_secret` is registered in Actix `app_data`,
/// this verifies the JWT signature (HMAC-SHA256) before extracting the user.
/// Without it, only decodes the payload (no signature validation).
///
/// # Arguments
/// * `req` - Actix HttpRequest
///
/// # Returns
/// AuthenticatedUser with user_id, email, role, company_id, application_id
pub fn extract_user_from_request(req: &HttpRequest) -> Result<AuthenticatedUser, LoginFlowError> {
    let token = extract_token_from_request(req)?;

    let claims = extract_claims(req, &token)?;

    // Validate user status is active (mirrors API jwt_middleware behavior)
    if !claims.is_active() {
        log::warn!("Rejected token for inactive user: {}", claims.user_id);
        return Err(LoginFlowError::Authentication("User account is not active".to_string()));
    }

    // Parse user_id as UUID
    let user_id = Uuid::parse_str(&claims.user_id)
        .map_err(|e| {
            log::error!("Invalid user_id format: {}", e);
            LoginFlowError::Authentication("Invalid user ID format in token".to_string())
        })?;

    // Parse company_id (use nil UUID if missing/invalid)
    let company_id = Uuid::parse_str(&claims.company_id)
        .unwrap_or_else(|_| Uuid::nil());

    // Parse application_id (use nil UUID if missing/invalid)
    let application_id = Uuid::parse_str(&claims.application_id)
        .unwrap_or_else(|_| Uuid::nil());

    log::info!("Extracted user from token: {} ({})", user_id, claims.email);

    Ok(AuthenticatedUser {
        user_id,
        email: claims.email,
        role: claims.role,
        company_id,
        application_id,
    })
}

/// Verify a JWT token directly using a signing_secret.
///
/// Standalone function for cases where you have the secret but no `LoginFlowClient`.
pub fn verify_token_with_secret(token: &str, signing_secret: &str) -> Result<AuthenticatedUser, LoginFlowError> {
    let claims = verify_jwt_claims(token, signing_secret)
        .map_err(|e| LoginFlowError::Authentication(e.to_string()))?;

    let user_id = Uuid::parse_str(&claims.user_id)
        .map_err(|_| LoginFlowError::ParseError("Invalid user_id format".to_string()))?;

    let company_id = Uuid::parse_str(&claims.company_id)
        .unwrap_or_else(|_| Uuid::nil());

    let application_id = Uuid::parse_str(&claims.application_id)
        .unwrap_or_else(|_| Uuid::nil());

    Ok(AuthenticatedUser {
        user_id,
        email: claims.email,
        role: claims.role,
        company_id,
        application_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    #[test]
    fn test_extract_token_missing_header() {
        let req = TestRequest::default().to_http_request();
        let result = extract_token_from_request(&req);
        assert!(matches!(result, Err(LoginFlowError::Authentication(_))));
    }

    #[test]
    fn test_extract_token_invalid_format() {
        let req = TestRequest::default()
            .insert_header(("Authorization", "Basic xxx"))
            .to_http_request();
        let result = extract_token_from_request(&req);
        assert!(matches!(result, Err(LoginFlowError::Authentication(_))));
    }

    #[test]
    fn test_extract_token_valid() {
        let req = TestRequest::default()
            .insert_header(("Authorization", "Bearer test-token"))
            .to_http_request();
        let result = extract_token_from_request(&req);
        assert_eq!(result.unwrap(), "test-token");
    }
}
