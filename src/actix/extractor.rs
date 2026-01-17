//! JWT extraction utilities for Actix-web

use actix_web::HttpRequest;
use uuid::Uuid;

use crate::error::LoginFlowError;
use crate::models::{AuthenticatedUser, decode_jwt_claims};

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
            log::warn!("❌ Missing Authorization header");
            LoginFlowError::Authentication("Missing Authorization header".to_string())
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            log::warn!("❌ Invalid Authorization header format");
            LoginFlowError::Authentication("Invalid Authorization header format. Expected 'Bearer <token>'".to_string())
        })?;

    Ok(token.to_string())
}

/// Extract authenticated user from request
///
/// This extracts the JWT from the Authorization header and decodes it
/// to get the user information.
///
/// # Warning
/// This decodes the token without validating the signature.
/// For production use with untrusted tokens, consider validating with LoginFlow's /validate endpoint.
///
/// # Arguments
/// * `req` - Actix HttpRequest
///
/// # Returns
/// AuthenticatedUser with user_id, email, role, company_id, application_id
pub fn extract_user_from_request(req: &HttpRequest) -> Result<AuthenticatedUser, LoginFlowError> {
    let token = extract_token_from_request(req)?;

    // Decode JWT claims
    let claims = decode_jwt_claims(&token)
        .map_err(|e| {
            log::error!("❌ Failed to decode JWT: {}", e);
            LoginFlowError::Authentication(format!("Invalid token: {}", e))
        })?;

    // Parse user_id as UUID
    let user_id = Uuid::parse_str(&claims.user_id)
        .map_err(|e| {
            log::error!("❌ Invalid user_id format: {}", e);
            LoginFlowError::Authentication("Invalid user ID format in token".to_string())
        })?;

    // Parse company_id (use nil UUID if missing/invalid)
    let company_id = Uuid::parse_str(&claims.company_id)
        .unwrap_or_else(|_| Uuid::nil());

    // Parse application_id (use nil UUID if missing/invalid)
    let application_id = Uuid::parse_str(&claims.application_id)
        .unwrap_or_else(|_| Uuid::nil());

    log::info!("✅ Extracted user from token: {} ({})", user_id, claims.email);

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
