//! Authentication middleware for Actix-web
//!
//! Provides a `FromRequest` extractor that automatically extracts and validates
//! the authenticated user from the JWT token in the Authorization header.

use actix_web::{dev::Payload, error::ErrorUnauthorized, Error, FromRequest, HttpRequest};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

use crate::models::AuthenticatedUser;
use super::extractor::extract_user_from_request;

/// Authentication middleware extractor for Actix-web
///
/// Automatically extracts the authenticated user from the JWT token
/// in the Authorization header.
///
/// # Example
/// ```rust
/// use actix_web::{post, HttpResponse};
/// use loginflow_sdk::actix::AuthMiddleware;
///
/// #[post("/create")]
/// pub async fn create_resource(auth: AuthMiddleware) -> HttpResponse {
///     let user_id = auth.user_id();
///     let email = auth.email();
///
///     HttpResponse::Ok().json(serde_json::json!({
///         "created_by": user_id.to_string(),
///         "email": email
///     }))
/// }
/// ```
///
/// # Error Response
/// Returns 401 Unauthorized if:
/// - Authorization header is missing
/// - Token format is invalid
/// - Token cannot be decoded
pub struct AuthMiddleware {
    user: AuthenticatedUser,
    token: String,
}

impl AuthMiddleware {
    /// Get the authenticated user's ID
    pub fn user_id(&self) -> Uuid {
        self.user.user_id
    }

    /// Get the authenticated user's email
    pub fn email(&self) -> &str {
        &self.user.email
    }

    /// Get the authenticated user's role
    pub fn role(&self) -> &str {
        &self.user.role
    }

    /// Get the user's company ID
    pub fn company_id(&self) -> Uuid {
        self.user.company_id
    }

    /// Get the user's application ID
    pub fn application_id(&self) -> Uuid {
        self.user.application_id
    }

    /// Get the full authenticated user struct
    pub fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    /// Get the raw JWT token (useful for forwarding to other services)
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.user.is_admin()
    }

    /// Check if user has master role
    pub fn is_master(&self) -> bool {
        self.user.is_master()
    }
}

impl FromRequest for AuthMiddleware {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            // Extract token from header
            let token = super::extractor::extract_token_from_request(&req)
                .map_err(|e| {
                    log::error!("Authentication failed: {}", e);
                    ErrorUnauthorized(e.to_string())
                })?;

            // Extract user from token
            let user = extract_user_from_request(&req)
                .map_err(|e| {
                    log::error!("Authentication failed: {}", e);
                    ErrorUnauthorized(e.to_string())
                })?;

            Ok(AuthMiddleware { user, token })
        })
    }
}

/// Optional authentication middleware
///
/// Like `AuthMiddleware` but returns `None` instead of an error
/// when authentication fails. Useful for endpoints that work both
/// authenticated and unauthenticated.
///
/// # Example
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use loginflow_sdk::actix::OptionalAuth;
///
/// #[get("/profile")]
/// pub async fn get_profile(auth: OptionalAuth) -> HttpResponse {
///     if let Some(user) = auth.user() {
///         HttpResponse::Ok().json(serde_json::json!({
///             "authenticated": true,
///             "user_id": user.user_id.to_string()
///         }))
///     } else {
///         HttpResponse::Ok().json(serde_json::json!({
///             "authenticated": false
///         }))
///     }
/// }
/// ```
pub struct OptionalAuth {
    inner: Option<AuthMiddleware>,
}

impl OptionalAuth {
    /// Get the authenticated user if present
    pub fn user(&self) -> Option<&AuthenticatedUser> {
        self.inner.as_ref().map(|a| a.user())
    }

    /// Get the token if present
    pub fn token(&self) -> Option<&str> {
        self.inner.as_ref().map(|a| a.token())
    }

    /// Check if user is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.inner.is_some()
    }
}

impl FromRequest for OptionalAuth {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            // Try to extract token
            let token = match super::extractor::extract_token_from_request(&req) {
                Ok(t) => t,
                Err(_) => return Ok(OptionalAuth { inner: None }),
            };

            // Try to extract user
            let user = match extract_user_from_request(&req) {
                Ok(u) => u,
                Err(_) => return Ok(OptionalAuth { inner: None }),
            };

            Ok(OptionalAuth {
                inner: Some(AuthMiddleware { user, token }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use actix_web::FromRequest;

    #[actix_web::test]
    async fn test_auth_middleware_missing_header() {
        let req = TestRequest::default().to_http_request();
        let mut payload = Payload::None;

        let result = AuthMiddleware::from_request(&req, &mut payload).await;
        assert!(result.is_err());
    }

    #[actix_web::test]
    async fn test_optional_auth_missing_header() {
        let req = TestRequest::default().to_http_request();
        let mut payload = Payload::None;

        let result = OptionalAuth::from_request(&req, &mut payload).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_authenticated());
    }
}
