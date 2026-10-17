//! Authentication middleware for Actix-web
//!
//! Provides a `FromRequest` extractor that automatically extracts and validates
//! the authenticated user from the JWT token in the Authorization header.

use std::future::Future;
use std::pin::Pin;

use actix_web::error::ErrorForbidden;
use actix_web::{Error, FromRequest, HttpRequest, dev::Payload};
use log::warn;
use uuid::Uuid;

use super::extractor::verify_request;
use crate::error::LoginFlowError;
use crate::models::AuthenticatedUser;

/// Authentication middleware extractor for Actix-web
///
/// Verifies the access token in the Authorization header with the
/// `LoginFlowClient` registered in `app_data` (ES256 signature via JWKS,
/// issuer, audience, expiration) and exposes the authenticated user. The
/// access token carries no email: resolve one, when actually needed, through
/// [`crate::LoginFlowClient::userinfo`] instead.
///
/// # Example
/// ```rust
/// use actix_web::{post, HttpResponse};
/// use loginflow_sdk::actix::AuthMiddleware;
///
/// #[post("/create")]
/// pub async fn create_resource(auth: AuthMiddleware) -> HttpResponse {
///     let company_user_id = auth.company_user_id();
///
///     HttpResponse::Ok().json(serde_json::json!({
///         "created_by": company_user_id.to_string(),
///     }))
/// }
/// ```
///
/// # Error Response
/// - 500 if no `LoginFlowClient` is registered in `app_data` (configuration error)
/// - 401 if the Authorization header is missing or the token fails verification
/// - 503 if the signing keys (JWKS) cannot be obtained
pub struct AuthMiddleware {
    user: AuthenticatedUser,
    token: String,
}

impl AuthMiddleware {
    /// Get the authenticated user's `company_users` id (the token's `sub`).
    pub fn company_user_id(&self) -> Uuid {
        self.user.company_user_id
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
        Box::pin(async move { authenticate(&req).await.map_err(Error::from) })
    }
}

/// Verify the request's token with the registered client.
async fn authenticate(req: &HttpRequest) -> Result<AuthMiddleware, LoginFlowError> {
    let (user, token) = verify_request(req).await?;
    Ok(AuthMiddleware { user, token })
}

/// Admin authentication middleware extractor
///
/// Like `AuthMiddleware` but additionally requires the user to have
/// `app_admin` or `master` role. Returns 403 Forbidden if the role check fails.
pub struct AdminAuth {
    inner: AuthMiddleware,
}

impl AdminAuth {
    pub fn company_user_id(&self) -> Uuid {
        self.inner.company_user_id()
    }
    pub fn role(&self) -> &str {
        self.inner.role()
    }
    pub fn company_id(&self) -> Uuid {
        self.inner.company_id()
    }
    pub fn application_id(&self) -> Uuid {
        self.inner.application_id()
    }
    pub fn user(&self) -> &AuthenticatedUser {
        self.inner.user()
    }
    pub fn token(&self) -> &str {
        self.inner.token()
    }
}

impl FromRequest for AdminAuth {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = AuthMiddleware::from_request(req, payload);

        Box::pin(async move {
            let auth = fut.await?;
            if !auth.is_admin() {
                warn!(
                    "AdminAuth: insufficient role '{}' for user {}",
                    auth.role(),
                    auth.company_user_id()
                );
                return Err(ErrorForbidden(
                    "Insufficient permissions: admin role required",
                ));
            }
            Ok(AdminAuth { inner: auth })
        })
    }
}

/// Master authentication middleware extractor
///
/// Like `AuthMiddleware` but additionally requires the user to have
/// `master` role. Returns 403 Forbidden if the role check fails.
pub struct MasterAuth {
    inner: AuthMiddleware,
}

impl MasterAuth {
    pub fn company_user_id(&self) -> Uuid {
        self.inner.company_user_id()
    }
    pub fn role(&self) -> &str {
        self.inner.role()
    }
    pub fn company_id(&self) -> Uuid {
        self.inner.company_id()
    }
    pub fn application_id(&self) -> Uuid {
        self.inner.application_id()
    }
    pub fn user(&self) -> &AuthenticatedUser {
        self.inner.user()
    }
    pub fn token(&self) -> &str {
        self.inner.token()
    }
}

impl FromRequest for MasterAuth {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = AuthMiddleware::from_request(req, payload);

        Box::pin(async move {
            let auth = fut.await?;
            if !auth.is_master() {
                warn!(
                    "MasterAuth: insufficient role '{}' for user {}",
                    auth.role(),
                    auth.company_user_id()
                );
                return Err(ErrorForbidden(
                    "Insufficient permissions: master role required",
                ));
            }
            Ok(MasterAuth { inner: auth })
        })
    }
}

/// Optional authentication middleware
///
/// Like `AuthMiddleware` but yields no user instead of a 401 when the header
/// is missing or the token is rejected. Useful for endpoints that work both
/// authenticated and unauthenticated. Configuration errors (no registered
/// `LoginFlowClient`) and JWKS outages are still returned as errors.
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
///             "company_user_id": user.company_user_id.to_string()
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
            match authenticate(&req).await {
                Ok(auth) => Ok(OptionalAuth { inner: Some(auth) }),
                Err(LoginFlowError::Authentication(_)) => Ok(OptionalAuth { inner: None }),
                Err(err) => Err(Error::from(err)),
            }
        })
    }
}
