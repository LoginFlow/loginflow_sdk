//! Token extraction and verification utilities for Actix-web

use actix_web::{HttpRequest, web};
use log::warn;

use crate::client::LoginFlowClient;
use crate::dpop::{VerifiedDpopProof, verify_proof_matches_cnf};
use crate::error::LoginFlowError;
use crate::models::{AuthenticatedUser, JwtClaims};

/// Request header carrying the RFC 9449 DPoP proof.
const DPOP_HEADER: &str = "DPoP";

/// Authorization scheme an access token was presented with (RFC 6750 / RFC 9449 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <token>`
    Bearer,
    /// `Authorization: DPoP <token>`, accompanied by a `DPoP` proof header
    Dpop,
}

/// The scheme and the raw token of an `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationHeader {
    pub scheme: AuthScheme,
    pub token: String,
}

/// Parse the `Authorization` header as `Bearer <token>` or `DPoP <token>` (scheme matched
/// case-insensitively). Any other scheme (e.g. `Basic`) is rejected.
///
/// # Errors
/// [`LoginFlowError::Authentication`] when the header is missing, not ASCII, uses another
/// scheme, or carries no token.
pub fn extract_authorization(req: &HttpRequest) -> Result<AuthorizationHeader, LoginFlowError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            warn!("Missing Authorization header");
            LoginFlowError::Authentication("Missing Authorization header".to_string())
        })?;

    let invalid_format = || {
        warn!("Invalid Authorization header format");
        LoginFlowError::Authentication(
            "Invalid Authorization header format. Expected 'Bearer <token>' or 'DPoP <token>'"
                .to_string(),
        )
    };
    let (scheme, token) = auth_header.split_once(' ').ok_or_else(invalid_format)?;
    let scheme = if scheme.eq_ignore_ascii_case("bearer") {
        AuthScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("dpop") {
        AuthScheme::Dpop
    } else {
        return Err(invalid_format());
    };
    let token = token.trim();
    if token.is_empty() {
        return Err(invalid_format());
    }
    Ok(AuthorizationHeader {
        scheme,
        token: token.to_string(),
    })
}

/// Extract the access token from the `Authorization` header (`Bearer` or `DPoP` scheme).
///
/// This only parses the header: it neither verifies the token nor enforces DPoP binding. Use
/// [`extract_user_from_request`] (or the extractors) for that.
///
/// # Returns
/// The token without the scheme prefix
pub fn extract_token_from_request(req: &HttpRequest) -> Result<String, LoginFlowError> {
    extract_authorization(req).map(|header| header.token)
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
/// Uses the `LoginFlowClient` registered in Actix `app_data`: ES256 signature via JWKS,
/// header `typ: at+jwt`, issuer, audience and expiration. The access token carries no account
/// status, so a revoked or deactivated account still passes until the token expires; for a
/// sensitive operation also call `IntrospectionClient::introspect_cached`.
///
/// DPoP (RFC 9449 §7.1): a DPoP-bound token (`cnf.jkt`) is only accepted under the `DPoP`
/// scheme with a `DPoP` proof signed by that key for this request's method and URL and bound to
/// this token (`ath`); a token without `cnf` is only accepted under `Bearer`. Single-use `jti`
/// enforcement (replay protection) is the caller's job: the SDK holds no storage. Read the
/// verified proof from [`crate::actix::AuthMiddleware::dpop_proof`] and reject a `jti` already
/// seen within [`crate::dpop::MAX_PROOF_AGE_SECS`].
pub async fn extract_user_from_request(
    req: &HttpRequest,
) -> Result<AuthenticatedUser, LoginFlowError> {
    verify_request(req).await.map(|verified| verified.user)
}

/// Outcome of [`verify_request`].
pub(crate) struct VerifiedRequest {
    pub user: AuthenticatedUser,
    pub token: String,
    pub dpop_proof: Option<VerifiedDpopProof>,
}

/// Verify the request's token and its DPoP binding.
pub(crate) async fn verify_request(req: &HttpRequest) -> Result<VerifiedRequest, LoginFlowError> {
    let client = registered_client(req)?;
    let authorization = extract_authorization(req)?;
    let claims = client
        .verify_token(&authorization.token)
        .await
        .inspect_err(|e| warn!("Authentication failed: {}", e))?;
    let dpop_proof = verify_binding(req, &client, &claims, &authorization)
        .inspect_err(|e| warn!("Authentication failed: {}", e))?;
    Ok(VerifiedRequest {
        user: AuthenticatedUser::from_claims(&claims),
        token: authorization.token,
        dpop_proof,
    })
}

/// RFC 9449 §7.1 scheme/binding matrix for a verified token.
fn verify_binding(
    req: &HttpRequest,
    client: &LoginFlowClient,
    claims: &JwtClaims,
    authorization: &AuthorizationHeader,
) -> Result<Option<VerifiedDpopProof>, LoginFlowError> {
    match (claims.cnf.as_ref(), authorization.scheme) {
        (None, AuthScheme::Bearer) => Ok(None),
        (None, AuthScheme::Dpop) => Err(LoginFlowError::Authentication(
            "the access token is not DPoP-bound: present it with the Bearer scheme".to_string(),
        )),
        (Some(_), AuthScheme::Bearer) => Err(LoginFlowError::Authentication(
            "a DPoP-bound access token must be presented with the DPoP scheme".to_string(),
        )),
        (Some(cnf), AuthScheme::Dpop) => {
            let proof = single_dpop_header(req)?;
            let htu = request_htu(req, client.config().resource_base_url.as_deref());
            verify_proof_matches_cnf(
                proof,
                req.method().as_str(),
                &htu,
                &authorization.token,
                &cnf.jkt,
            )
            .map(Some)
            .map_err(|e| LoginFlowError::Authentication(format!("Invalid DPoP proof: {e}")))
        }
    }
}

/// The one `DPoP` header value (RFC 9449 §4.3 check 1: not more than one).
fn single_dpop_header(req: &HttpRequest) -> Result<&str, LoginFlowError> {
    let mut values = req.headers().get_all(DPOP_HEADER);
    let missing = || LoginFlowError::Authentication("Missing or invalid DPoP header".to_string());
    let proof = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or_else(missing)?;
    if values.next().is_some() {
        return Err(LoginFlowError::Authentication(
            "More than one DPoP header".to_string(),
        ));
    }
    Ok(proof)
}

/// The request URL a proof's `htu` must name: `resource_base_url` + path when configured,
/// otherwise the connection's scheme + host + path. Never the query string (RFC 9449 §4.3).
fn request_htu(req: &HttpRequest, resource_base_url: Option<&str>) -> String {
    match resource_base_url {
        Some(base) => format!("{}{}", base.trim_end_matches('/'), req.path()),
        None => {
            let info = req.connection_info();
            format!("{}://{}{}", info.scheme(), info.host(), req.path())
        }
    }
}
