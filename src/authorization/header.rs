//! The `Authorization` header of a resource request (RFC 6750 / RFC 9449 §7.1).

use crate::error::LoginFlowError;

/// Authorization scheme an access token was presented with.
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
    /// `Bearer` or `DPoP`.
    pub scheme: AuthScheme,
    /// The raw access token.
    pub token: String,
}

/// Parse an `Authorization` header value as `Bearer <token>` or `DPoP <token>` (scheme matched
/// case-insensitively). Any other scheme (e.g. `Basic`) is rejected.
///
/// # Errors
/// [`LoginFlowError::Authentication`] for another scheme or no token.
pub fn parse_authorization(value: &str) -> Result<AuthorizationHeader, LoginFlowError> {
    let invalid_format = || {
        LoginFlowError::authentication(
            "Invalid Authorization header format. Expected 'Bearer <token>' or 'DPoP <token>'",
        )
    };
    let (scheme, token) = value.split_once(' ').ok_or_else(invalid_format)?;
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
