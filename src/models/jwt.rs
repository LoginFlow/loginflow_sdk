//! JWT-related models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// JWT claims structure from LoginFlow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// User ID (UUID string)
    pub user_id: String,
    /// User email
    #[serde(default)]
    pub email: String,
    /// User role (user, app_admin, master)
    #[serde(default = "default_role")]
    pub role: String,
    /// Company ID (UUID string)
    #[serde(default)]
    pub company_id: String,
    /// Application ID (UUID string)
    #[serde(default)]
    pub application_id: String,
    /// Issued at timestamp (Unix epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Expiration timestamp (Unix epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

fn default_role() -> String {
    "user".to_string()
}

impl JwtClaims {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            exp < now
        } else {
            false
        }
    }

    /// Get remaining validity in seconds
    pub fn remaining_validity(&self) -> Option<i64> {
        self.exp.map(|exp| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            exp - now
        })
    }
}

/// Decode JWT claims without signature validation
///
/// # Warning
/// This only decodes the payload without validating the signature.
/// For production use with untrusted tokens, consider validating with LoginFlow's /validate endpoint.
pub fn decode_jwt_claims(token: &str) -> Result<JwtClaims, JwtDecodeError> {
    use base64::{engine::general_purpose, Engine as _};

    // Split JWT into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(JwtDecodeError::InvalidFormat(
            "JWT must have 3 parts separated by dots".into(),
        ));
    }

    // Decode payload (second part)
    let payload = parts[1];
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| JwtDecodeError::Base64Error(e.to_string()))?;

    let payload_str = String::from_utf8(decoded)
        .map_err(|e| JwtDecodeError::Utf8Error(e.to_string()))?;

    // Parse JSON
    let claims: JwtClaims = serde_json::from_str(&payload_str)
        .map_err(|e| JwtDecodeError::JsonError(e.to_string()))?;

    Ok(claims)
}

/// JWT decoding errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum JwtDecodeError {
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    #[error("UTF-8 decode error: {0}")]
    Utf8Error(String),

    #[error("JSON parse error: {0}")]
    JsonError(String),

    #[error("Missing required claim: {0}")]
    MissingClaim(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_claims() {
        // This is a test JWT with payload: {"user_id":"123","email":"test@test.com","role":"user","company_id":"456","application_id":"789"}
        let test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwicm9sZSI6InVzZXIiLCJjb21wYW55X2lkIjoiNDU2IiwiYXBwbGljYXRpb25faWQiOiI3ODkifQ.signature";

        let claims = decode_jwt_claims(test_token).unwrap();
        assert_eq!(claims.user_id, "123");
        assert_eq!(claims.email, "test@test.com");
        assert_eq!(claims.role, "user");
        assert_eq!(claims.company_id, "456");
        assert_eq!(claims.application_id, "789");
    }

    #[test]
    fn test_invalid_jwt_format() {
        let result = decode_jwt_claims("invalid");
        assert!(matches!(result, Err(JwtDecodeError::InvalidFormat(_))));
    }

    #[test]
    fn test_jwt_expiration() {
        let claims = JwtClaims {
            user_id: "123".into(),
            email: "test@test.com".into(),
            role: "user".into(),
            company_id: "456".into(),
            application_id: "789".into(),
            iat: Some(1000),
            exp: Some(1000), // Already expired
            session_id: None,
        };

        assert!(claims.is_expired());
    }
}
