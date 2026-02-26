//! JWT-related models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// JWT claims structure from LoginFlow
///
/// Supports both the backend's native field names (`created_at`, `expires_in`)
/// and standard JWT fields (`iat`, `exp`) via serde aliases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// JWT ID (unique token identifier)
    #[serde(default)]
    pub jti: Option<String>,
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
    /// User status
    #[serde(default)]
    pub status: Option<String>,
    /// Created at (backend format: NaiveDateTime string)
    #[serde(default, alias = "iat")]
    pub created_at: Option<serde_json::Value>,
    /// Expires at (backend format: NaiveDateTime string)
    #[serde(default, alias = "exp")]
    pub expires_in: Option<serde_json::Value>,
    /// Session ID (optional)
    #[serde(default)]
    pub session_id: Option<String>,
}

fn default_role() -> String {
    "user".to_string()
}

impl JwtClaims {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        match &self.expires_in {
            Some(serde_json::Value::Number(n)) => {
                // Unix timestamp format
                if let Some(exp) = n.as_i64() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    exp < now
                } else {
                    false
                }
            }
            Some(serde_json::Value::String(s)) => {
                // NaiveDateTime string format from backend (e.g. "2026-02-26T20:00:00")
                if let Ok(expires_dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
                    let now = chrono::Utc::now().naive_utc();
                    expires_dt < now
                } else if let Ok(expires_dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
                    let now = chrono::Utc::now().naive_utc();
                    expires_dt < now
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Get remaining validity in seconds
    pub fn remaining_validity(&self) -> Option<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        match &self.expires_in {
            Some(serde_json::Value::Number(n)) => n.as_i64().map(|exp| exp - now),
            Some(serde_json::Value::String(s)) => {
                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
                    .ok()
                    .map(|dt| dt.and_utc().timestamp() - now)
            }
            _ => None,
        }
    }
}

/// Decode JWT claims without signature validation
///
/// # Warning
/// This only decodes the payload without validating the signature.
/// Use `verify_jwt_claims()` instead when you have a signing_secret.
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

/// Verify JWT signature using HMAC-SHA256 and return validated claims.
///
/// This is the secure way to validate tokens locally without hitting LoginFlow.
/// Requires the `signing_secret` from your application's API key.
///
/// Validates:
/// 1. HMAC-SHA256 signature
/// 2. Token expiration
///
/// # Arguments
/// * `token` - The JWT token string
/// * `signing_secret` - The per-app signing secret from LoginFlow API key
///
/// # Returns
/// Validated `JwtClaims` or error
pub fn verify_jwt_claims(token: &str, signing_secret: &str) -> Result<JwtClaims, JwtDecodeError> {
    use hmac::{Hmac, Mac};
    use jwt::VerifyWithKey;
    use sha2::Sha256;

    let key: Hmac<Sha256> = Hmac::new_from_slice(signing_secret.as_bytes())
        .map_err(|_| JwtDecodeError::SignatureInvalid("Failed to create verification key".into()))?;

    let claims: JwtClaims = token
        .verify_with_key(&key)
        .map_err(|_| JwtDecodeError::SignatureInvalid("JWT signature verification failed".into()))?;

    // Check expiration
    if claims.is_expired() {
        return Err(JwtDecodeError::TokenExpired);
    }

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

    #[error("JWT signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("JWT token has expired")]
    TokenExpired,
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
    fn test_verify_jwt_invalid_signature() {
        let test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzIn0.wrong_signature";
        let result = verify_jwt_claims(test_token, "some_secret");
        assert!(matches!(result, Err(JwtDecodeError::SignatureInvalid(_))));
    }
}
