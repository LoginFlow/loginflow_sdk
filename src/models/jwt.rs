//! JWT-related models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// JWT claims structure from LoginFlow
///
/// Matches the API's `JwtClaims` struct. The backend always sets `jti`, `status`,
/// `created_at`, and `expires_in` in every JWT it issues.
///
/// Supports both the backend's native field names (`created_at`, `expires_in`)
/// and standard JWT fields (`iat`, `exp`) via serde aliases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// JWT ID (unique token identifier, used for blacklist)
    #[serde(default)]
    pub jti: String,
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
    /// User status (active, inactive)
    #[serde(default = "default_status")]
    pub status: String,
    /// Created at - supports NaiveDateTime string from backend or numeric timestamp
    #[serde(default, alias = "iat", deserialize_with = "deserialize_flexible_datetime")]
    pub created_at: Option<FlexibleDateTime>,
    /// Expires at - supports NaiveDateTime string from backend or numeric timestamp
    #[serde(default, alias = "exp", deserialize_with = "deserialize_flexible_datetime")]
    pub expires_in: Option<FlexibleDateTime>,
}

fn default_role() -> String {
    "user".to_string()
}

fn default_status() -> String {
    "active".to_string()
}

/// Flexible datetime that can be deserialized from either a NaiveDateTime string
/// (e.g. "2026-03-05T12:00:00") or a Unix timestamp (e.g. 1741176000).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum FlexibleDateTime {
    /// NaiveDateTime string format from the backend
    String(String),
    /// Unix timestamp (seconds since epoch)
    Timestamp(i64),
}

impl FlexibleDateTime {
    /// Convert to Unix timestamp (seconds since epoch)
    pub fn as_timestamp(&self) -> Option<i64> {
        match self {
            FlexibleDateTime::Timestamp(ts) => Some(*ts),
            FlexibleDateTime::String(s) => {
                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                    .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
                    .ok()
                    .map(|dt| dt.and_utc().timestamp())
            }
        }
    }
}

fn deserialize_flexible_datetime<'de, D>(deserializer: D) -> Result<Option<FlexibleDateTime>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde_json::Value;
    let opt: Option<Value> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(Value::Number(n)) => {
            if let Some(ts) = n.as_i64() {
                Ok(Some(FlexibleDateTime::Timestamp(ts)))
            } else {
                Ok(None)
            }
        }
        Some(Value::String(s)) => Ok(Some(FlexibleDateTime::String(s))),
        _ => Ok(None),
    }
}

impl JwtClaims {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        match &self.expires_in {
            Some(dt) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                dt.as_timestamp().map(|exp| exp < now).unwrap_or(false)
            }
            None => false,
        }
    }

    /// Get remaining validity in seconds
    pub fn remaining_validity(&self) -> Option<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        self.expires_in.as_ref()?.as_timestamp().map(|exp| exp - now)
    }

    /// Check if user status is active
    pub fn is_active(&self) -> bool {
        self.status == "active"
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
        // jti defaults to empty string when not present
        assert_eq!(claims.jti, "");
        // status defaults to "active" when not present
        assert_eq!(claims.status, "active");
        assert!(claims.is_active());
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
