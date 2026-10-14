//! JWT-related models for LoginFlow SDK

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// `token_type` of a token that grants API access. Consumers accept no other type.
pub const ACCESS_TOKEN_TYPE: &str = "access";

/// Claims of a LoginFlow token.
///
/// Carries the standard registered claims (`iss`, `sub`, `aud`, `exp`, `iat`)
/// and LoginFlow's own claims. Only obtained through
/// [`LoginFlowClient::verify_token`](crate::LoginFlowClient::verify_token),
/// i.e. after the ES256 signature, issuer, audience and expiration were checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// JWT ID (unique token identifier, used for revocation)
    pub jti: String,
    /// Issuer (e.g. "https://api.loginflow.dev")
    pub iss: String,
    /// Subject: the user ID
    pub sub: String,
    /// Audience: the application ID for access tokens
    pub aud: String,
    /// Expiration time (Unix seconds)
    pub exp: i64,
    /// Issued at (Unix seconds)
    pub iat: i64,
    /// User ID (UUID string)
    pub user_id: String,
    /// Company ID (UUID string)
    pub company_id: String,
    /// Application ID (UUID string)
    pub application_id: String,
    /// User email
    pub email: String,
    /// User role (user, app_admin, master)
    pub role: String,
    /// User status (active, inactive)
    pub status: String,
    /// Token purpose: "access", "refresh", "totp_challenge" or "password_reset"
    pub token_type: String,
    /// LoginFlow's own creation timestamp (NaiveDateTime string)
    #[serde(default, deserialize_with = "deserialize_flexible_datetime")]
    pub created_at: Option<FlexibleDateTime>,
    /// LoginFlow's own expiration timestamp (NaiveDateTime string)
    #[serde(default, deserialize_with = "deserialize_flexible_datetime")]
    pub expires_in: Option<FlexibleDateTime>,
}

/// Flexible datetime that can be deserialized from either a NaiveDateTime string
/// (e.g. "2026-03-05T12:00:00") or a Unix timestamp (e.g. 1741176000).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

fn deserialize_flexible_datetime<'de, D>(
    deserializer: D,
) -> Result<Option<FlexibleDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<Value> = Option::deserialize(deserializer)?;
    Ok(match opt {
        Some(Value::Number(n)) => n.as_i64().map(FlexibleDateTime::Timestamp),
        Some(Value::String(s)) => Some(FlexibleDateTime::String(s)),
        _ => None,
    })
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl JwtClaims {
    /// Check if the token is past its `exp`
    pub fn is_expired(&self) -> bool {
        self.exp <= now_unix()
    }

    /// Remaining validity in seconds (negative when expired)
    pub fn remaining_validity(&self) -> i64 {
        self.exp - now_unix()
    }

    /// Check if user status is active
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Check if this is an access token
    pub fn is_access_token(&self) -> bool {
        self.token_type == ACCESS_TOKEN_TYPE
    }
}
