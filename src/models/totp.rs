//! TOTP (Time-based One-Time Password) models for LoginFlow SDK
//!
//! Models for optional 2FA setup, verification, and login flow.

use serde::{Deserialize, Serialize};
use crate::models::auth::LoginResponse;

// ============================================================================
// TOTP SETUP & MANAGEMENT (authenticated endpoints)
// ============================================================================

/// Response from TOTP setup - contains the secret and QR code URI
///
/// After receiving this, display the `otpauth_uri` as a QR code for the user
/// to scan with their authenticator app (Google Authenticator, Authy, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    /// Base32-encoded TOTP secret
    pub secret: String,
    /// otp_auth:// URI for QR code generation
    pub otp_auth_uri: String,
    /// Issuer name displayed in authenticator app
    pub issuer: String,
}

/// Request to verify TOTP setup with a code from the authenticator app
///
/// The user must provide a valid 6-digit code from their authenticator
/// to confirm they have successfully configured it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTotpSetupRequest {
    /// 6-digit TOTP code from authenticator app
    pub code: String,
}

/// TOTP status for a user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpStatusResponse {
    /// Whether TOTP 2FA is enabled
    pub enabled: bool,
    /// When TOTP was verified/enabled (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
}

/// Request to disable TOTP 2FA
///
/// Requires a valid TOTP code as confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableTotpRequest {
    /// Current 6-digit TOTP code for confirmation
    pub code: String,
}

// ============================================================================
// TOTP LOGIN FLOW (public endpoint)
// ============================================================================

/// Challenge response returned when login requires TOTP 2FA
///
/// When a user with TOTP enabled logs in, they receive this instead of a
/// full JWT. Use the `totp_token` with [`VerifyTotpLoginRequest`] to complete login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpChallengeResponse {
    /// Indicates that 2FA verification is required
    pub requires_2fa: bool,
    /// Short-lived temporary token (5 min) to use with verify-totp endpoint
    pub totp_token: String,
    /// Seconds until the temporary token expires
    pub expires_in: i64,
}

/// Request to complete login after TOTP challenge
///
/// Submit the temporary token from [`TotpChallengeResponse`] along with
/// a valid 6-digit TOTP code to receive the full JWT session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTotpLoginRequest {
    /// Temporary token from the TOTP challenge
    pub totp_token: String,
    /// 6-digit TOTP code from authenticator app
    pub code: String,
}

// ============================================================================
// LOGIN RESULT (unified login response)
// ============================================================================

/// Result of a login attempt - either a full session or a TOTP challenge.
///
/// When TOTP 2FA is enabled for a user, `login()` returns `TotpRequired`
/// instead of `Success`. Complete the flow with `verify_totp_login()`.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult};
///
/// async fn login(client: &LoginFlowClient) {
///     let result = client.login(LoginRequest {
///         email: "user@example.com".into(),
///         password: "password".into(),
///     }).await.unwrap();
///
///     match result {
///         LoginResult::Success(response) => {
///             println!("JWT: {}", response.jwt);
///         }
///         LoginResult::TotpRequired(challenge) => {
///             println!("2FA required, token: {}", challenge.totp_token);
///             // Prompt user for TOTP code, then call verify_totp_login()
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LoginResult {
    /// TOTP 2FA verification is required before login can complete
    TotpRequired(TotpChallengeResponse),
    /// Login succeeded with full JWT session
    Success(Box<LoginResponse>),
}

impl LoginResult {
    /// Returns `true` if TOTP 2FA verification is required
    pub fn requires_totp(&self) -> bool {
        matches!(self, LoginResult::TotpRequired(_))
    }

    /// Returns the login response if successful, `None` if TOTP is required
    pub fn into_login_response(self) -> Option<LoginResponse> {
        match self {
            LoginResult::Success(r) => Some(*r),
            LoginResult::TotpRequired(_) => None,
        }
    }

    /// Returns the TOTP challenge if required, `None` if login succeeded
    pub fn into_totp_challenge(self) -> Option<TotpChallengeResponse> {
        match self {
            LoginResult::TotpRequired(c) => Some(c),
            LoginResult::Success(_) => None,
        }
    }

    /// Returns the effective refresh token when login succeeded.
    ///
    /// If the backend did not include a dedicated refresh token, this falls
    /// back to the current JWT token.
    pub fn effective_refresh_token(&self) -> Option<&str> {
        match self {
            LoginResult::Success(r) => Some(r.effective_refresh_token()),
            LoginResult::TotpRequired(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::auth::{ApplicationInfo, CompanyInfo, SessionInfo, UserInfo};

    fn login_response() -> LoginResponse {
        LoginResponse {
            jwt: "jwt".into(),
            refresh_token: Some("rt".into()),
            expires_in: 3600,
            user: UserInfo {
                id: "u-1".into(),
                email: Some("u@test.com".into()),
                first_name: Some("U".into()),
                last_name: Some("T".into()),
                role: Some("user".into()),
                company_id: Some("c-1".into()),
            },
            company: CompanyInfo {
                id: "c-1".into(),
                name: "C".into(),
                tax_id: None,
                email: None,
            },
            session: SessionInfo {
                id: "s-1".into(),
                device_info: None,
                ip_address: None,
                user_agent: None,
                location: None,
                created_at: "2026-01-01T00:00:00".into(),
                expires_at: "2026-01-02T00:00:00".into(),
                refresh_expires_at: Some("2026-01-08T00:00:00".into()),
            },
            application: ApplicationInfo {
                id: "a-1".into(),
                name: "App".into(),
                status: "active".into(),
            },
        }
    }

    #[test]
    fn login_result_effective_refresh_token_success() {
        let result = LoginResult::Success(Box::new(login_response()));
        assert_eq!(result.effective_refresh_token(), Some("rt"));
    }

    #[test]
    fn login_result_effective_refresh_token_totp_required() {
        let result = LoginResult::TotpRequired(TotpChallengeResponse {
            requires_2fa: true,
            totp_token: "tmp".into(),
            expires_in: 300,
        });
        assert_eq!(result.effective_refresh_token(), None);
    }
}
