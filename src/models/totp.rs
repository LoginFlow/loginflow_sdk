//! TOTP (Time-based One-Time Password) models for LoginFlow SDK.
//!
//! TOTP enrollment stays an account API (`setup_totp`/`verify_totp_setup`/`get_totp_status`/
//! `disable_totp`), kept in SDK v0.6.0. The TOTP *login* step (`verify_totp_login`) and the
//! stateless `verify_totp_code` check were removed: the second factor now goes through the OIDC
//! challenge's `next: totp` step.

use serde::{Deserialize, Serialize};

// ============================================================================
// TOTP SETUP & MANAGEMENT (authenticated endpoints)
// ============================================================================

/// Optional request body for TOTP setup: the consumer names the entry.
///
/// Only the consuming application knows what surface the user is enrolling
/// into. Absent, the server falls back to the tenant's names — never its own.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TotpSetupRequest {
    pub issuer: Option<String>,
}

/// Response from TOTP setup - contains the secret and QR code URI
///
/// After receiving this, display the `otpauth_uri` as a QR code for the user
/// to scan with their authenticator app (Google Authenticator, Authy, etc.)
#[derive(Clone, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    /// Base32-encoded TOTP secret
    pub secret: String,
    /// otpauth:// URI for QR code generation.
    ///
    /// Field name matches the API contract exactly (`otpauth_uri`, one word —
    /// see loginflow_api `TotpSetupResponse` and `docs/api/v1/user/totp/setup.md`).
    /// It was previously `otp_auth_uri`, which made every `setup_totp` call fail
    /// to deserialize.
    pub otpauth_uri: String,
    /// Issuer name displayed in authenticator app
    pub issuer: String,
}

debug_redacted!(TotpSetupResponse {
    public: [issuer],
    secret: [secret, otpauth_uri]
});

/// Request to verify TOTP setup with a code from the authenticator app
///
/// The user must provide a valid 6-digit code from their authenticator
/// to confirm they have successfully configured it.
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyTotpSetupRequest {
    /// 6-digit TOTP code from authenticator app
    pub code: String,
}

debug_redacted!(VerifyTotpSetupRequest {
    public: [],
    secret: [code]
});

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
#[derive(Clone, Serialize, Deserialize)]
pub struct DisableTotpRequest {
    /// Current 6-digit TOTP code for confirmation
    pub code: String,
}

debug_redacted!(DisableTotpRequest {
    public: [],
    secret: [code]
});
