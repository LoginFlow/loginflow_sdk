//! Password-related models for LoginFlow SDK. A password reset goes through the hosted login's
//! `intent=password_reset`, outside this SDK.

use serde::{Deserialize, Serialize};

// ============================================================================
// CHANGE PASSWORD (authenticated user)
// ============================================================================

/// Request to change password (requires authentication and a recent `auth_time`;
/// RFC 9470 step-up on `insufficient_user_authentication`).
#[derive(Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    /// The new password: at least 8 characters with an uppercase and a lowercase letter, a
    /// number and a special character, not in a known breach.
    pub new_password: String,
}

debug_redacted!(ChangePasswordRequest {
    public: [],
    secret: [new_password]
});

/// Response for password change: the `data` of `POST /v1/user/change-password`
/// (`{"data": {"message": "..."}}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePasswordResponse {
    /// Human-readable confirmation.
    pub message: String,
}
