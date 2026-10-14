//! Password-related models for LoginFlow SDK

use serde::{Deserialize, Serialize};

// ============================================================================
// PASSWORD RESET FLOW (3 steps)
// ============================================================================

/// Step 2: Verify reset code
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyResetCodeRequest {
    pub email: String,
    pub code: String,
}

debug_redacted!(VerifyResetCodeRequest {
    public: [email],
    secret: [code]
});

/// Step 2 Response: Contains reset token for step 3
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyResetCodeResponse {
    pub reset_token: String,
}

debug_redacted!(VerifyResetCodeResponse {
    public: [],
    secret: [reset_token]
});

/// Step 3: Complete password reset with new password
#[derive(Clone, Serialize, Deserialize)]
pub struct CompleteResetRequest {
    pub email: String,
    /// The verification code from step 2 (SDK will convert to reset_token internally)
    pub code: String,
    pub new_password: String,
    pub confirm_password: String,
}

debug_redacted!(CompleteResetRequest {
    public: [email],
    secret: [code, new_password, confirm_password]
});

// ============================================================================
// INTERNAL MODELS (sent to LoginFlow API)
// ============================================================================

/// Internal request for password reset initiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowResetPasswordRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Internal request for code verification
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowVerifyResetCodeRequest {
    pub email: String,
    pub reset_code: String,
    pub company_id: String,
    pub application_id: String,
}

debug_redacted!(LoginFlowVerifyResetCodeRequest {
    public: [email, company_id, application_id],
    secret: [reset_code]
});

/// Internal request for completing password reset
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowCompleteResetRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub new_password: String,
    pub confirm_password: String,
    pub reset_token: String,
}

debug_redacted!(LoginFlowCompleteResetRequest {
    public: [email, company_id, application_id],
    secret: [new_password, confirm_password, reset_token]
});

// ============================================================================
// CHANGE PASSWORD (authenticated user)
// ============================================================================

/// Request to change password (requires authentication)
#[derive(Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

debug_redacted!(ChangePasswordRequest {
    public: [],
    secret: [current_password, new_password, confirm_password]
});

/// Response for password change: the `data` of `POST /v1/user/change-password`.
///
/// The server answers with a bare message string (`{"data": "<message>"}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChangePasswordResponse {
    pub message: String,
}
