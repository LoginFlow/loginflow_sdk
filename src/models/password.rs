//! Password-related models for LoginFlow SDK

use serde::{Deserialize, Serialize};

// ============================================================================
// PASSWORD RESET FLOW (3 steps)
// ============================================================================

/// Step 1: Request password reset (sends verification code to email)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
}

/// Step 2: Verify reset code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResetCodeRequest {
    pub email: String,
    pub code: String,
}

/// Step 2 Response: Contains reset token for step 3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResetCodeResponse {
    pub reset_token: String,
}

/// Step 3: Complete password reset with new password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteResetRequest {
    pub email: String,
    /// The verification code from step 2 (SDK will convert to reset_token internally)
    pub code: String,
    pub new_password: String,
    pub confirm_password: String,
}

// ============================================================================
// INTERNAL MODELS (sent to LoginFlow API)
// ============================================================================

/// Internal request for password reset initiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowResetPasswordRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
}

/// Internal request for code verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowVerifyResetCodeRequest {
    pub email: String,
    pub reset_code: String,
    pub company_id: String,
    pub application_id: String,
}

/// Internal response with verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub(crate) struct LoginFlowVerifyCodeResponse {
    pub data_reset: LoginFlowVerifyResetCodeRequest,
    pub reset_token: String,
}

/// Internal request for completing password reset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowCompleteResetRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub new_password: String,
    pub confirm_password: String,
    pub reset_token: String,
}

// ============================================================================
// CHANGE PASSWORD (authenticated user)
// ============================================================================

/// Request to change password (requires authentication)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

/// Response for password change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub message: String,
}

/// Internal request for changing password
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowChangePasswordRequest {
    pub user_id: String,
    pub company_id: String,
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

// ============================================================================
// MESSAGE RESPONSES
// ============================================================================

/// Simple message response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}
