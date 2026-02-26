//! Authentication models for LoginFlow SDK

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// PUBLIC API REQUEST MODELS (what consuming apps send)
// ============================================================================

/// Request for user registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

/// Request for user login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Request for logout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_all_devices: Option<bool>,
}

/// Request for refreshing access token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub session_id: String,
}

/// Request for email verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
}

/// Request for OTP login (step 1: request code)
///
/// Sends a 6-digit OTP code to the user's email.
/// The code expires in 30 minutes. Rate limited to 3 requests per 15 minutes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOtpRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Response after requesting an OTP code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOtpResponse {
    pub success: bool,
    pub message: String,
    pub email_sent_to: String,
    pub expires_at: String,
    pub expires_in_minutes: i64,
}

/// Request for OTP login (step 2: verify code and login)
///
/// Submit the 6-digit code received by email to complete login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpLoginRequest {
    pub email: String,
    pub code: String,
}

/// Response from OTP login with JWT and user data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpLoginResponse {
    pub success: bool,
    pub message: String,
    pub jwt: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub company: CompanyInfo,
    pub session: SessionInfo,
    pub application: ApplicationInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ============================================================================
// INTERNAL REQUEST MODELS (sent to LoginFlow API)
// ============================================================================

/// Internal request for LoginFlow registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRegisterRequest {
    pub application_id: String,
    pub company_id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}

/// Internal request for LoginFlow login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowLoginRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub password: String,
}

/// Internal request for OTP code request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRequestOtpRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Internal request for OTP login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowOtpLoginRequest {
    pub email: String,
    pub code: String,
    pub company_id: String,
    pub application_id: String,
}

/// Internal request for email verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowVerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    pub company_id: String,
}

/// Request for resending verification code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendVerificationRequest {
    pub user_id: String,
    pub email: String,
}

/// Internal request for resending verification code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowResendVerificationRequest {
    pub user_id: String,
    pub company_id: String,
    pub email: String,
    pub application_id: String,
}

// ============================================================================
// RESPONSE MODELS
// ============================================================================

/// Generic LoginFlow response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowResponseWrapper<T> {
    pub data: T,
    pub status: String,
    pub data_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub timestamp: String,
}

/// Registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub email: String,
    pub message: String,
}

/// Internal registration data from LoginFlow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRegisterData {
    pub application_id: String,
    pub company_id: String,
    pub user_id: String,
}

/// Internal registration response from LoginFlow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRegisterResponse {
    pub data: LoginFlowRegisterData,
    pub message: String,
    pub status: String,
}

/// Login response with JWT and user data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub jwt: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub company: CompanyInfo,
    pub session: SessionInfo,
    pub application: ApplicationInfo,
}

/// Refresh token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub refresh_expires_at: String,
}

/// User information from login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company_id: Option<String>,
}

/// Company information from login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyInfo {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tax_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// Session information from login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

/// Application information from login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationInfo {
    pub id: String,
    pub name: String,
    pub status: String,
}

// ============================================================================
// AUTHENTICATED USER (extracted from JWT)
// ============================================================================

/// User data extracted from JWT token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub company_id: Uuid,
    pub application_id: Uuid,
}

impl AuthenticatedUser {
    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.role == "app_admin" || self.role == "master"
    }

    /// Check if user has master role
    pub fn is_master(&self) -> bool {
        self.role == "master"
    }
}
