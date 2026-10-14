//! Authentication models for LoginFlow SDK

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::jwt::JwtClaims;

// ============================================================================
// PUBLIC API REQUEST MODELS (what consuming apps send)
// ============================================================================

/// Request for user registration
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
}

debug_redacted!(RegisterRequest {
    public: [email, first_name, last_name],
    secret: [password]
});

/// Request for user login
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

debug_redacted!(LoginRequest {
    public: [email],
    secret: [password]
});

/// Request for logout
///
/// The user is the owner of the access token the call is made with. The server
/// requires one of the two targets: `session_token` (the session ID returned at
/// login, `LoginResponse.session.id`) to close that session, or
/// `logout_all_devices: Some(true)` to close every session of the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logout_all_devices: Option<bool>,
}

/// Request for refreshing access token
#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
    pub session_id: String,
}

debug_redacted!(RefreshTokenRequest {
    public: [session_id],
    secret: [refresh_token]
});

/// Request for email verification
#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    /// Email template language ("es", "en"). Defaults to "es" if not provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

debug_redacted!(VerifyEmailRequest {
    public: [user_id, language],
    secret: [verification_code]
});

/// Request for OTP login (step 1: request code)
///
/// Sends a one-time code to the user's email. Whether an unknown email gets an
/// account created on step 2 is a per-application setting on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestOtpRequest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Email template language ("es", "en"). Defaults to "es" if not provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Response after requesting an OTP code.
///
/// Identical whether or not a code was sent: `email_sent_to` is the requested
/// address, masked, and does not confirm that an account exists.
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
#[derive(Clone, Serialize, Deserialize)]
pub struct OtpLoginRequest {
    pub email: String,
    pub code: String,
}

debug_redacted!(OtpLoginRequest {
    public: [email],
    secret: [code]
});

/// Response from OTP login with JWT and user data
#[derive(Clone, Serialize, Deserialize)]
pub struct OtpLoginResponse {
    pub success: bool,
    pub message: String,
    pub jwt: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub company: CompanyInfo,
    pub session: SessionInfo,
    pub application: ApplicationInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

debug_redacted!(OtpLoginResponse {
    public: [
        success,
        message,
        expires_in,
        user,
        company,
        session,
        application,
        metadata
    ],
    secret: [jwt, refresh_token]
});

// ============================================================================
// INTERNAL REQUEST MODELS (sent to LoginFlow API)
// ============================================================================

/// Internal request for LoginFlow registration
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRegisterRequest {
    pub application_id: String,
    pub company_id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    pub auth_type: String,
}

debug_redacted!(LoginFlowRegisterRequest {
    public: [
        application_id,
        company_id,
        email,
        first_name,
        last_name,
        auth_type
    ],
    secret: [password]
});

/// Internal request for LoginFlow login
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowLoginRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub password: String,
}

debug_redacted!(LoginFlowLoginRequest {
    public: [email, company_id, application_id],
    secret: [password]
});

/// Internal request for OTP code request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRequestOtpRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Internal request for OTP login
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowOtpLoginRequest {
    pub email: String,
    pub code: String,
    pub company_id: String,
    pub application_id: String,
}

debug_redacted!(LoginFlowOtpLoginRequest {
    public: [email, company_id, application_id],
    secret: [code]
});

/// Internal request for email verification
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowVerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    pub company_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

debug_redacted!(LoginFlowVerifyEmailRequest {
    public: [user_id, company_id, language],
    secret: [verification_code]
});

/// Request for resending verification code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResendVerificationRequest {
    pub user_id: String,
    pub email: String,
    /// Email template language ("es", "en"). Defaults to "es" if not provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Internal request for resending verification code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowResendVerificationRequest {
    pub user_id: String,
    pub company_id: String,
    pub email: String,
    pub application_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Request for initiating email verification
///
/// The SDK automatically adds `company_id` and `application_id` from config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEmailVerificationRequest {
    pub user_id: String,
    pub email: String,
    /// Email template language ("es", "en"). Defaults to "es" if not provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Internal request sent to the LoginFlow API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowRequestEmailVerificationRequest {
    pub user_id: String,
    pub company_id: String,
    pub application_id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Response from requesting email verification.
///
/// The verification code is only ever delivered by email, never in the response.
/// The response is identical whether or not a code was issued (unknown user,
/// email mismatch, already verified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEmailVerificationResponse {
    pub success: bool,
    pub message: String,
}

// ============================================================================
// RESPONSE MODELS
// ============================================================================

/// Metadata from LoginFlow API responses (LoginFlow standard)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    pub status: u16,
    pub timestamp: String,
    pub request_id: String,
    pub path: String,
}

/// Generic LoginFlow response wrapper (LoginFlow standard)
///
/// All success responses follow: `{ "data": T, "meta": { status, timestamp, request_id, path } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowResponseWrapper<T> {
    pub data: T,
    pub meta: ResponseMeta,
}

/// Structured error response from LoginFlow API (LoginFlow standard)
///
/// All error responses follow: `{ "error": { code, message, details? }, "meta": { ... } }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorResponse {
    pub error: LoginFlowErrorDetail,
    pub meta: ResponseMeta,
}

/// Error detail from a LoginFlow API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFlowErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Registration response: the `data` of `POST /v1/public/user-accounts`.
///
/// Public registration always creates a `user`; roles are assigned only
/// through the master API. For an email that is already registered the server
/// answers with the same shape and a random, unused `user_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub company_id: String,
    pub application_id: String,
}

/// Login response with JWT and user data
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub jwt: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub company: CompanyInfo,
    pub session: SessionInfo,
    pub application: ApplicationInfo,
}

debug_redacted!(LoginResponse {
    public: [expires_in, user, company, session, application],
    secret: [jwt, refresh_token]
});

/// Refresh token response
///
/// Mirrors the API's `session_management_model::RefreshTokenResponse`.
/// The refresh token is rotated on every refresh: store the new one.
#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub refresh_expires_at: String,
}

debug_redacted!(RefreshTokenResponse {
    public: [expires_at, refresh_expires_at],
    secret: [access_token, refresh_token]
});

impl RefreshTokenResponse {
    /// Check if the access token has expired based on `expires_at`
    pub fn is_access_expired(&self) -> bool {
        Self::parse_datetime(&self.expires_at)
            .map(|dt| dt < chrono::Utc::now().naive_utc())
            .unwrap_or(false)
    }

    /// Remaining seconds until access token expires. Negative means already expired.
    pub fn access_token_remaining_secs(&self) -> Option<i64> {
        Self::parse_datetime(&self.expires_at)
            .map(|dt| dt.and_utc().timestamp() - chrono::Utc::now().timestamp())
    }

    /// Remaining seconds until refresh token expires. Negative means already expired.
    pub fn refresh_token_remaining_secs(&self) -> Option<i64> {
        Self::parse_datetime(&self.refresh_expires_at)
            .map(|dt| dt.and_utc().timestamp() - chrono::Utc::now().timestamp())
    }

    fn parse_datetime(s: &str) -> Option<chrono::NaiveDateTime> {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ")
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f"))
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
            .ok()
    }
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
///
/// Mirrors the API's `JwtSessionModel` struct.
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
    /// Refresh token expiration timestamp (from API's JwtSessionModel)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_expires_at: Option<String>,
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

/// User data taken from a verified access token
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub company_id: Uuid,
    pub application_id: Uuid,
}

impl AuthenticatedUser {
    /// Build the user from verified claims.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when `user_id`, `company_id` or
    /// `application_id` is not a UUID.
    pub fn from_claims(claims: &JwtClaims) -> LoginFlowResult<Self> {
        Ok(Self {
            user_id: parse_claim_uuid(&claims.user_id, "user ID")?,
            email: claims.email.clone(),
            role: claims.role.clone(),
            company_id: parse_claim_uuid(&claims.company_id, "company ID")?,
            application_id: parse_claim_uuid(&claims.application_id, "application ID")?,
        })
    }

    /// Check if user has admin role
    pub fn is_admin(&self) -> bool {
        self.role == "app_admin" || self.role == "master"
    }

    /// Check if user has master role
    pub fn is_master(&self) -> bool {
        self.role == "master"
    }
}

fn parse_claim_uuid(value: &str, name: &str) -> LoginFlowResult<Uuid> {
    Uuid::parse_str(value)
        .map_err(|_| LoginFlowError::Authentication(format!("Invalid {name} format in token")))
}
