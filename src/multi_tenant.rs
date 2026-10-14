//! Multi-tenant support for LoginFlow SDK
//!
//! This module provides extensions for multi-tenant applications where
//! the `company_id` varies per request instead of being fixed in configuration.
//!
//! # Feature Flag
//!
//! Enable this feature in Cargo.toml:
//! ```toml
//! loginflow_sdk = { version = "0.5", features = ["multi-tenant"] }
//! ```
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use loginflow_sdk::LoginFlowClient;
//! use loginflow_sdk::multi_tenant::{MultiTenantLoginRequest, MultiTenantExt};
//!
//! async fn login_user(client: &LoginFlowClient, email: &str, password: &str, company_id: &str) {
//!     let request = MultiTenantLoginRequest {
//!         email: email.to_string(),
//!         password: password.to_string(),
//!         company_id: company_id.to_string(),
//!     };
//!
//!     let response = client.login_with_company(request).await;
//!     // Handle response...
//! }
//! ```

use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::client::{LoginFlowClient, NewPassword};
use crate::error::LoginFlowResult;
use crate::models::debug_redacted;
use crate::models::{
    CompleteResetRequest, LoginRequest, LoginResult, OAuthLoginRequest, OtpLoginRequest,
    OtpLoginResponse, RegisterRequest, RegisterResponse, RequestOtpRequest, RequestOtpResponse,
    VerifyEmailRequest, VerifyResetCodeRequest, VerifyResetCodeResponse,
};

// ============================================================================
// MULTI-TENANT REQUEST MODELS
// ============================================================================

/// Login request with explicit company_id for multi-tenant applications
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantLoginRequest {
    pub email: String,
    pub password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantLoginRequest {
    public: [email, company_id],
    secret: [password]
});

/// Registration request with explicit company_id for multi-tenant applications.
///
/// Public registration always creates a `user`; roles are assigned only
/// through the master API.
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantRegisterRequest {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantRegisterRequest {
    public: [email, first_name, last_name, company_id],
    secret: [password]
});

/// Email verification request with explicit company_id
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantVerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantVerifyEmailRequest {
    public: [user_id, company_id],
    secret: [verification_code]
});

/// Password reset request with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantResetPasswordRequest {
    pub email: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Verify reset code request with explicit company_id
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantVerifyResetCodeRequest {
    pub email: String,
    pub code: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantVerifyResetCodeRequest {
    public: [email, company_id],
    secret: [code]
});

/// Complete password reset request with explicit company_id
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantCompleteResetRequest {
    pub email: String,
    pub code: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantCompleteResetRequest {
    public: [email, company_id],
    secret: [code, new_password, confirm_password]
});

/// Complete password reset request using the reset token from the verify step
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantCompleteResetWithTokenRequest {
    pub email: String,
    pub reset_token: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantCompleteResetWithTokenRequest {
    public: [email, company_id],
    secret: [reset_token, new_password, confirm_password]
});

/// OAuth login request with explicit company_id for multi-tenant applications
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantOAuthLoginRequest {
    /// OAuth provider: "google" or "microsoft"
    pub provider: String,
    /// ID token (JWT) obtained from the OAuth provider
    pub id_token: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

debug_redacted!(MultiTenantOAuthLoginRequest {
    public: [provider, company_id],
    secret: [id_token]
});

/// OTP code request (step 1) with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantRequestOtpRequest {
    pub email: String,
    pub company_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// Email template language ("es", "en")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// OTP login request (step 2) with explicit company_id
#[derive(Clone, Serialize, Deserialize)]
pub struct MultiTenantOtpLoginRequest {
    pub email: String,
    pub code: String,
    pub company_id: String,
}

debug_redacted!(MultiTenantOtpLoginRequest {
    public: [email, company_id],
    secret: [code]
});

// ============================================================================
// MULTI-TENANT EXTENSION TRAIT
// ============================================================================

/// Extension trait for multi-tenant operations
///
/// This trait extends `LoginFlowClient` with methods that accept
/// `company_id` as a parameter instead of using the configured one.
/// All calls share the client's HTTP connection pool, timeout and user agent.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::LoginFlowClient;
/// use loginflow_sdk::multi_tenant::{MultiTenantLoginRequest, MultiTenantExt};
///
/// async fn example(client: &LoginFlowClient) {
///     let req = MultiTenantLoginRequest {
///         email: "user@company-a.com".into(),
///         password: "password123".into(),
///         company_id: "company-a-uuid".into(),
///     };
///
///     let result = client.login_with_company(req).await;
/// }
/// ```
pub trait MultiTenantExt {
    /// Login with explicit company_id
    ///
    /// Returns `LoginResult::Success` or `LoginResult::TotpRequired` if 2FA is enabled
    fn login_with_company(
        &self,
        req: MultiTenantLoginRequest,
    ) -> impl Future<Output = LoginFlowResult<LoginResult>> + Send;

    /// Register user with explicit company_id
    fn register_with_company(
        &self,
        req: MultiTenantRegisterRequest,
    ) -> impl Future<Output = LoginFlowResult<RegisterResponse>> + Send;

    /// Verify email with explicit company_id
    fn verify_email_with_company(
        &self,
        req: MultiTenantVerifyEmailRequest,
    ) -> impl Future<Output = LoginFlowResult<bool>> + Send;

    /// Request password reset with explicit company_id
    fn request_password_reset_with_company(
        &self,
        req: MultiTenantResetPasswordRequest,
    ) -> impl Future<Output = LoginFlowResult<()>> + Send;

    /// Verify reset code with explicit company_id
    fn verify_reset_code_with_company(
        &self,
        req: MultiTenantVerifyResetCodeRequest,
    ) -> impl Future<Output = LoginFlowResult<VerifyResetCodeResponse>> + Send;

    /// Complete password reset with explicit company_id
    fn complete_password_reset_with_company(
        &self,
        req: MultiTenantCompleteResetRequest,
    ) -> impl Future<Output = LoginFlowResult<()>> + Send;

    /// Complete password reset with the reset token obtained from the verify step
    fn complete_password_reset_with_token_with_company(
        &self,
        req: MultiTenantCompleteResetWithTokenRequest,
    ) -> impl Future<Output = LoginFlowResult<()>> + Send;

    /// Login with OAuth provider using explicit company_id
    fn login_with_oauth_with_company(
        &self,
        req: MultiTenantOAuthLoginRequest,
    ) -> impl Future<Output = LoginFlowResult<LoginResult>> + Send;

    /// Request an OTP login code with explicit company_id
    fn request_otp_login_with_company(
        &self,
        req: MultiTenantRequestOtpRequest,
    ) -> impl Future<Output = LoginFlowResult<RequestOtpResponse>> + Send;

    /// Login with an OTP code with explicit company_id
    fn login_with_otp_with_company(
        &self,
        req: MultiTenantOtpLoginRequest,
    ) -> impl Future<Output = LoginFlowResult<OtpLoginResponse>> + Send;
}

impl MultiTenantExt for LoginFlowClient {
    async fn login_with_company(
        &self,
        req: MultiTenantLoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        self.login_for(
            &req.company_id,
            LoginRequest {
                email: req.email,
                password: req.password,
            },
        )
        .await
    }

    async fn register_with_company(
        &self,
        req: MultiTenantRegisterRequest,
    ) -> LoginFlowResult<RegisterResponse> {
        let register = RegisterRequest {
            email: req.email,
            first_name: req.first_name,
            last_name: req.last_name,
            password: req.password,
        };
        self.register_for(&req.company_id, register).await
    }

    async fn verify_email_with_company(
        &self,
        req: MultiTenantVerifyEmailRequest,
    ) -> LoginFlowResult<bool> {
        let verify = VerifyEmailRequest {
            verification_code: req.verification_code,
            user_id: req.user_id,
            language: None,
        };
        self.verify_email_for(&req.company_id, verify).await
    }

    async fn request_password_reset_with_company(
        &self,
        req: MultiTenantResetPasswordRequest,
    ) -> LoginFlowResult<()> {
        self.request_password_reset_for(&req.company_id, &req.email, None)
            .await
    }

    async fn verify_reset_code_with_company(
        &self,
        req: MultiTenantVerifyResetCodeRequest,
    ) -> LoginFlowResult<VerifyResetCodeResponse> {
        self.verify_reset_code_for(
            &req.company_id,
            VerifyResetCodeRequest {
                email: req.email,
                code: req.code,
            },
        )
        .await
    }

    async fn complete_password_reset_with_company(
        &self,
        req: MultiTenantCompleteResetRequest,
    ) -> LoginFlowResult<()> {
        let complete = CompleteResetRequest {
            email: req.email,
            code: req.code,
            new_password: req.new_password,
            confirm_password: req.confirm_password,
        };
        self.complete_password_reset_for(&req.company_id, complete)
            .await
    }

    async fn complete_password_reset_with_token_with_company(
        &self,
        req: MultiTenantCompleteResetWithTokenRequest,
    ) -> LoginFlowResult<()> {
        let new_password = NewPassword {
            email: req.email,
            reset_token: req.reset_token,
            new_password: req.new_password,
            confirm_password: req.confirm_password,
        };
        self.complete_password_reset_with_token_for(&req.company_id, new_password)
            .await
    }

    async fn login_with_oauth_with_company(
        &self,
        req: MultiTenantOAuthLoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        self.login_with_oauth_for(
            &req.company_id,
            OAuthLoginRequest {
                provider: req.provider,
                id_token: req.id_token,
            },
        )
        .await
    }

    async fn request_otp_login_with_company(
        &self,
        req: MultiTenantRequestOtpRequest,
    ) -> LoginFlowResult<RequestOtpResponse> {
        let request = RequestOtpRequest {
            email: req.email,
            metadata: req.metadata,
            language: req.language,
        };
        self.request_otp_login_for(&req.company_id, request).await
    }

    async fn login_with_otp_with_company(
        &self,
        req: MultiTenantOtpLoginRequest,
    ) -> LoginFlowResult<OtpLoginResponse> {
        self.login_with_otp_for(
            &req.company_id,
            OtpLoginRequest {
                email: req.email,
                code: req.code,
            },
        )
        .await
    }
}
