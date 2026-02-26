//! Multi-tenant support for LoginFlow SDK
//!
//! This module provides extensions for multi-tenant applications where
//! the `company_id` varies per request instead of being fixed in configuration.
//!
//! # Feature Flag
//!
//! Enable this feature in Cargo.toml:
//! ```toml
//! loginflow_sdk = { version = "0.1", features = ["multi-tenant"] }
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

use crate::client::LoginFlowClient;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::{
    LoginFlowResponseWrapper, LoginResponse, LoginResult, RegisterResponse, VerifyResetCodeResponse,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// MULTI-TENANT REQUEST MODELS
// ============================================================================

/// Login request with explicit company_id for multi-tenant applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantLoginRequest {
    pub email: String,
    pub password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Registration request with explicit company_id for multi-tenant applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantRegisterRequest {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Company ID - passed dynamically per request
    pub company_id: String,
    /// Optional role override (default: "user")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// Email verification request with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantVerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Password reset request with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantResetPasswordRequest {
    pub email: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Verify reset code request with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantVerifyResetCodeRequest {
    pub email: String,
    pub code: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Complete password reset request with explicit company_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantCompleteResetRequest {
    pub email: String,
    pub code: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// Complete password reset request using temporary token (preferred flow)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantCompleteResetWithTokenRequest {
    pub email: String,
    pub temporary_token: String,
    pub new_password: String,
    pub confirm_password: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

/// OAuth login request with explicit company_id for multi-tenant applications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTenantOAuthLoginRequest {
    /// OAuth provider: "google" or "microsoft"
    pub provider: String,
    /// ID token (JWT) obtained from the OAuth provider
    pub id_token: String,
    /// Company ID - passed dynamically per request
    pub company_id: String,
}

// ============================================================================
// INTERNAL REQUEST MODELS FOR MULTI-TENANT
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalLoginRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalRegisterRequest {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalVerifyEmailRequest {
    pub verification_code: String,
    pub user_id: String,
    pub company_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalResetPasswordRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalVerifyResetCodeRequest {
    pub email: String,
    pub reset_code: String,
    pub company_id: String,
    pub application_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalCompleteResetRequest {
    pub email: String,
    pub company_id: String,
    pub application_id: String,
    pub new_password: String,
    pub confirm_password: String,
    pub reset_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InternalRegisterData {
    pub application_id: String,
    pub company_id: String,
    pub user_id: String,
}

/// Internal registration response now uses LoginFlowResponseWrapper

// ============================================================================
// MULTI-TENANT EXTENSION TRAIT
// ============================================================================

/// Extension trait for multi-tenant operations
///
/// This trait extends `LoginFlowClient` with methods that accept
/// `company_id` as a parameter instead of using the configured one.
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
#[async_trait::async_trait]
pub trait MultiTenantExt {
    /// Login with explicit company_id
    ///
    /// Returns `LoginResult::Success` or `LoginResult::TotpRequired` if 2FA is enabled
    async fn login_with_company(
        &self,
        req: MultiTenantLoginRequest,
    ) -> LoginFlowResult<LoginResult>;

    /// Register user with explicit company_id
    async fn register_with_company(
        &self,
        req: MultiTenantRegisterRequest,
    ) -> LoginFlowResult<RegisterResponse>;

    /// Verify email with explicit company_id
    async fn verify_email_with_company(
        &self,
        req: MultiTenantVerifyEmailRequest,
    ) -> LoginFlowResult<bool>;

    /// Request password reset with explicit company_id
    async fn request_password_reset_with_company(
        &self,
        req: MultiTenantResetPasswordRequest,
    ) -> LoginFlowResult<()>;

    /// Verify reset code with explicit company_id
    async fn verify_reset_code_with_company(
        &self,
        req: MultiTenantVerifyResetCodeRequest,
    ) -> LoginFlowResult<VerifyResetCodeResponse>;

    /// Complete password reset with explicit company_id
    async fn complete_password_reset_with_company(
        &self,
        req: MultiTenantCompleteResetRequest,
    ) -> LoginFlowResult<()>;

    /// Complete password reset with temporary token (preferred after verify step)
    async fn complete_password_reset_with_token_with_company(
        &self,
        req: MultiTenantCompleteResetWithTokenRequest,
    ) -> LoginFlowResult<()>;

    /// Login with OAuth provider using explicit company_id
    async fn login_with_oauth_with_company(
        &self,
        req: MultiTenantOAuthLoginRequest,
    ) -> LoginFlowResult<LoginResult>;
}

#[async_trait::async_trait]
impl MultiTenantExt for LoginFlowClient {
    async fn login_with_company(
        &self,
        req: MultiTenantLoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        let internal_req = InternalLoginRequest {
            email: req.email,
            company_id: req.company_id,
            application_id: self.config().application_id.clone(),
            password: req.password,
        };

        let url = self.config().build_url("public/login-password");
        log::info!("[MultiTenant] Logging in at: {}", url);

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("[MultiTenant] Login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResult> = response.json().await?;
        match &wrapped.data {
            LoginResult::TotpRequired(_) => log::info!("[MultiTenant] Login requires TOTP 2FA"),
            LoginResult::Success(_) => log::info!("[MultiTenant] User logged in successfully"),
        }

        Ok(wrapped.data)
    }

    async fn register_with_company(
        &self,
        req: MultiTenantRegisterRequest,
    ) -> LoginFlowResult<RegisterResponse> {
        let internal_req = InternalRegisterRequest {
            application_id: self.config().application_id.clone(),
            company_id: req.company_id,
            email: req.email.clone(),
            first_name: req.first_name,
            last_name: req.last_name,
            password: req.password,
            role: req.role.unwrap_or_else(|| "user".to_string()),
            status: Some("ACTIVE".to_string()),
            auth_type: "password".to_string(),
            phone: req.phone,
        };

        let url = self.config().build_url("public/users");
        log::info!("📝 [MultiTenant] Registering user at: {}", url);

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!(
                "❌ [MultiTenant] Registration failed ({}): {}",
                status,
                body
            );
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<InternalRegisterData> = response.json().await?;
        log::info!(
            "✅ [MultiTenant] User registered: {}",
            wrapped.data.user_id
        );

        Ok(RegisterResponse {
            user_id: wrapped.data.user_id,
            email: req.email,
            message: "User registered successfully".to_string(),
        })
    }

    async fn verify_email_with_company(
        &self,
        req: MultiTenantVerifyEmailRequest,
    ) -> LoginFlowResult<bool> {
        let internal_req = InternalVerifyEmailRequest {
            verification_code: req.verification_code,
            user_id: req.user_id,
            company_id: req.company_id,
        };

        let url = self.config().build_url("public/verify-email");
        log::info!("✉️ [MultiTenant] Verifying email at: {}", url);

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ [MultiTenant] Email verified");
            Ok(true)
        } else {
            let body = response.text().await.unwrap_or_default();
            log::warn!(
                "⚠️ [MultiTenant] Email verification failed ({}): {}",
                status,
                body
            );
            Ok(false)
        }
    }

    async fn request_password_reset_with_company(
        &self,
        req: MultiTenantResetPasswordRequest,
    ) -> LoginFlowResult<()> {
        let internal_req = InternalResetPasswordRequest {
            email: req.email.clone(),
            company_id: req.company_id,
            application_id: self.config().application_id.clone(),
        };

        let url = self.config().build_url("public/reset-password");
        log::info!(
            "🔑 [MultiTenant] Requesting password reset for: {}",
            req.email
        );

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ [MultiTenant] Password reset code sent");
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!(
                "❌ [MultiTenant] Password reset request failed ({}): {}",
                status,
                body
            );
            Err(LoginFlowError::from_status(status.as_u16(), &body))
        }
    }

    async fn verify_reset_code_with_company(
        &self,
        req: MultiTenantVerifyResetCodeRequest,
    ) -> LoginFlowResult<VerifyResetCodeResponse> {
        let internal_req = InternalVerifyResetCodeRequest {
            email: req.email.clone(),
            reset_code: req.code,
            company_id: req.company_id,
            application_id: self.config().application_id.clone(),
        };

        let url = self.config().build_url("public/reset-password/verify");
        log::info!("🔑 [MultiTenant] Verifying reset code for: {}", req.email);

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!(
                "❌ [MultiTenant] Reset code verification failed ({}): {}",
                status,
                body
            );
            return Err(LoginFlowError::Authentication(
                "Invalid or expired reset code".to_string(),
            ));
        }

        let json_response: serde_json::Value = response.json().await?;
        let reset_token = json_response
            .get("data")
            .and_then(|d| d.get("reset_token"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| LoginFlowError::ParseError("Missing reset_token".to_string()))?
            .to_string();

        log::info!("✅ [MultiTenant] Reset code verified");
        Ok(VerifyResetCodeResponse { reset_token })
    }

    async fn complete_password_reset_with_company(
        &self,
        req: MultiTenantCompleteResetRequest,
    ) -> LoginFlowResult<()> {
        // First verify the code
        let verify_req = MultiTenantVerifyResetCodeRequest {
            email: req.email.clone(),
            code: req.code.clone(),
            company_id: req.company_id.clone(),
        };
        let verify_response = self.verify_reset_code_with_company(verify_req).await?;

        let internal_req = InternalCompleteResetRequest {
            email: req.email.clone(),
            company_id: req.company_id,
            application_id: self.config().application_id.clone(),
            new_password: req.new_password,
            confirm_password: req.confirm_password,
            reset_token: verify_response.reset_token,
        };

        let url = self.config().build_url("public/reset-password/complete");
        log::info!(
            "🔑 [MultiTenant] Completing password reset for: {}",
            req.email
        );

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ [MultiTenant] Password reset completed");
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!(
                "❌ [MultiTenant] Password reset completion failed ({}): {}",
                status,
                body
            );
            Err(LoginFlowError::from_status(status.as_u16(), &body))
        }
    }

    async fn complete_password_reset_with_token_with_company(
        &self,
        req: MultiTenantCompleteResetWithTokenRequest,
    ) -> LoginFlowResult<()> {
        let internal_req = InternalCompleteResetRequest {
            email: req.email.clone(),
            company_id: req.company_id,
            application_id: self.config().application_id.clone(),
            new_password: req.new_password,
            confirm_password: req.confirm_password,
            reset_token: req.temporary_token,
        };

        let url = self.config().build_url("public/reset-password/complete");
        log::info!(
            "🔑 [MultiTenant] Completing password reset with temporary token for: {}",
            req.email
        );

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ [MultiTenant] Password reset completed with temporary token");
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!(
                "❌ [MultiTenant] Password reset completion with temporary token failed ({}): {}",
                status,
                body
            );
            Err(LoginFlowError::from_status(status.as_u16(), &body))
        }
    }

    async fn login_with_oauth_with_company(
        &self,
        req: MultiTenantOAuthLoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        let internal_req = serde_json::json!({
            "provider": req.provider,
            "id_token": req.id_token,
            "company_id": req.company_id,
            "application_id": self.config().application_id,
        });

        let url = self.config().build_url("public/oauth-login");
        log::info!("[MultiTenant] OAuth login ({}) at: {}", req.provider, url);

        let response = reqwest::Client::new()
            .post(&url)
            .timeout(std::time::Duration::from_secs(self.config().timeout_secs))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("[MultiTenant] OAuth login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResult> = response.json().await?;
        match &wrapped.data {
            LoginResult::TotpRequired(_) => log::info!("[MultiTenant] OAuth login requires TOTP 2FA"),
            LoginResult::Success(_) => log::info!("[MultiTenant] OAuth login successful"),
        }

        Ok(wrapped.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_tenant_login_request() {
        let req = MultiTenantLoginRequest {
            email: "test@example.com".into(),
            password: "password123".into(),
            company_id: "company-uuid".into(),
        };

        assert_eq!(req.email, "test@example.com");
        assert_eq!(req.company_id, "company-uuid");
    }

    #[test]
    fn test_multi_tenant_register_request() {
        let req = MultiTenantRegisterRequest {
            email: "test@example.com".into(),
            first_name: "John".into(),
            last_name: "Doe".into(),
            password: "password123".into(),
            phone: Some("+1234567890".into()),
            company_id: "company-uuid".into(),
            role: Some("admin".into()),
        };

        assert_eq!(req.role, Some("admin".into()));
    }

    #[test]
    fn test_multi_tenant_oauth_login_request() {
        let req = MultiTenantOAuthLoginRequest {
            provider: "google".into(),
            id_token: "test-token".into(),
            company_id: "company-uuid".into(),
        };

        assert_eq!(req.provider, "google");
        assert_eq!(req.company_id, "company-uuid");
    }
}
