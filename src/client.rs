//! HTTP Client for LoginFlow API
//!
//! Provides async methods for all LoginFlow authentication endpoints.

use std::time::Duration;

use reqwest::Client;

use crate::config::LoginFlowConfig;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::{
    // Auth models
    RegisterRequest, RegisterResponse, LoginRequest, LoginResponse,
    LogoutRequest, VerifyEmailRequest, ResendVerificationRequest, AuthenticatedUser,
    // Internal auth models
    LoginFlowRegisterRequest, LoginFlowLoginRequest, LoginFlowRegisterResponse,
    LoginFlowResponseWrapper, LoginFlowVerifyEmailRequest, LoginFlowResendVerificationRequest,
    // Password models
    VerifyResetCodeRequest, VerifyResetCodeResponse,
    CompleteResetRequest, ChangePasswordRequest, ChangePasswordResponse,
    // Internal password models
    LoginFlowResetPasswordRequest, LoginFlowVerifyResetCodeRequest,
    LoginFlowCompleteResetRequest, LoginFlowChangePasswordRequest,
    // User account models
    FullUserAccountResponse, UserAccountResponse, UpdateUserAccountRequest, OperationResponse,
    // User profile models
    UserProfileResponse, UpdateUserProfileRequest,
};

/// LoginFlow HTTP Client
///
/// Provides async methods for interacting with LoginFlow authentication service.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};
///
/// #[tokio::main]
/// async fn main() {
///     // From environment variables
///     let client = LoginFlowClient::from_env().expect("Failed to create client");
///
///     // Or with explicit config
///     let client = LoginFlowClient::new(LoginFlowConfig {
///         base_url: "https://your-loginflow-server.com".into(),
///         api_version: 1,
///         company_id: "your-company-uuid".into(),
///         application_id: "your-app-uuid".into(),
///         timeout_secs: 30,
///         user_agent: None,
///     }).expect("Failed to create client");
/// }
/// ```
#[derive(Clone)]
pub struct LoginFlowClient {
    config: LoginFlowConfig,
    http_client: Client,
}

impl LoginFlowClient {
    /// Create a new client with explicit configuration
    pub fn new(config: LoginFlowConfig) -> LoginFlowResult<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs));

        if let Some(ref user_agent) = config.user_agent {
            builder = builder.user_agent(user_agent);
        }

        let http_client = builder
            .build()
            .map_err(|e| LoginFlowError::Config(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, http_client })
    }

    /// Create a new client from environment variables
    pub fn from_env() -> LoginFlowResult<Self> {
        let config = LoginFlowConfig::from_env()?;
        Self::new(config)
    }

    /// Get the current configuration
    pub fn config(&self) -> &LoginFlowConfig {
        &self.config
    }

    // =========================================================================
    // AUTHENTICATION ENDPOINTS
    // =========================================================================

    /// Register a new user
    ///
    /// # Arguments
    /// * `req` - Registration request with email, name, password
    ///
    /// # Returns
    /// Registration response with user ID
    pub async fn register(&self, req: RegisterRequest) -> LoginFlowResult<RegisterResponse> {
        let internal_req = LoginFlowRegisterRequest {
            application_id: self.config.application_id.clone(),
            company_id: self.config.company_id.clone(),
            email: req.email.clone(),
            first_name: req.first_name.clone(),
            last_name: req.last_name.clone(),
            password: req.password.clone(),
            role: "user".to_string(),
            status: Some("ACTIVE".to_string()),
            auth_type: "password".to_string(),
            phone: req.phone.clone(),
        };

        let url = self.config.build_url("public/users");
        log::info!("📝 LoginFlowClient - Registering user at: {}", url);
        log::debug!("📦 Request body: {:?}", internal_req);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Registration failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let lf_response: LoginFlowRegisterResponse = response.json().await?;
        log::info!("✅ User registered successfully: {}", lf_response.data.user_id);

        Ok(RegisterResponse {
            user_id: lf_response.data.user_id,
            email: req.email,
            message: lf_response.message,
        })
    }

    /// Login with email and password
    ///
    /// # Arguments
    /// * `req` - Login request with email and password
    ///
    /// # Returns
    /// Login response with JWT token and user data
    pub async fn login(&self, req: LoginRequest) -> LoginFlowResult<LoginResponse> {
        let internal_req = LoginFlowLoginRequest {
            email: req.email.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            password: req.password.clone(),
        };

        let url = self.config.build_url("public/login-password");
        log::info!("🔐 LoginFlowClient - Logging in at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        // LoginFlow wraps response in a wrapper
        let wrapped: LoginFlowResponseWrapper<LoginResponse> = response.json().await?;
        log::info!("✅ User logged in successfully");

        Ok(wrapped.data)
    }

    /// Logout user session
    ///
    /// # Arguments
    /// * `req` - Logout request with user ID and optional session token
    pub async fn logout(&self, req: LogoutRequest) -> LoginFlowResult<()> {
        let url = self.config.build_url("master/logout");
        log::info!("🚪 LoginFlowClient - Logging out user: {}", req.user_id);

        let response = self.http_client
            .post(&url)
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Logout failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        log::info!("✅ User logged out successfully");
        Ok(())
    }

    /// Verify user's email with verification code
    ///
    /// # Arguments
    /// * `req` - Verification request with code and user ID
    pub async fn verify_email(&self, req: VerifyEmailRequest) -> LoginFlowResult<bool> {
        let internal_req = LoginFlowVerifyEmailRequest {
            verification_code: req.verification_code,
            user_id: req.user_id,
            company_id: self.config.company_id.clone(),
        };

        let url = self.config.build_url("public/verify-email");
        log::info!("✉️ LoginFlowClient - Verifying email at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ Email verified successfully");
            Ok(true)
        } else {
            let body = response.text().await.unwrap_or_default();
            log::warn!("⚠️ Email verification failed ({}): {}", status, body);
            Ok(false)
        }
    }

    /// Resend verification code to user's email
    ///
    /// # Arguments
    /// * `req` - Resend request with user ID and email
    ///
    /// # Returns
    /// `true` if the code was resent successfully, `false` otherwise
    pub async fn resend_verification(&self, req: ResendVerificationRequest) -> LoginFlowResult<bool> {
        let internal_req = LoginFlowResendVerificationRequest {
            user_id: req.user_id,
            company_id: self.config.company_id.clone(),
            email: req.email,
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/resend-verification");
        log::info!("✉️ LoginFlowClient - Resending verification at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ Verification code resent successfully");
            Ok(true)
        } else {
            let body = response.text().await.unwrap_or_default();
            log::warn!("⚠️ Resend verification failed ({}): {}", status, body);
            Ok(false)
        }
    }

    // =========================================================================
    // PASSWORD RESET ENDPOINTS (3-step flow)
    // =========================================================================

    /// Step 1: Request password reset (sends verification code to email)
    ///
    /// # Arguments
    /// * `email` - User's email address
    pub async fn request_password_reset(&self, email: &str) -> LoginFlowResult<()> {
        let internal_req = LoginFlowResetPasswordRequest {
            email: email.to_string(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/reset-password");
        log::info!("🔑 LoginFlowClient - Requesting password reset for: {}", email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ Password reset code sent");
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Password reset request failed ({}): {}", status, body);
            Err(LoginFlowError::from_status(status.as_u16(), &body))
        }
    }

    /// Step 2: Verify reset code
    ///
    /// # Arguments
    /// * `req` - Verification request with email and code
    ///
    /// # Returns
    /// Response with reset token for step 3
    pub async fn verify_reset_code(&self, req: VerifyResetCodeRequest) -> LoginFlowResult<VerifyResetCodeResponse> {
        let internal_req = LoginFlowVerifyResetCodeRequest {
            email: req.email.clone(),
            reset_code: req.code.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/reset-password/verify");
        log::info!("🔑 LoginFlowClient - Verifying reset code for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Reset code verification failed ({}): {}", status, body);
            return Err(LoginFlowError::Authentication(
                "Invalid or expired reset code".to_string()
            ));
        }

        // Parse response to extract reset_token
        let json_response: serde_json::Value = response.json().await?;
        let reset_token = json_response
            .get("reset_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| LoginFlowError::ParseError("Missing reset_token in response".to_string()))?
            .to_string();

        log::info!("✅ Reset code verified successfully");
        Ok(VerifyResetCodeResponse { reset_token })
    }

    /// Step 3: Complete password reset with new password
    ///
    /// # Arguments
    /// * `req` - Complete reset request with new password
    ///
    /// # Note
    /// This method internally calls verify_reset_code to get the reset_token
    pub async fn complete_password_reset(&self, req: CompleteResetRequest) -> LoginFlowResult<()> {
        // First verify the code to get reset_token
        let verify_req = VerifyResetCodeRequest {
            email: req.email.clone(),
            code: req.code.clone(),
        };
        let verify_response = self.verify_reset_code(verify_req).await?;

        // Now complete the reset
        let internal_req = LoginFlowCompleteResetRequest {
            email: req.email.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            new_password: req.new_password.clone(),
            confirm_password: req.confirm_password.clone(),
            reset_token: verify_response.reset_token,
        };

        let url = self.config.build_url("public/reset-password/complete");
        log::info!("🔑 LoginFlowClient - Completing password reset for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ Password reset completed successfully");
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Password reset completion failed ({}): {}", status, body);
            Err(LoginFlowError::from_status(status.as_u16(), &body))
        }
    }

    // =========================================================================
    // AUTHENTICATED ENDPOINTS
    // =========================================================================

    /// Change password for authenticated user
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `user_id` - User's UUID
    /// * `company_id` - Company's UUID
    /// * `req` - Change password request
    pub async fn change_password(
        &self,
        token: &str,
        user_id: &str,
        company_id: &str,
        req: ChangePasswordRequest,
    ) -> LoginFlowResult<ChangePasswordResponse> {
        let internal_req = LoginFlowChangePasswordRequest {
            user_id: user_id.to_string(),
            company_id: company_id.to_string(),
            current_password: req.current_password.clone(),
            new_password: req.new_password.clone(),
            confirm_password: req.confirm_password.clone(),
        };

        let url = self.config.build_url("public/change-password");
        log::info!("🔑 LoginFlowClient - Changing password for user: {}", user_id);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            log::info!("✅ Password changed successfully");
            Ok(ChangePasswordResponse {
                success: true,
                message: "Password changed successfully".to_string(),
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Password change failed ({}): {}", status, body);

            // Check for specific error types
            if status.as_u16() == 401 || body.contains("incorrect") || body.contains("invalid") {
                Err(LoginFlowError::Authentication("Current password is incorrect".to_string()))
            } else if status.as_u16() == 400 {
                Err(LoginFlowError::Validation("New password does not meet security requirements".to_string()))
            } else {
                Err(LoginFlowError::from_status(status.as_u16(), &body))
            }
        }
    }

    // =========================================================================
    // USER ACCOUNT ENDPOINTS
    // =========================================================================

    /// Get a user account by ID (returns full account + profile data)
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `account_id` - User account UUID
    pub async fn get_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<FullUserAccountResponse> {
        let url = self.config.build_url(&format!("user-accounts/{}", account_id));
        log::info!("LoginFlowClient - Getting account: {}", account_id);

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Get account failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<FullUserAccountResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Update a user account
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `account_id` - User account UUID
    /// * `req` - Fields to update (role, auth_type, is_active)
    pub async fn update_account(
        &self,
        token: &str,
        account_id: &str,
        req: UpdateUserAccountRequest,
    ) -> LoginFlowResult<UserAccountResponse> {
        let url = self.config.build_url(&format!("user-accounts/{}", account_id));
        log::info!("LoginFlowClient - Updating account: {}", account_id);

        let response = self.http_client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Update account failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<UserAccountResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Soft-delete a user account
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `account_id` - User account UUID
    pub async fn soft_delete_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!("user-accounts/{}/soft-delete", account_id));
        log::info!("LoginFlowClient - Soft-deleting account: {}", account_id);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            log::error!("Soft-delete account failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<OperationResponse> = serde_json::from_str(&body)?;
        Ok(wrapped.data)
    }

    /// Restore a soft-deleted user account
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `account_id` - User account UUID
    pub async fn restore_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!("user-accounts/{}/restore", account_id));
        log::info!("LoginFlowClient - Restoring account: {}", account_id);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            log::error!("Restore account failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<OperationResponse> = serde_json::from_str(&body)?;
        Ok(wrapped.data)
    }

    /// Hard-delete a user account (permanent)
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `account_id` - User account UUID
    pub async fn hard_delete_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!("user-accounts/{}", account_id));
        log::info!("LoginFlowClient - Hard-deleting account: {}", account_id);

        let response = self.http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            log::error!("Hard-delete account failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<OperationResponse> = serde_json::from_str(&body)?;
        Ok(wrapped.data)
    }

    // =========================================================================
    // USER PROFILE ENDPOINTS
    // =========================================================================

    /// Get a user profile by ID
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `profile_id` - User profile UUID
    pub async fn get_profile(
        &self,
        token: &str,
        profile_id: &str,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = self.config.build_url(&format!("user-profiles/{}", profile_id));
        log::info!("LoginFlowClient - Getting profile: {}", profile_id);

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Get profile failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<UserProfileResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Search for a user profile by email
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `email` - Email address to search for
    pub async fn search_profile_by_email(
        &self,
        token: &str,
        email: &str,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = self.config.build_url("user-profiles/search");
        log::info!("LoginFlowClient - Searching profile by email: {}", email);

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .query(&[("email", email)])
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Search profile failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<UserProfileResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Update a user profile
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `profile_id` - User profile UUID
    /// * `req` - Fields to update (email, first_name, last_name)
    pub async fn update_profile(
        &self,
        token: &str,
        profile_id: &str,
        req: UpdateUserProfileRequest,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = self.config.build_url(&format!("user-profiles/{}", profile_id));
        log::info!("LoginFlowClient - Updating profile: {}", profile_id);

        let response = self.http_client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Update profile failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<UserProfileResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Delete a user profile (permanent)
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `profile_id` - User profile UUID
    pub async fn delete_profile(
        &self,
        token: &str,
        profile_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!("user-profiles/{}", profile_id));
        log::info!("LoginFlowClient - Deleting profile: {}", profile_id);

        let response = self.http_client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            log::error!("Delete profile failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<OperationResponse> = serde_json::from_str(&body)?;
        Ok(wrapped.data)
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /// Extract authenticated user from JWT token
    ///
    /// # Warning
    /// This decodes the token without validating the signature.
    /// For untrusted tokens, consider using LoginFlow's /validate endpoint.
    pub fn extract_user_from_token(&self, token: &str) -> LoginFlowResult<AuthenticatedUser> {
        use crate::models::decode_jwt_claims;
        use uuid::Uuid;

        let claims = decode_jwt_claims(token)
            .map_err(|e| LoginFlowError::Authentication(e.to_string()))?;

        let user_id = Uuid::parse_str(&claims.user_id)
            .map_err(|_| LoginFlowError::ParseError("Invalid user_id format".to_string()))?;

        let company_id = Uuid::parse_str(&claims.company_id)
            .unwrap_or_else(|_| Uuid::nil());

        let application_id = Uuid::parse_str(&claims.application_id)
            .unwrap_or_else(|_| Uuid::nil());

        Ok(AuthenticatedUser {
            user_id,
            email: claims.email,
            role: claims.role,
            company_id,
            application_id,
        })
    }
}

impl std::fmt::Debug for LoginFlowClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginFlowClient")
            .field("base_url", &self.config.base_url)
            .field("api_version", &self.config.api_version)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LoginFlowConfig {
        LoginFlowConfig {
            base_url: std::env::var("LOGINFLOW_URL")
                .unwrap_or_else(|_| "https://test-server.example.com".into()),
            api_version: std::env::var("LOGINFLOW_VERSION")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap_or(1),
            company_id: std::env::var("LOGINFLOW_COMPANY")
                .unwrap_or_else(|_| "test-company".into()),
            application_id: std::env::var("LOGINFLOW_APPLICATION")
                .unwrap_or_else(|_| "test-app".into()),
            timeout_secs: 30,
            user_agent: None,
        }
    }

    #[test]
    fn test_client_creation() {
        let config = test_config();
        let expected_url = config.base_url.clone();

        let client = LoginFlowClient::new(config).unwrap();
        assert_eq!(client.config().base_url, expected_url);
    }

    #[test]
    fn test_client_from_env() {
        // Solo corre si las variables están configuradas
        if std::env::var("LOGINFLOW_URL").is_ok() {
            let client = LoginFlowClient::from_env();
            assert!(client.is_ok());
        }
    }
}
