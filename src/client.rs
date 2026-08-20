//! HTTP Client for LoginFlow API
//!
//! Provides async methods for all LoginFlow authentication endpoints.

use std::time::Duration;

use reqwest::Client;

use crate::config::LoginFlowConfig;
use crate::error::{LoginFlowError, LoginFlowResult};

/// Minimal percent-encoding for query parameter values (no external dependency).
fn urlencoded(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0x0F) as usize]));
            }
        }
    }
    out
}
use crate::models::{
    // Auth models
    RegisterRequest, RegisterResponse, LoginRequest, LoginResponse,
    LogoutRequest, RefreshTokenRequest, RefreshTokenResponse, VerifyEmailRequest,
    ResendVerificationRequest, AuthenticatedUser,
    // OTP models
    RequestOtpRequest, RequestOtpResponse, OtpLoginRequest, OtpLoginResponse,
    RequestPasswordlessCodeRequest, RequestPasswordlessCodeResponse, PasswordlessAuthRequest, PasswordlessAuthResponse,
    // TOTP models
    LoginResult, TotpSetupResponse, VerifyTotpSetupRequest, TotpStatusResponse,
    DisableTotpRequest, VerifyTotpCodeRequest, VerifyTotpLoginRequest,
    // OAuth models
    OAuthLoginRequest,
    // Internal auth models
    LoginFlowRegisterRequest, LoginFlowLoginRequest, LoginFlowRegisterData,
    LoginFlowResponseWrapper, LoginFlowVerifyEmailRequest, LoginFlowResendVerificationRequest,
    LoginFlowRequestOtpRequest, LoginFlowOtpLoginRequest,
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
    // Delegated auth models
    CreateDelegatedTokenRequest, CreateDelegatedTokenResponse, ValidateDelegatedTokenRequest,
    LoginFlowCreateDelegatedTokenRequest, LoginFlowValidateDelegatedTokenRequest,
    // Account recovery models
    AccountRecoveryRequest, AccountRecoveryResponse,
    LoginFlowAccountRecoveryRequest,
    // Email verification request models
    RequestEmailVerificationRequest, RequestEmailVerificationResponse,
    LoginFlowRequestEmailVerificationRequest,
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
///         signing_secret: None,
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

        let url = self.config.build_url("public/user-accounts");
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

        let wrapped: LoginFlowResponseWrapper<LoginFlowRegisterData> = response.json().await?;
        log::info!("✅ User registered successfully: {}", wrapped.data.user_id);

        Ok(RegisterResponse {
            user_id: wrapped.data.user_id,
            email: req.email,
            message: "User registered successfully".to_string(),
        })
    }

    /// Login with email and password
    ///
    /// # Returns
    /// - `LoginResult::Success(LoginResponse)` if login succeeds (no TOTP enabled)
    /// - `LoginResult::TotpRequired(TotpChallengeResponse)` if 2FA is needed
    ///
    /// When TOTP is required, use `verify_totp_login()` to complete the login.
    pub async fn login(&self, req: LoginRequest) -> LoginFlowResult<LoginResult> {
        let internal_req = LoginFlowLoginRequest {
            email: req.email.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            password: req.password.clone(),
        };

        let url = self.config.build_url("public/login-password");
        log::info!("LoginFlowClient - Logging in at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResult> = response.json().await?;
        match &wrapped.data {
            LoginResult::TotpRequired(_) => log::info!("Login requires TOTP 2FA"),
            LoginResult::Success(_) => log::info!("User logged in successfully"),
        }

        Ok(wrapped.data)
    }

    /// Refresh access token using refresh token and session id
    ///
    /// # Arguments
    /// * `req` - Refresh request with refresh token and session ID
    ///
    /// # Returns
    /// New access/refresh token pair and their expirations
    pub async fn refresh_token(&self, req: RefreshTokenRequest) -> LoginFlowResult<RefreshTokenResponse> {
        let url = self.config.build_url("public/refresh-token");
        log::info!("🔁 LoginFlowClient - Refreshing token at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Refresh token failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<RefreshTokenResponse> = response.json().await?;
        log::info!("✅ Token refreshed successfully");

        Ok(wrapped.data)
    }

    /// Logout user session
    ///
    /// This endpoint is protected and requires the current access token in
    /// the `Authorization: Bearer <token>` header.
    ///
    /// # Arguments
    /// * `access_token` - Current JWT access token
    /// * `req` - Logout request with user ID and optional session token
    pub async fn logout(&self, access_token: &str, req: LogoutRequest) -> LoginFlowResult<()> {
        let url = self.config.build_url("user/logout");
        log::info!("🚪 LoginFlowClient - Logging out user: {}", req.user_id);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
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
            language: req.language,
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
            language: req.language,
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
    // OTP LOGIN ENDPOINTS (2-step flow)
    // =========================================================================

    /// Step 1: Request OTP code for passwordless login
    ///
    /// Sends a 6-digit code to the user's email. The code expires in 30 minutes.
    /// Rate limited to 3 requests per 15 minutes.
    ///
    /// # Arguments
    /// * `req` - OTP request with email and optional metadata
    ///
    /// # Returns
    /// Response with obfuscated email and expiration info
    pub async fn request_otp_login(&self, req: RequestOtpRequest) -> LoginFlowResult<RequestOtpResponse> {
        let internal_req = LoginFlowRequestOtpRequest {
            email: req.email.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            metadata: req.metadata,
            language: req.language,
        };

        let url = self.config.build_url("public/request-otp-login");
        log::info!("LoginFlowClient - Requesting OTP for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("OTP request failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<RequestOtpResponse> = response.json().await?;
        log::info!("OTP code sent to: {}", wrapped.data.email_sent_to);

        Ok(wrapped.data)
    }

    /// Step 1: Request a passwordless code by email.
    ///
    /// This uses the dedicated backend passwordless flow. On step 2 the backend
    /// will authenticate an existing account or create one if it does not exist.
    pub async fn request_passwordless_code(
        &self,
        req: RequestPasswordlessCodeRequest,
    ) -> LoginFlowResult<RequestPasswordlessCodeResponse> {
        let internal_req = LoginFlowRequestOtpRequest {
            email: req.email.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            metadata: req.metadata,
            language: req.language,
        };

        let url = self.config.build_url("public/request-passwordless-code");
        log::info!("LoginFlowClient - Requesting passwordless code for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Passwordless code request failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<RequestPasswordlessCodeResponse> = response.json().await?;
        log::info!("Passwordless code sent to: {}", wrapped.data.email_sent_to);

        Ok(wrapped.data)
    }

    /// Step 2: Login with OTP code
    ///
    /// Validates the 6-digit code and returns a full JWT session (same as password login).
    /// The code is single-use and deleted after validation.
    ///
    /// # Arguments
    /// * `req` - OTP login request with email and 6-digit code
    ///
    /// # Returns
    /// Login response with JWT, user, company, session, and application info
    pub async fn login_with_otp(&self, req: OtpLoginRequest) -> LoginFlowResult<OtpLoginResponse> {
        let internal_req = LoginFlowOtpLoginRequest {
            email: req.email.clone(),
            code: req.code.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/login-with-otp");
        log::info!("LoginFlowClient - OTP login for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("OTP login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<OtpLoginResponse> = response.json().await?;
        log::info!("OTP login successful");

        Ok(wrapped.data)
    }

    /// Step 2: Authenticate with the passwordless code received by email.
    ///
    /// The backend will log the user in if the account exists, or register and
    /// activate a passwordless account if it does not exist yet.
    pub async fn authenticate_passwordless(
        &self,
        req: PasswordlessAuthRequest,
    ) -> LoginFlowResult<PasswordlessAuthResponse> {
        let internal_req = LoginFlowOtpLoginRequest {
            email: req.email.clone(),
            code: req.code.clone(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/authenticate-passwordless");
        log::info!("LoginFlowClient - Passwordless authentication for: {}", req.email);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Passwordless authentication failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<PasswordlessAuthResponse> = response.json().await?;
        log::info!("Passwordless authentication successful");

        Ok(wrapped.data)
    }

    // =========================================================================
    // TOTP 2FA ENDPOINTS
    // =========================================================================

    /// Complete login after TOTP challenge (public endpoint, no JWT required)
    ///
    /// Call this after `login()` returns `LoginResult::TotpRequired`.
    ///
    /// # Arguments
    /// * `req` - TOTP verification with temporary token and 6-digit code
    ///
    /// # Returns
    /// Full login response with JWT, user, company, session, and application info
    pub async fn verify_totp_login(&self, req: VerifyTotpLoginRequest) -> LoginFlowResult<LoginResponse> {
        let url = self.config.build_url("public/verify-totp");
        log::info!("LoginFlowClient - Verifying TOTP for login");

        let response = self.http_client
            .post(&url)
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("TOTP verification failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResponse> = response.json().await?;
        log::info!("TOTP login completed successfully");

        Ok(wrapped.data)
    }

    /// Set up TOTP 2FA for the authenticated user
    ///
    /// Returns the secret and otpauth URI for QR code display.
    /// The user must verify with `verify_totp_setup()` to activate TOTP.
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    pub async fn setup_totp(&self, token: &str) -> LoginFlowResult<TotpSetupResponse> {
        let url = self.config.build_url("user/totp/setup");
        log::info!("LoginFlowClient - Setting up TOTP");

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("TOTP setup failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<TotpSetupResponse> = response.json().await?;
        log::info!("TOTP setup initiated");

        Ok(wrapped.data)
    }

    /// Verify TOTP setup by providing a code from the authenticator app
    ///
    /// This activates TOTP 2FA for the user. After this, all future logins
    /// will require a TOTP code.
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `code` - 6-digit code from the authenticator app
    pub async fn verify_totp_setup(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let req = VerifyTotpSetupRequest {
            code: code.to_string(),
        };

        let url = self.config.build_url("user/totp/verify-setup");
        log::info!("LoginFlowClient - Verifying TOTP setup");

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("TOTP setup verification failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        // The API confirms with a message envelope, not a TotpStatusResponse
        // (see loginflow_api `totp_verify_setup` -> `ApiResponse::message`).
        // Parsing a status here made every successful activation look like a
        // deserialization failure. Callers needing the status can call
        // `get_totp_status` afterwards.
        log::info!("TOTP 2FA activated");

        Ok(())
    }

    /// Verify a TOTP code without changing any state
    ///
    /// Answers whether the code matches the user's authenticator right now.
    /// Nothing is enabled, disabled or re-issued, and no email is sent —
    /// unlike `verify_totp_setup` (activates) and `disable_totp` (removes).
    ///
    /// Requires `POST /v1/user/totp/verify-code` on the server
    /// (loginflow_api >= the PR that introduced it).
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `code` - Current 6-digit TOTP code
    ///
    /// # Errors
    /// `Unauthorized` when the code does not match; `Validation` when TOTP is
    /// not enabled for the account.
    pub async fn verify_totp_code(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let req = VerifyTotpCodeRequest {
            code: code.to_string(),
        };

        let url = self.config.build_url("user/totp/verify-code");
        log::info!("LoginFlowClient - Verifying TOTP code");

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("TOTP code verification failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        log::info!("TOTP code verified");

        Ok(())
    }

    /// Get the TOTP status for the authenticated user
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    pub async fn get_totp_status(&self, token: &str) -> LoginFlowResult<TotpStatusResponse> {
        let url = self.config.build_url("user/totp/status");
        log::info!("LoginFlowClient - Getting TOTP status");

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("Get TOTP status failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<TotpStatusResponse> = response.json().await?;
        Ok(wrapped.data)
    }

    /// Disable TOTP 2FA for the authenticated user
    ///
    /// Requires a valid current TOTP code as confirmation.
    ///
    /// # Arguments
    /// * `token` - Valid JWT token
    /// * `code` - Current 6-digit TOTP code for confirmation
    pub async fn disable_totp(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let req = DisableTotpRequest {
            code: code.to_string(),
        };

        let url = self.config.build_url("user/totp/disable");
        log::info!("LoginFlowClient - Disabling TOTP");

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("TOTP disable failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        log::info!("TOTP 2FA disabled");
        Ok(())
    }

    // =========================================================================
    // OAUTH LOGIN ENDPOINTS
    // =========================================================================

    /// Login with an OAuth provider (Google or Microsoft)
    ///
    /// The frontend handles the OAuth redirect flow and obtains an ID token.
    /// This method sends that token to LoginFlow for server-side validation
    /// (JWKS signature check, audience, issuer, expiration).
    ///
    /// # Returns
    /// - `LoginResult::Success(LoginResponse)` if login/registration succeeds
    /// - `LoginResult::TotpRequired(TotpChallengeResponse)` if 2FA is enabled
    ///
    /// # Example
    /// ```rust,no_run
    /// use loginflow_sdk::{LoginFlowClient, OAuthLoginRequest, LoginResult};
    ///
    /// async fn oauth_login(client: &LoginFlowClient, id_token: &str) {
    ///     let result = client.login_with_oauth(OAuthLoginRequest {
    ///         provider: "google".to_string(),
    ///         id_token: id_token.to_string(),
    ///     }).await;
    ///
    ///     match result {
    ///         Ok(LoginResult::Success(resp)) => println!("JWT: {}", resp.jwt),
    ///         Ok(LoginResult::TotpRequired(challenge)) => println!("2FA needed"),
    ///         Err(e) => eprintln!("OAuth login failed: {}", e),
    ///     }
    /// }
    /// ```
    pub async fn login_with_oauth(&self, req: OAuthLoginRequest) -> LoginFlowResult<LoginResult> {
        let internal_req = serde_json::json!({
            "provider": req.provider,
            "id_token": req.id_token,
            "company_id": self.config.company_id,
            "application_id": self.config.application_id,
        });

        let url = self.config.build_url("public/oauth-login");
        log::info!("LoginFlowClient - OAuth login ({}) at: {}", req.provider, url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("OAuth login failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResult> = response.json().await?;
        match &wrapped.data {
            LoginResult::TotpRequired(_) => log::info!("OAuth login requires TOTP 2FA"),
            LoginResult::Success(_) => log::info!("OAuth login successful"),
        }

        Ok(wrapped.data)
    }

    // =========================================================================
    // PASSWORD RESET ENDPOINTS (3-step flow)
    // =========================================================================

    /// Step 1: Request password reset (sends verification code to email)
    ///
    /// # Arguments
    /// * `email` - User's email address
    pub async fn request_password_reset(&self, email: &str, language: Option<&str>) -> LoginFlowResult<()> {
        let internal_req = LoginFlowResetPasswordRequest {
            email: email.to_string(),
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            language: language.map(String::from),
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

        // Parse AulaMás response to extract reset_token from data envelope
        let json_response: serde_json::Value = response.json().await?;
        let reset_token = json_response
            .get("data")
            .and_then(|d| d.get("reset_token"))
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

        let url = self.config.build_url("user/change-password");
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
        let base_url = self.config.build_url("user-profiles/search");
        let url = format!("{}?email={}", base_url, urlencoded(email));
        log::info!("LoginFlowClient - Searching profile by email: {}", email);

        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
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
    // DELEGATED AUTH
    // =========================================================================

    /// Create a delegated authentication token
    ///
    /// Generates a 6-digit code that can be shared with another user to allow
    /// them to log in on behalf of the token creator (e.g. parent → child access).
    /// The code expires after 24 hours.
    ///
    /// # Arguments
    /// * `token` - JWT access token of the creator (required, this is a protected endpoint)
    /// * `req` - Optional metadata to attach to the delegation
    pub async fn create_delegated_token(
        &self,
        token: &str,
        req: CreateDelegatedTokenRequest,
    ) -> LoginFlowResult<CreateDelegatedTokenResponse> {
        let internal_req = LoginFlowCreateDelegatedTokenRequest {
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            metadata: req.metadata,
        };

        let url = self.config.build_url("user/auth/create-delegated-token");
        log::info!("🔑 LoginFlowClient - Creating delegated token at: {}", url);

        let response = self.http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Create delegated token failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<CreateDelegatedTokenResponse> = response.json().await?;
        log::info!("✅ Delegated token created: code={}", wrapped.data.code);
        Ok(wrapped.data)
    }

    /// Validate a delegated token and log in
    ///
    /// Uses a 6-digit code received from the token creator to authenticate
    /// as the creator's user. Returns the same response as a normal login.
    ///
    /// # Arguments
    /// * `req` - Validation request with the 6-digit code
    pub async fn validate_delegated_token(
        &self,
        req: ValidateDelegatedTokenRequest,
    ) -> LoginFlowResult<LoginResponse> {
        let internal_req = LoginFlowValidateDelegatedTokenRequest {
            code: req.code,
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };

        let url = self.config.build_url("public/auth/validate-delegated-token");
        log::info!("🔑 LoginFlowClient - Validating delegated token at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Validate delegated token failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<LoginResponse> = response.json().await?;
        log::info!("✅ Delegated token validated, user: {}", wrapped.data.user.id);
        Ok(wrapped.data)
    }

    // =========================================================================
    // ACCOUNT RECOVERY
    // =========================================================================

    /// Request account recovery when user loses access to their email
    ///
    /// Sends a recovery request to the company's support email. This creates
    /// a support ticket that must be processed manually.
    ///
    /// # Arguments
    /// * `req` - Recovery request with old/new emails and supporting info
    pub async fn request_account_recovery(
        &self,
        req: AccountRecoveryRequest,
    ) -> LoginFlowResult<AccountRecoveryResponse> {
        let internal_req = LoginFlowAccountRecoveryRequest {
            old_email: req.old_email,
            new_email: req.new_email,
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            reason: req.reason,
            full_name: req.full_name,
            phone: req.phone,
            additional_info: req.additional_info,
            language: req.language,
        };

        let url = self.config.build_url("public/auth/request-account-recovery");
        log::info!("🔑 LoginFlowClient - Requesting account recovery at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Account recovery request failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<AccountRecoveryResponse> = response.json().await?;
        log::info!("✅ Account recovery request submitted");
        Ok(wrapped.data)
    }

    // =========================================================================
    // EMAIL VERIFICATION (request)
    // =========================================================================

    /// Request email verification for a user
    ///
    /// Initiates the email verification flow by sending a verification code
    /// to the user's email. Use `verify_email()` to complete the verification.
    ///
    /// # Arguments
    /// * `req` - Request with user_id, email, and optional skip_email flag
    pub async fn request_email_verification(
        &self,
        req: RequestEmailVerificationRequest,
    ) -> LoginFlowResult<RequestEmailVerificationResponse> {
        let internal_req = LoginFlowRequestEmailVerificationRequest {
            user_id: req.user_id,
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            email: req.email,
            skip_email: req.skip_email,
            language: req.language,
        };

        let url = self.config.build_url("public/request-email-verification");
        log::info!("✉️ LoginFlowClient - Requesting email verification at: {}", url);

        let response = self.http_client
            .post(&url)
            .json(&internal_req)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            log::error!("❌ Request email verification failed ({}): {}", status, body);
            return Err(LoginFlowError::from_status(status.as_u16(), &body));
        }

        let wrapped: LoginFlowResponseWrapper<RequestEmailVerificationResponse> = response.json().await?;
        log::info!("✅ Email verification requested successfully");
        Ok(wrapped.data)
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /// Verify a JWT token's signature and expiration locally using the signing_secret.
    ///
    /// This validates the HMAC-SHA256 signature and checks expiration without
    /// hitting the LoginFlow server. Requires `signing_secret` in config.
    ///
    /// # Returns
    /// Validated `JwtClaims` with full token data
    pub fn verify_token(&self, token: &str) -> LoginFlowResult<crate::models::JwtClaims> {
        let signing_secret = self.config.signing_secret.as_ref().ok_or_else(|| {
            LoginFlowError::Config(
                "signing_secret not configured. Set LOGINFLOW_SIGNING_SECRET or pass it in LoginFlowConfig.".to_string(),
            )
        })?;

        crate::models::verify_jwt_claims(token, signing_secret)
            .map_err(|e| LoginFlowError::Authentication(e.to_string()))
    }

    /// Check if the client has a signing_secret configured for local JWT verification.
    pub fn can_verify_locally(&self) -> bool {
        self.config.signing_secret.is_some()
    }

    /// Extract authenticated user from JWT token.
    ///
    /// When `signing_secret` is configured, this verifies the signature first.
    /// Without it, only decodes the payload (no signature validation).
    pub fn extract_user_from_token(&self, token: &str) -> LoginFlowResult<AuthenticatedUser> {
        use uuid::Uuid;

        let claims = if self.can_verify_locally() {
            self.verify_token(token)?
        } else {
            crate::models::decode_jwt_claims(token)
                .map_err(|e| LoginFlowError::Authentication(e.to_string()))?
        };

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
            base_url: std::env::var("LOGIN_FLOW_URL")
                .unwrap_or_else(|_| "https://test-server.example.com".into()),
            api_version: std::env::var("LOGIN_FLOW_VERSION")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap_or(1),
            company_id: std::env::var("LOGIN_FLOW_COMPANY")
                .unwrap_or_else(|_| "test-company".into()),
            application_id: std::env::var("LOGIN_FLOW_APPLICATION")
                .unwrap_or_else(|_| "test-app".into()),
            timeout_secs: 30,
            user_agent: None,
            signing_secret: None,
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
        if std::env::var("LOGIN_FLOW_URL").is_ok() {
            let client = LoginFlowClient::from_env();
            assert!(client.is_ok());
        }
    }

    #[test]
    fn test_urlencoded_simple_ascii() {
        assert_eq!(urlencoded("hello"), "hello");
        assert_eq!(urlencoded("test123"), "test123");
    }

    #[test]
    fn test_urlencoded_email() {
        assert_eq!(urlencoded("user@example.com"), "user%40example.com");
    }

    #[test]
    fn test_urlencoded_special_characters() {
        assert_eq!(urlencoded("a b"), "a%20b");
        assert_eq!(urlencoded("foo&bar=baz"), "foo%26bar%3Dbaz");
        assert_eq!(urlencoded("hello+world"), "hello%2Bworld");
    }

    #[test]
    fn test_urlencoded_preserves_unreserved() {
        assert_eq!(urlencoded("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn test_urlencoded_empty() {
        assert_eq!(urlencoded(""), "");
    }

    #[test]
    fn test_search_profile_url_construction() {
        let config = test_config();
        let base_url = config.build_url("user-profiles/search");
        let email = "test@example.com";
        let url = format!("{}?email={}", base_url, urlencoded(email));
        assert!(url.contains("user-profiles/search?email=test%40example.com"));
    }
}
