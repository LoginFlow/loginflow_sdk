//! HTTP Client for LoginFlow API
//!
//! Provides async methods for all LoginFlow authentication endpoints and
//! local verification of LoginFlow access tokens (ES256 via JWKS).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use log::{debug, info};
use reqwest::{Client, RequestBuilder};

use crate::config::LoginFlowConfig;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{send_for_data, send_for_flag, send_for_unit};
use crate::jwks::JwksCache;
use crate::models::{
    // Account recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    // Auth
    AuthenticatedUser,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    CompleteResetRequest,
    // Delegated auth
    CreateDelegatedTokenRequest,
    CreateDelegatedTokenResponse,
    // TOTP
    DisableTotpRequest,
    // User account
    FullUserAccountResponse,
    // JWT
    JwtClaims,
    LoginFlowAccountRecoveryRequest,
    LoginFlowCompleteResetRequest,
    LoginFlowCreateDelegatedTokenRequest,
    LoginFlowLoginRequest,
    LoginFlowOAuthLoginRequest,
    LoginFlowOtpLoginRequest,
    LoginFlowRegisterRequest,
    LoginFlowRequestEmailVerificationRequest,
    LoginFlowRequestOtpRequest,
    LoginFlowResendVerificationRequest,
    LoginFlowResetPasswordRequest,
    LoginFlowValidateDelegatedTokenRequest,
    LoginFlowVerifyEmailRequest,
    LoginFlowVerifyResetCodeRequest,
    LoginRequest,
    LoginResponse,
    LoginResult,
    LogoutRequest,
    // OAuth
    OAuthLoginRequest,
    OperationResponse,
    // OTP
    OtpLoginRequest,
    OtpLoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    RegisterRequest,
    RegisterResponse,
    RequestEmailVerificationRequest,
    RequestEmailVerificationResponse,
    RequestOtpRequest,
    RequestOtpResponse,
    ResendVerificationRequest,
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    UpdateUserAccountRequest,
    // User profile
    UpdateUserProfileRequest,
    UserAccountResponse,
    UserProfileResponse,
    ValidateDelegatedTokenRequest,
    VerifyEmailRequest,
    VerifyResetCodeRequest,
    VerifyResetCodeResponse,
    VerifyTotpCodeRequest,
    VerifyTotpLoginRequest,
    VerifyTotpSetupRequest,
};
use crate::refresh_flight::RefreshFlights;

/// Clock skew tolerated when checking `exp`, in seconds.
pub const TOKEN_LEEWAY_SECS: u64 = 30;

/// Message of the [`LoginFlowError::Authentication`] returned for every rejected
/// OTP login code or delegated token (wrong, expired, burned, reused or foreign).
pub const INVALID_CODE_MESSAGE: &str = "The code is invalid or has expired";

/// Message of the [`LoginFlowError::Authentication`] returned for every rejected
/// password reset code.
pub const INVALID_RESET_CODE_MESSAGE: &str = "Invalid or expired reset code";

/// Minimal percent-encoding for query parameter values (no external dependency).
fn urlencoded(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0x0F) as usize]));
            }
        }
    }
    out
}

/// LoginFlow HTTP Client
///
/// Provides async methods for interacting with LoginFlow authentication service.
/// Cloning is cheap: clones share the HTTP connection pool, the JWKS cache and
/// the refreshes in flight.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{LoginFlowClient, LoginFlowConfig, LoginFlowResult};
///
/// fn build() -> LoginFlowResult<LoginFlowClient> {
///     // From environment variables
///     let _from_env = LoginFlowClient::from_env()?;
///
///     // Or with explicit config
///     LoginFlowClient::new(LoginFlowConfig {
///         base_url: "https://api.loginflow.dev".into(),
///         api_version: 1,
///         company_id: "your-company-uuid".into(),
///         application_id: "your-app-uuid".into(),
///         timeout_secs: 30,
///         user_agent: None,
///         issuer: "https://api.loginflow.dev".into(),
///         jwks_url: None,
///         jwks_cache_ttl_secs: 600,
///     })
/// }
/// ```
#[derive(Clone)]
pub struct LoginFlowClient {
    config: LoginFlowConfig,
    http_client: Client,
    jwks: Arc<JwksCache>,
    refresh_flights: Arc<RefreshFlights>,
}

impl LoginFlowClient {
    /// Create a new client with explicit configuration
    ///
    /// # Errors
    /// [`LoginFlowError::Config`] when `issuer`, `application_id` or `base_url`
    /// is empty, or the HTTP client cannot be built.
    pub fn new(config: LoginFlowConfig) -> LoginFlowResult<Self> {
        config.validate()?;

        let mut builder = Client::builder().timeout(Duration::from_secs(config.timeout_secs));
        if let Some(ref user_agent) = config.user_agent {
            builder = builder.user_agent(user_agent);
        }
        let http_client = builder
            .build()
            .map_err(|e| LoginFlowError::Config(format!("Failed to create HTTP client: {}", e)))?;

        let jwks = Arc::new(JwksCache::new(
            http_client.clone(),
            config.resolved_jwks_url(),
            Duration::from_secs(config.jwks_cache_ttl_secs),
        ));

        Ok(Self {
            config,
            http_client,
            jwks,
            refresh_flights: Arc::default(),
        })
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

    /// POST to a versioned endpoint with the shared HTTP client.
    pub(crate) fn post(&self, endpoint: &str) -> RequestBuilder {
        self.http_client.post(self.config.build_url(endpoint))
    }

    fn authorized(request: RequestBuilder, token: &str) -> RequestBuilder {
        request.header("Authorization", format!("Bearer {}", token))
    }

    // =========================================================================
    // AUTHENTICATION ENDPOINTS
    // =========================================================================

    /// Register a new user (`POST /v1/public/user-accounts`).
    ///
    /// The account is always created with role `user`; roles are assigned
    /// only through the master API. A verification code is emailed to the user.
    ///
    /// An email that already has an account in the application gets the same
    /// response with a random, unused `user_id` (no account is created and no
    /// email is sent), so the response never reveals whether the email exists.
    pub async fn register(&self, req: RegisterRequest) -> LoginFlowResult<RegisterResponse> {
        self.register_for(&self.config.company_id, req).await
    }

    /// Login with email and password
    ///
    /// # Returns
    /// - `LoginResult::Success(LoginResponse)` if login succeeds (no TOTP enabled)
    /// - `LoginResult::TotpRequired(TotpChallengeResponse)` if 2FA is needed
    ///
    /// When TOTP is required, use `verify_totp_login()` to complete the login.
    pub async fn login(&self, req: LoginRequest) -> LoginFlowResult<LoginResult> {
        self.login_for(&self.config.company_id, req).await
    }

    /// Refresh the session with the refresh token and session ID.
    ///
    /// The refresh token is rotated: store the returned one. Presenting a
    /// rotated token again (more than 2 s after its rotation) revokes the
    /// session, so refreshes are single-flight: concurrent calls with the same
    /// session and refresh token share one request and all get its result.
    /// Calls with a different token are never joined to it.
    pub async fn refresh_token(
        &self,
        req: RefreshTokenRequest,
    ) -> LoginFlowResult<RefreshTokenResponse> {
        self.refresh_flights
            .run(&req.session_id, &req.refresh_token, || {
                send_for_data(
                    self.post("public/refresh-token").json(&req),
                    "Refresh token",
                )
            })
            .await
    }

    /// Logout (`POST /v1/user/logout`, requires the current access token).
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] when the request names neither a
    /// `session_token` nor `logout_all_devices: Some(true)` (the server rejects it too).
    pub async fn logout(&self, access_token: &str, req: LogoutRequest) -> LoginFlowResult<()> {
        let has_session = req.session_token.as_deref().is_some_and(|s| !s.is_empty());
        let all_devices = req.logout_all_devices.unwrap_or(false);
        if !has_session && !all_devices {
            return Err(LoginFlowError::Validation(
                "Logout requires session_token or logout_all_devices: true".to_string(),
            ));
        }
        send_for_unit(
            Self::authorized(self.post("user/logout"), access_token).json(&req),
            "Logout",
        )
        .await
    }

    /// Verify user's email with verification code
    ///
    /// # Returns
    /// `true` when the code was accepted, `false` when the server rejected it
    /// (wrong, expired, burned after 5 failed attempts or unknown: one `401`).
    ///
    /// # Errors
    /// Rate limits ([`LoginFlowError::RateLimit`]), server errors and transport
    /// errors; they are never reported as `false`.
    pub async fn verify_email(&self, req: VerifyEmailRequest) -> LoginFlowResult<bool> {
        self.verify_email_for(&self.config.company_id, req).await
    }

    /// Resend verification code to user's email
    ///
    /// The server answers the same whether or not a code was sent (unknown user,
    /// email mismatch, already verified), so `true` means "accepted", not "sent".
    ///
    /// # Returns
    /// `true` when the server accepted the request, `false` when it rejected it
    /// (e.g. a malformed email).
    ///
    /// # Errors
    /// [`LoginFlowError::RateLimit`] once the email asked for too many codes
    /// (`retry_after_secs` says how long to wait), server and transport errors.
    pub async fn resend_verification(
        &self,
        req: ResendVerificationRequest,
    ) -> LoginFlowResult<bool> {
        let body = LoginFlowResendVerificationRequest {
            user_id: req.user_id,
            company_id: self.config.company_id.clone(),
            email: req.email,
            application_id: self.config.application_id.clone(),
            language: req.language,
        };
        send_for_flag(
            self.post("public/resend-verification").json(&body),
            "Resend verification",
        )
        .await
    }

    // =========================================================================
    // OTP LOGIN (email code, 2 steps)
    // =========================================================================

    /// Step 1: request a one-time login code by email
    /// (`POST /v1/public/request-otp-login`).
    ///
    /// Whether an unknown email gets an account on step 2 is a per-application
    /// server setting (`allow_self_signup`). The response is identical whether
    /// or not a code was sent (`email_sent_to` is the requested address, masked),
    /// so it never reveals whether the account exists.
    pub async fn request_otp_login(
        &self,
        req: RequestOtpRequest,
    ) -> LoginFlowResult<RequestOtpResponse> {
        self.request_otp_login_for(&self.config.company_id, req)
            .await
    }

    /// Step 2: login with the emailed code (`POST /v1/public/login-with-otp`).
    ///
    /// Returns a full session, same as password login. The code is single-use
    /// and is burned after 5 failed attempts.
    ///
    /// # Errors
    /// Every rejected code is [`LoginFlowError::Authentication`] with
    /// [`INVALID_CODE_MESSAGE`]; rate limits and server errors keep their own variant.
    pub async fn login_with_otp(&self, req: OtpLoginRequest) -> LoginFlowResult<OtpLoginResponse> {
        self.login_with_otp_for(&self.config.company_id, req).await
    }

    // =========================================================================
    // TOTP 2FA ENDPOINTS
    // =========================================================================

    /// Complete login after TOTP challenge (public endpoint, no JWT required)
    ///
    /// Call this after `login()` returns `LoginResult::TotpRequired`.
    pub async fn verify_totp_login(
        &self,
        req: VerifyTotpLoginRequest,
    ) -> LoginFlowResult<LoginResponse> {
        send_for_data(
            self.post("public/verify-totp").json(&req),
            "TOTP login verification",
        )
        .await
    }

    /// Set up TOTP 2FA for the authenticated user
    ///
    /// Returns the secret and otpauth URI for QR code display.
    /// The user must verify with `verify_totp_setup()` to activate TOTP.
    ///
    /// # Arguments
    /// * `token` - Valid access token
    /// * `issuer` - Name the authenticator app shows for the entry. The
    ///   consumer decides it — only it knows what surface the user is
    ///   enrolling into (e.g. "Acme Back Office"). `None` falls back to the
    ///   tenant application's name, then the company's, then no issuer;
    ///   LoginFlow's own name never appears.
    pub async fn setup_totp(
        &self,
        token: &str,
        issuer: Option<&str>,
    ) -> LoginFlowResult<TotpSetupResponse> {
        let mut request = Self::authorized(self.post("user/totp/setup"), token);
        if let Some(issuer) = issuer {
            request = request.json(&TotpSetupRequest {
                issuer: Some(issuer.to_string()),
            });
        }
        send_for_data(request, "TOTP setup").await
    }

    /// Verify TOTP setup by providing a code from the authenticator app
    ///
    /// This activates TOTP 2FA for the user. The server answers with a message
    /// envelope; call `get_totp_status` afterwards if you need the status.
    pub async fn verify_totp_setup(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let body = VerifyTotpSetupRequest {
            code: code.to_string(),
        };
        send_for_unit(
            Self::authorized(self.post("user/totp/verify-setup"), token).json(&body),
            "TOTP setup verification",
        )
        .await
    }

    /// Verify a TOTP code without changing any state
    ///
    /// Answers whether the code matches the user's authenticator right now.
    /// Nothing is enabled, disabled or re-issued, and no email is sent.
    ///
    /// # Errors
    /// `Authentication` when the code does not match; `Validation` when TOTP is
    /// not enabled for the account.
    pub async fn verify_totp_code(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let body = VerifyTotpCodeRequest {
            code: code.to_string(),
        };
        send_for_unit(
            Self::authorized(self.post("user/totp/verify-code"), token).json(&body),
            "TOTP code verification",
        )
        .await
    }

    /// Get the TOTP status for the authenticated user
    pub async fn get_totp_status(&self, token: &str) -> LoginFlowResult<TotpStatusResponse> {
        let request = Self::authorized(
            self.http_client
                .get(self.config.build_url("user/totp/status")),
            token,
        );
        send_for_data(request, "TOTP status").await
    }

    /// Disable TOTP 2FA for the authenticated user (requires a current TOTP code)
    pub async fn disable_totp(&self, token: &str, code: &str) -> LoginFlowResult<()> {
        let body = DisableTotpRequest {
            code: code.to_string(),
        };
        send_for_unit(
            Self::authorized(self.post("user/totp/disable"), token).json(&body),
            "TOTP disable",
        )
        .await
    }

    // =========================================================================
    // OAUTH LOGIN ENDPOINTS
    // =========================================================================

    /// Login with an OAuth provider (Google or Microsoft)
    ///
    /// The frontend handles the OAuth redirect flow and obtains an ID token.
    /// This method sends that token to LoginFlow for server-side validation.
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
    ///         Ok(LoginResult::TotpRequired(_challenge)) => println!("2FA needed"),
    ///         Err(e) => eprintln!("OAuth login failed: {}", e),
    ///     }
    /// }
    /// ```
    pub async fn login_with_oauth(&self, req: OAuthLoginRequest) -> LoginFlowResult<LoginResult> {
        self.login_with_oauth_for(&self.config.company_id, req)
            .await
    }

    // =========================================================================
    // PASSWORD RESET ENDPOINTS (3-step flow)
    // =========================================================================

    /// Step 1: Request password reset (sends verification code to email)
    ///
    /// The server answers with the same message whether or not a code was sent
    /// (unknown email, inactive, unverified or locked account), so `Ok(())` means
    /// "accepted", not "sent".
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] for a malformed email;
    /// [`LoginFlowError::RateLimit`] once the email asked for too many resets
    /// (`retry_after_secs` says how long to wait).
    pub async fn request_password_reset(
        &self,
        email: &str,
        language: Option<&str>,
    ) -> LoginFlowResult<()> {
        self.request_password_reset_for(&self.config.company_id, email, language)
            .await
    }

    /// Step 2: Verify reset code
    ///
    /// The code is an 8-digit string and may start with `0`: keep it as text.
    ///
    /// # Returns
    /// Response with reset token for step 3
    ///
    /// # Errors
    /// Every rejected code is [`LoginFlowError::Authentication`] with
    /// [`INVALID_RESET_CODE_MESSAGE`].
    pub async fn verify_reset_code(
        &self,
        req: VerifyResetCodeRequest,
    ) -> LoginFlowResult<VerifyResetCodeResponse> {
        self.verify_reset_code_for(&self.config.company_id, req)
            .await
    }

    /// Step 3: Complete password reset with new password
    ///
    /// Internally calls `verify_reset_code` to obtain the reset token.
    pub async fn complete_password_reset(&self, req: CompleteResetRequest) -> LoginFlowResult<()> {
        self.complete_password_reset_for(&self.config.company_id, req)
            .await
    }

    // =========================================================================
    // AUTHENTICATED ENDPOINTS
    // =========================================================================

    /// Change the password of the user that owns `token`
    /// (`POST /v1/user/change-password`). The user, company and application
    /// come from the token; the body only carries the passwords.
    pub async fn change_password(
        &self,
        token: &str,
        req: ChangePasswordRequest,
    ) -> LoginFlowResult<ChangePasswordResponse> {
        send_for_data(
            Self::authorized(self.post("user/change-password"), token).json(&req),
            "Password change",
        )
        .await
    }

    // =========================================================================
    // USER ACCOUNT ENDPOINTS (master scope: require a master token)
    // =========================================================================

    /// Get a user account by ID (`GET /v1/master/user-accounts/{id}`, master token)
    pub async fn get_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<FullUserAccountResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-accounts/{}", urlencoded(account_id)));
        send_for_data(
            Self::authorized(self.http_client.get(url), token),
            "Get account",
        )
        .await
    }

    /// Update a user account (`PATCH /v1/master/user-accounts/{id}`, master token)
    pub async fn update_account(
        &self,
        token: &str,
        account_id: &str,
        req: UpdateUserAccountRequest,
    ) -> LoginFlowResult<UserAccountResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-accounts/{}", urlencoded(account_id)));
        send_for_data(
            Self::authorized(self.http_client.patch(url), token).json(&req),
            "Update account",
        )
        .await
    }

    /// Soft-delete a user account (`POST /v1/master/user-accounts/{id}/soft-delete`, master token)
    pub async fn soft_delete_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!(
            "master/user-accounts/{}/soft-delete",
            urlencoded(account_id)
        ));
        send_for_data(
            Self::authorized(self.http_client.post(url), token),
            "Soft-delete account",
        )
        .await
    }

    /// Restore a soft-deleted user account (`POST /v1/master/user-accounts/{id}/restore`, master token)
    pub async fn restore_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self.config.build_url(&format!(
            "master/user-accounts/{}/restore",
            urlencoded(account_id)
        ));
        send_for_data(
            Self::authorized(self.http_client.post(url), token),
            "Restore account",
        )
        .await
    }

    /// Hard-delete a user account (`DELETE /v1/master/user-accounts/{id}`, master token, permanent)
    pub async fn hard_delete_account(
        &self,
        token: &str,
        account_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-accounts/{}", urlencoded(account_id)));
        send_for_data(
            Self::authorized(self.http_client.delete(url), token),
            "Hard-delete account",
        )
        .await
    }

    // =========================================================================
    // USER PROFILE ENDPOINTS (master scope: require a master token)
    // =========================================================================

    /// Get a user profile by ID (`GET /v1/master/user-profiles/{id}`, master token)
    pub async fn get_profile(
        &self,
        token: &str,
        profile_id: &str,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-profiles/{}", urlencoded(profile_id)));
        send_for_data(
            Self::authorized(self.http_client.get(url), token),
            "Get profile",
        )
        .await
    }

    /// Search a user profile by email (`GET /v1/master/user-profiles/search?email=`, master token)
    pub async fn search_profile_by_email(
        &self,
        token: &str,
        email: &str,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = format!(
            "{}?email={}",
            self.config.build_url("master/user-profiles/search"),
            urlencoded(email)
        );
        send_for_data(
            Self::authorized(self.http_client.get(url), token),
            "Search profile",
        )
        .await
    }

    /// Update a user profile (`PATCH /v1/master/user-profiles/{id}`, master token)
    pub async fn update_profile(
        &self,
        token: &str,
        profile_id: &str,
        req: UpdateUserProfileRequest,
    ) -> LoginFlowResult<UserProfileResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-profiles/{}", urlencoded(profile_id)));
        send_for_data(
            Self::authorized(self.http_client.patch(url), token).json(&req),
            "Update profile",
        )
        .await
    }

    /// Delete a user profile (`DELETE /v1/master/user-profiles/{id}`, master token, permanent)
    pub async fn delete_profile(
        &self,
        token: &str,
        profile_id: &str,
    ) -> LoginFlowResult<OperationResponse> {
        let url = self
            .config
            .build_url(&format!("master/user-profiles/{}", urlencoded(profile_id)));
        send_for_data(
            Self::authorized(self.http_client.delete(url), token),
            "Delete profile",
        )
        .await
    }

    // =========================================================================
    // DELEGATED AUTH
    // =========================================================================

    /// Create a delegated authentication token (`POST /v1/user/auth/create-delegated-token`)
    ///
    /// Generates an 8-character token, valid 15 minutes, that someone the token
    /// owner trusts can redeem to sign in as the owner (e.g. parent -> child access).
    pub async fn create_delegated_token(
        &self,
        token: &str,
        req: CreateDelegatedTokenRequest,
    ) -> LoginFlowResult<CreateDelegatedTokenResponse> {
        let body = LoginFlowCreateDelegatedTokenRequest {
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            metadata: req.metadata,
        };
        send_for_data(
            Self::authorized(self.post("user/auth/create-delegated-token"), token).json(&body),
            "Create delegated token",
        )
        .await
    }

    /// Redeem a delegated token and log in as its creator
    /// (`POST /v1/public/auth/validate-delegated-token`).
    ///
    /// The request carries the token and the creator's email. The token is
    /// single-use and is burned after 5 failed attempts.
    ///
    /// # Errors
    /// Every rejected token (wrong, expired, burned, reused, unknown email or a
    /// token of another creator) is [`LoginFlowError::Authentication`] with
    /// [`INVALID_CODE_MESSAGE`].
    pub async fn validate_delegated_token(
        &self,
        req: ValidateDelegatedTokenRequest,
    ) -> LoginFlowResult<LoginResponse> {
        let body = LoginFlowValidateDelegatedTokenRequest {
            code: req.code,
            email: req.email,
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
        };
        send_for_data(
            self.post("public/auth/validate-delegated-token")
                .json(&body),
            "Validate delegated token",
        )
        .await
        .map_err(|err| rejected_code(err, INVALID_CODE_MESSAGE))
    }

    // =========================================================================
    // ACCOUNT RECOVERY
    // =========================================================================

    /// Request account recovery when the user lost access to their email
    /// (`POST /v1/public/auth/request-account-recovery`).
    ///
    /// The response never reveals whether `old_email` has an account or
    /// `new_email` is taken: a ticket ID is always returned, but support only
    /// receives a ticket when the request is actionable.
    pub async fn request_account_recovery(
        &self,
        req: AccountRecoveryRequest,
    ) -> LoginFlowResult<AccountRecoveryResponse> {
        let body = LoginFlowAccountRecoveryRequest {
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
        send_for_data(
            self.post("public/auth/request-account-recovery")
                .json(&body),
            "Account recovery request",
        )
        .await
    }

    // =========================================================================
    // EMAIL VERIFICATION (request)
    // =========================================================================

    /// Request email verification for a user
    ///
    /// Sends a verification code to the user's email (never returned in the
    /// response). Complete it with `verify_email()`.
    pub async fn request_email_verification(
        &self,
        req: RequestEmailVerificationRequest,
    ) -> LoginFlowResult<RequestEmailVerificationResponse> {
        let body = LoginFlowRequestEmailVerificationRequest {
            user_id: req.user_id,
            company_id: self.config.company_id.clone(),
            application_id: self.config.application_id.clone(),
            email: req.email,
            language: req.language,
        };
        send_for_data(
            self.post("public/request-email-verification").json(&body),
            "Email verification request",
        )
        .await
    }

    // =========================================================================
    // TOKEN VERIFICATION
    // =========================================================================

    /// Verify a LoginFlow access token locally.
    ///
    /// 1. The header must carry `alg: ES256` and a `kid`.
    /// 2. The key is taken from the issuer's JWKS (cached, refreshed on an unknown `kid`).
    /// 3. Signature, `iss` (= configured issuer), `aud` (= configured
    ///    application ID) and `exp` (30 s leeway) are checked; `exp`, `iss`,
    ///    `aud` and `sub` must be present.
    /// 4. `token_type` must be `"access"` and `status` must be `"active"`.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] for any token that fails a check;
    /// [`LoginFlowError::Jwks`] when the signing keys cannot be obtained.
    pub async fn verify_token(&self, token: &str) -> LoginFlowResult<JwtClaims> {
        let header = decode_header(token).map_err(|e| reject(format!("malformed token: {e}")))?;
        if header.alg != Algorithm::ES256 {
            return Err(reject(format!("unsupported algorithm {:?}", header.alg)));
        }
        let kid = header
            .kid
            .filter(|k| !k.is_empty())
            .ok_or_else(|| reject("token has no kid".to_string()))?;

        let key = self.jwks.key(&kid).await?;

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.application_id.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = TOKEN_LEEWAY_SECS;

        let claims = decode::<JwtClaims>(token, &key, &validation)
            .map_err(|e| reject(format!("token rejected: {e}")))?
            .claims;

        if !claims.is_access_token() {
            return Err(reject(format!(
                "token_type '{}' is not an access token",
                claims.token_type
            )));
        }
        if !claims.is_active() {
            return Err(reject("user account is not active".to_string()));
        }
        Ok(claims)
    }

    /// Verify an access token and return the user it belongs to.
    ///
    /// Same checks as [`verify_token`](Self::verify_token).
    pub async fn extract_user_from_token(&self, token: &str) -> LoginFlowResult<AuthenticatedUser> {
        let claims = self.verify_token(token).await?;
        AuthenticatedUser::from_claims(&claims)
    }

    // =========================================================================
    // TENANT-SCOPED CALLS (shared by the single- and multi-tenant APIs)
    // =========================================================================

    pub(crate) async fn register_for(
        &self,
        company_id: &str,
        req: RegisterRequest,
    ) -> LoginFlowResult<RegisterResponse> {
        let body = LoginFlowRegisterRequest {
            application_id: self.config.application_id.clone(),
            company_id: company_id.to_string(),
            email: req.email,
            first_name: req.first_name,
            last_name: req.last_name,
            password: req.password,
            auth_type: "password".to_string(),
        };
        let registered: RegisterResponse = send_for_data(
            self.post("public/user-accounts").json(&body),
            "Registration",
        )
        .await?;
        info!("User registered: {}", registered.user_id);
        Ok(registered)
    }

    pub(crate) async fn login_for(
        &self,
        company_id: &str,
        req: LoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        let body = LoginFlowLoginRequest {
            email: req.email,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
            password: req.password,
        };
        send_for_data(self.post("public/login-password").json(&body), "Login").await
    }

    pub(crate) async fn verify_email_for(
        &self,
        company_id: &str,
        req: VerifyEmailRequest,
    ) -> LoginFlowResult<bool> {
        let body = LoginFlowVerifyEmailRequest {
            verification_code: req.verification_code,
            user_id: req.user_id,
            company_id: company_id.to_string(),
            language: req.language,
        };
        send_for_flag(
            self.post("public/verify-email").json(&body),
            "Email verification",
        )
        .await
    }

    pub(crate) async fn request_otp_login_for(
        &self,
        company_id: &str,
        req: RequestOtpRequest,
    ) -> LoginFlowResult<RequestOtpResponse> {
        let body = LoginFlowRequestOtpRequest {
            email: req.email,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
            metadata: req.metadata,
            language: req.language,
        };
        send_for_data(
            self.post("public/request-otp-login").json(&body),
            "OTP request",
        )
        .await
    }

    pub(crate) async fn login_with_otp_for(
        &self,
        company_id: &str,
        req: OtpLoginRequest,
    ) -> LoginFlowResult<OtpLoginResponse> {
        let body = LoginFlowOtpLoginRequest {
            email: req.email,
            code: req.code,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
        };
        send_for_data(self.post("public/login-with-otp").json(&body), "OTP login")
            .await
            .map_err(|err| rejected_code(err, INVALID_CODE_MESSAGE))
    }

    pub(crate) async fn login_with_oauth_for(
        &self,
        company_id: &str,
        req: OAuthLoginRequest,
    ) -> LoginFlowResult<LoginResult> {
        let body = LoginFlowOAuthLoginRequest {
            provider: req.provider,
            id_token: req.id_token,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
        };
        send_for_data(self.post("public/oauth-login").json(&body), "OAuth login").await
    }

    pub(crate) async fn request_password_reset_for(
        &self,
        company_id: &str,
        email: &str,
        language: Option<&str>,
    ) -> LoginFlowResult<()> {
        let body = LoginFlowResetPasswordRequest {
            email: email.to_string(),
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
            language: language.map(String::from),
        };
        send_for_unit(
            self.post("public/reset-password").json(&body),
            "Password reset request",
        )
        .await
    }

    pub(crate) async fn verify_reset_code_for(
        &self,
        company_id: &str,
        req: VerifyResetCodeRequest,
    ) -> LoginFlowResult<VerifyResetCodeResponse> {
        let body = LoginFlowVerifyResetCodeRequest {
            email: req.email,
            reset_code: req.code,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
        };
        send_for_data(
            self.post("public/reset-password/verify").json(&body),
            "Reset code verification",
        )
        .await
        .map_err(|err| rejected_code(err, INVALID_RESET_CODE_MESSAGE))
    }

    pub(crate) async fn complete_password_reset_for(
        &self,
        company_id: &str,
        req: CompleteResetRequest,
    ) -> LoginFlowResult<()> {
        let verified = self
            .verify_reset_code_for(
                company_id,
                VerifyResetCodeRequest {
                    email: req.email.clone(),
                    code: req.code,
                },
            )
            .await?;
        self.complete_password_reset_with_token_for(
            company_id,
            NewPassword {
                email: req.email,
                reset_token: verified.reset_token,
                new_password: req.new_password,
                confirm_password: req.confirm_password,
            },
        )
        .await
    }

    pub(crate) async fn complete_password_reset_with_token_for(
        &self,
        company_id: &str,
        new_password: NewPassword,
    ) -> LoginFlowResult<()> {
        let body = LoginFlowCompleteResetRequest {
            email: new_password.email,
            company_id: company_id.to_string(),
            application_id: self.config.application_id.clone(),
            new_password: new_password.new_password,
            confirm_password: new_password.confirm_password,
            reset_token: new_password.reset_token,
        };
        send_for_unit(
            self.post("public/reset-password/complete").json(&body),
            "Password reset completion",
        )
        .await
    }
}

/// Step 3 of a password reset: the new password plus the reset token from step 2.
pub(crate) struct NewPassword {
    pub email: String,
    pub reset_token: String,
    pub new_password: String,
    pub confirm_password: String,
}

/// A rejected one-time code (`401` or `422`) is reported as one
/// `Authentication(message)`, because the server's own body for it is a generic
/// envelope. Transport, rate-limit and server errors pass through.
fn rejected_code(err: LoginFlowError, message: &str) -> LoginFlowError {
    match err {
        LoginFlowError::Validation(_) | LoginFlowError::Authentication(_) => {
            LoginFlowError::Authentication(message.to_string())
        }
        other => other,
    }
}

fn reject(reason: String) -> LoginFlowError {
    debug!("Access token rejected: {}", reason);
    LoginFlowError::Authentication(format!("Invalid access token: {reason}"))
}

impl fmt::Debug for LoginFlowClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginFlowClient")
            .field("base_url", &self.config.base_url)
            .field("api_version", &self.config.api_version)
            .field("issuer", &self.config.issuer)
            .field("jwks", &self.jwks)
            .finish()
    }
}
