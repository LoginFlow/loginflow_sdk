//! HTTP Client for LoginFlow API
//!
//! Provides async methods for all LoginFlow authentication endpoints and
//! local verification of LoginFlow access tokens (ES256 via JWKS).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use log::debug;
use reqwest::{Client, RequestBuilder};
use tokio::sync::OnceCell;

use crate::config::LoginFlowConfig;
use crate::discovery::{self, DiscoveryDocument};
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{expect_success, read_capped, send_for_data, send_for_unit};
use crate::jwks::JwksCache;
use crate::models::{
    // JWT
    ACCESS_TOKEN_JWT_TYP,
    // Account recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    // Auth
    AuthenticatedUser,
    BACKCHANNEL_LOGOUT_EVENT_URI,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    // TOTP
    DisableTotpRequest,
    // User account
    FullUserAccountResponse,
    JwtClaims,
    LOGOUT_TOKEN_JWT_TYP,
    LoginFlowAccountRecoveryRequest,
    LogoutTokenClaims,
    OperationResponse,
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    UpdateUserAccountRequest,
    // User profile
    UpdateUserProfileRequest,
    UserAccountResponse,
    // Userinfo
    UserInfoResponse,
    UserProfileResponse,
    VerifyTotpSetupRequest,
};

/// Clock skew tolerated when checking `exp`, in seconds.
pub const TOKEN_LEEWAY_SECS: u64 = 30;

/// Maximum size of a `GET /oauth2/userinfo` response body.
const USERINFO_BODY_LIMIT: usize = 16 * 1024;

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
/// Cloning is cheap: clones share the HTTP connection pool and the JWKS cache.
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
    discovery: Arc<OnceCell<DiscoveryDocument>>,
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
            discovery: Arc::new(OnceCell::new()),
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

    /// The issuer's `.well-known/openid-configuration` document, fetched once and cached for the
    /// lifetime of this client (and every clone, which shares the cache). Every endpoint this
    /// SDK calls that has a discovery entry — `userinfo`, and the `token`/`introspection`/
    /// `revocation` endpoints a caller builds an [`crate::ClientCredentialsClient`],
    /// [`crate::IntrospectionClient`] or [`crate::RevocationClient`] from via their
    /// `from_discovery` constructors — is resolved from here, never hardcoded.
    ///
    /// # Errors
    /// [`LoginFlowError::Network`] when the document cannot be fetched;
    /// [`LoginFlowError::ParseError`] when it does not parse.
    pub async fn discovery(&self) -> LoginFlowResult<&DiscoveryDocument> {
        self.discovery
            .get_or_try_init(|| discovery::fetch(&self.http_client, &self.config.base_url))
            .await
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

    // =========================================================================
    // OTP LOGIN (email code, 2 steps)
    // =========================================================================

    // =========================================================================
    // TOTP 2FA ENDPOINTS
    // =========================================================================

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

    // =========================================================================
    // PASSWORD RESET ENDPOINTS (3-step flow)
    // =========================================================================

    // =========================================================================
    // AUTHENTICATED ENDPOINTS
    // =========================================================================

    /// Change the password of the user that owns `token`
    /// (`POST /v1/user/change-password`). The user, company and application
    /// come from the token; the body carries only the new password (SDK v0.6.0:
    /// RFC 6749 §4.1.3).
    ///
    /// Requires a recent authentication: the access token's `auth_time` must be
    /// within the last 300 s, or the server answers `401` with
    /// `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, surfaced
    /// here as [`LoginFlowError::InsufficientUserAuthentication`]. The caller must
    /// have the user step up (re-authenticate) and retry.
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

    // =========================================================================
    // USERINFO (OIDC Core §5.3.2)
    // =========================================================================

    /// `GET /oauth2/userinfo`: resolves `sub` and, by scope, `role`/`user_id` (needs `profile`)
    /// and `email` (needs `email`) live from the repository. This is the one sanctioned way to
    /// read a user's email in SDK v0.6.0 — the access token itself carries none.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when the token is rejected (expired, wrong scope,
    /// revoked); network/parse errors otherwise.
    pub async fn userinfo(&self, access_token: &str) -> LoginFlowResult<UserInfoResponse> {
        let url = self.discovery().await?.userinfo_endpoint.clone();
        let response = expect_success(
            Self::authorized(self.http_client.get(url), access_token)
                .send()
                .await?,
            "userinfo",
        )
        .await?;
        let body = read_capped(response, USERINFO_BODY_LIMIT)
            .await
            .map_err(|e| LoginFlowError::Network(e.to_string()))?;
        serde_json::from_slice(&body.bytes)
            .map_err(|e| LoginFlowError::ParseError(format!("invalid userinfo response: {e}")))
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
    ///
    /// The access token carries no account status: it is checked live wherever it matters
    /// (session end, revocation), never from a claim cached at issuance time.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] for any token that fails a check;
    /// [`LoginFlowError::Jwks`] when the signing keys cannot be obtained.
    pub async fn verify_token(&self, token: &str) -> LoginFlowResult<JwtClaims> {
        // RFC 9068 §2.1: an AS/RS MUST only process JWTs explicitly typed as access tokens.
        // A refresh/ID/temporary token (or anything else bearing a valid signature) never has
        // `typ: at+jwt`, so this check alone rejects a whole class of token-confusion attacks
        // before a single claim is even looked at.
        let key = self
            .verification_key(token, ACCESS_TOKEN_JWT_TYP, "an access token")
            .await?;

        let mut validation = self.issuer_validation();
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = TOKEN_LEEWAY_SECS;

        let claims = decode::<JwtClaims>(token, &key, &validation)
            .map_err(|e| reject(format!("token rejected: {e}")))?
            .claims;
        Ok(claims)
    }

    /// Verify an access token and return the user it belongs to.
    ///
    /// Same checks as [`verify_token`](Self::verify_token).
    pub async fn extract_user_from_token(&self, token: &str) -> LoginFlowResult<AuthenticatedUser> {
        let claims = self.verify_token(token).await?;
        AuthenticatedUser::from_claims(&claims)
    }

    /// Verify an OIDC Back-Channel Logout 1.0 §2.4 logout token delivered to this RP's own
    /// `backchannel_logout_uri`.
    ///
    /// Checks (§2.6): header `typ: logout+jwt`, ES256 signature via the issuer's JWKS, `iss`
    /// (= configured issuer), `aud` (= configured application ID), the single `events` member
    /// present, `sub` and/or `sid` present, and — the one check only this method bothers with,
    /// since a stray `nonce` is precisely what would let an ID token be replayed as a logout
    /// token — **no `nonce` claim**. There is no `exp` check: OIDC Back-Channel Logout 1.0
    /// deliberately leaves `exp` optional on this token type.
    ///
    /// Single-use enforcement of `jti` is the caller's responsibility (this SDK holds no
    /// storage): track delivered `jti`s for as long as a reasonable delivery-retry window, and
    /// reject a repeat.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] for any token that fails a check;
    /// [`LoginFlowError::Jwks`] when the signing keys cannot be obtained.
    pub async fn verify_logout_token(&self, token: &str) -> LoginFlowResult<LogoutTokenClaims> {
        let key = self
            .verification_key(token, LOGOUT_TOKEN_JWT_TYP, "a logout token")
            .await?;

        let mut validation = self.issuer_validation();
        validation.set_required_spec_claims(&["iss", "aud", "iat", "jti"]);
        // OIDC Back-Channel Logout 1.0 §2.4: `exp` is OPTIONAL on a logout token.
        validation.validate_exp = false;

        let claims = decode::<LogoutTokenClaims>(token, &key, &validation)
            .map_err(|e| reject(format!("logout token rejected: {e}")))?
            .claims;

        // §2.6 point 7: a logout token distinguishes itself from an ID token by never carrying
        // `nonce` — a token that has one is rejected outright, not merely ignored.
        if claims.nonce.is_some() {
            return Err(reject("a logout token must not carry a nonce".to_string()));
        }
        if claims.sub.is_none() && claims.sid.is_none() {
            return Err(reject(
                "a logout token must carry sub and/or sid".to_string(),
            ));
        }
        if claims.events.get(BACKCHANNEL_LOGOUT_EVENT_URI).is_none() {
            return Err(reject(
                "a logout token must carry the backchannel-logout event".to_string(),
            ));
        }
        Ok(claims)
    }

    /// Header checks shared by every token this SDK verifies — `alg: ES256`, the expected `typ`
    /// and a non-empty `kid` — and the issuer's JWKS key that `kid` names.
    async fn verification_key(
        &self,
        token: &str,
        expected_typ: &str,
        token_kind: &str,
    ) -> LoginFlowResult<DecodingKey> {
        let header = decode_header(token).map_err(|e| reject(format!("malformed token: {e}")))?;
        if header.alg != Algorithm::ES256 {
            return Err(reject(format!("unsupported algorithm {:?}", header.alg)));
        }
        if header.typ.as_deref() != Some(expected_typ) {
            return Err(reject(format!(
                "header typ {:?} is not {token_kind} (expected {:?})",
                header.typ, expected_typ
            )));
        }
        let kid = header
            .kid
            .filter(|k| !k.is_empty())
            .ok_or_else(|| reject("token has no kid".to_string()))?;
        self.jwks.key(&kid).await
    }

    /// ES256 validation pinned to the configured issuer and application (`aud`).
    fn issuer_validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.application_id.as_str()]);
        validation
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
