//! HTTP Client for LoginFlow API
//!
//! Provides async methods for the LoginFlow endpoints a resource server calls, and the local
//! checks of LoginFlow tokens (ES256 via JWKS) that [`crate::TokenVerifier`] builds on.

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
use crate::http::{build_http_client, expect_success, read_capped, send_for_data, send_for_unit};
use crate::jwks::JwksCache;
use crate::models::{
    // JWT
    ACCESS_TOKEN_JWT_TYP,
    AccessClaims,
    // Account recovery
    AccountRecoveryRequest,
    AccountRecoveryResponse,
    BACKCHANNEL_LOGOUT_EVENT_URI,
    // Password
    ChangePasswordRequest,
    ChangePasswordResponse,
    // TOTP
    DisableTotpRequest,
    LOGOUT_TOKEN_JWT_TYP,
    LoginFlowAccountRecoveryRequest,
    LogoutTokenClaims,
    TotpSetupRequest,
    TotpSetupResponse,
    TotpStatusResponse,
    // Userinfo
    UserInfoResponse,
    VerifyTotpSetupRequest,
};

/// Clock skew tolerated when checking `exp`, in seconds.
pub const TOKEN_LEEWAY_SECS: u64 = 30;

/// Maximum size of a `GET /oauth2/userinfo` response body.
const USERINFO_BODY_LIMIT: usize = 16 * 1024;

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
///         company_id: "CP-your-company".into(),
///         api_audience: "https://api.your-product.example".into(),
///         timeout_secs: 30,
///         user_agent: None,
///         issuer: "https://api.loginflow.dev".into(),
///         jwks_url: None,
///         jwks_cache_ttl_secs: 600,
///         resource_base_url: None, // DPoP `htu` base; None = derived from the request
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
    /// [`LoginFlowError::Config`] when the configuration is invalid (see
    /// [`LoginFlowConfig::validate`]), or the HTTP client cannot be built.
    pub fn new(config: LoginFlowConfig) -> LoginFlowResult<Self> {
        config.validate()?;

        let http_client = build_http_client(&config)?;

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
    // ACCOUNT CALLS ON BEHALF OF A PERSON
    //
    // `token` is the person's own access token, sent as `Authorization: Bearer`. A DPoP-bound
    // token (`cnf`) needs a proof signed by the person's device key, which a backend never
    // holds: LoginFlow refuses it (`401`, `LoginFlowError::Authentication`).
    // =========================================================================

    /// `POST /v1/user/totp/setup`: start TOTP 2FA enrollment for the person `token` belongs to.
    ///
    /// Returns the secret and otpauth URI for QR code display (`Debug` redacts both). The user
    /// must confirm with [`verify_totp_setup`](Self::verify_totp_setup) to activate TOTP; a new
    /// setup replaces a pending one.
    ///
    /// # Arguments
    /// * `token` - the person's access token (`Bearer`, not DPoP-bound)
    /// * `issuer` - Name the authenticator app shows for the entry. The
    ///   consumer decides it — only it knows what surface the user is
    ///   enrolling into (e.g. "Acme Back Office"). `None` falls back to the
    ///   tenant application's name, then the company's, then no issuer;
    ///   LoginFlow's own name never appears.
    ///
    /// # Errors
    /// [`LoginFlowError::NotFound`] when the token's account does not exist in its tenant;
    /// [`LoginFlowError::Authentication`] when the token is refused.
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

    /// `POST /v1/user/totp/verify-setup`: confirm the enrollment with a current code from the
    /// authenticator app, which activates TOTP 2FA. Call
    /// [`get_totp_status`](Self::get_totp_status) afterwards if you need the status.
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] with `code` [`crate::INVALID_CODE`] for a wrong code or a
    /// locked-out account (the token is fine: never sign the person out for it), and with `code`
    /// `BAD_REQUEST` when TOTP is already enabled or no setup was started.
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

    /// `GET /v1/user/totp/status`: whether TOTP 2FA is enabled for the person `token` belongs
    /// to, and since when.
    pub async fn get_totp_status(&self, token: &str) -> LoginFlowResult<TotpStatusResponse> {
        let request = Self::authorized(
            self.http_client
                .get(self.config.build_url("user/totp/status")),
            token,
        );
        send_for_data(request, "TOTP status").await
    }

    /// `POST /v1/user/totp/disable`: disable TOTP 2FA, confirmed with a current code.
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] with `code` [`crate::INVALID_CODE`] for a wrong code or a
    /// locked-out account, and with `code` `BAD_REQUEST` when TOTP is not enabled.
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

    /// `POST /v1/user/change-password`: change the password of the person `token` belongs to.
    /// The user, company and application come from the token; the body carries only the new
    /// password. On success every OTHER session of the person in the company ends (with a
    /// back-channel logout); the session `token` belongs to is kept.
    ///
    /// Requires a recent authentication: the access token's `auth_time` must be
    /// within the last 300 s, or the server answers `401` with
    /// `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, surfaced
    /// here as [`LoginFlowError::InsufficientUserAuthentication`]. The caller must
    /// have the user step up (re-authenticate) and retry.
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] with the server's reason as the message (weak, reused or
    /// breached password); [`LoginFlowError::Validation`] with `code` `BAD_REQUEST` for an
    /// account without a password (it signs in another way);
    /// [`LoginFlowError::ServiceUnavailable`] when the server is busy.
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

    /// `POST /v1/public/auth/request-account-recovery`: ask the company's support to move an
    /// account whose email the person lost access to (no token; the configured company is
    /// sent).
    ///
    /// The response never reveals whether `old_email` has an account or
    /// `new_email` is taken: a ticket ID is always returned, but support only
    /// receives a ticket when the request is actionable.
    ///
    /// # Errors
    /// [`LoginFlowError::Validation`] for a malformed email, the same email twice, or a company
    /// without a support email; [`LoginFlowError::RateLimit`] after 3 tickets per application
    /// and email in 15 minutes; [`LoginFlowError::NotFound`] for an unknown company.
    pub async fn request_account_recovery(
        &self,
        req: AccountRecoveryRequest,
    ) -> LoginFlowResult<AccountRecoveryResponse> {
        let body = LoginFlowAccountRecoveryRequest {
            old_email: req.old_email,
            new_email: req.new_email,
            company_id: self.config.company_id.clone(),
            application_id: req.application_id,
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
    // USERINFO (OIDC Core §5.3.2)
    // =========================================================================

    /// `GET /oauth2/userinfo` (endpoint read from discovery): resolves `sub` and, by scope,
    /// `user_id` (needs `profile`) and `email` (needs `email`) live. This is the one sanctioned
    /// way to read a person's email: the access token itself carries none. `access_token` must
    /// carry `openid` and be a `Bearer` token (not DPoP-bound, see the account calls above).
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when the token is rejected (expired, revoked, ended
    /// session, DPoP-bound); [`LoginFlowError::Authorization`] without the `openid` scope;
    /// network/parse errors otherwise.
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

    /// Verify a LoginFlow access token locally: the header checks of [`access_token_kid`], the
    /// issuer's JWKS key it names, and the claims checks of [`decode_access_claims`] against the
    /// configured issuer and API audience, and the token's `company_id` = the configured company
    /// (`LOGINFLOW_COMPANY`): an application can belong to several companies and its API
    /// audience is per application, so `aud` alone does not keep another company out.
    /// [`crate::TokenVerifier`] adds the DPoP binding and the permissions on top; it is the one
    /// public way to verify an access token.
    pub(crate) async fn verify_access_token(&self, token: &str) -> LoginFlowResult<AccessClaims> {
        let kid = access_token_kid(token)?;
        let key = self.jwks.key(&kid).await?;
        decode_access_claims(
            token,
            &key,
            &AccessTokenExpectation {
                issuer: &self.config.issuer,
                audience: &self.config.api_audience,
                company_id: &self.config.company_id,
            },
        )
    }

    /// Verify an OIDC Back-Channel Logout 1.0 §2.4 logout token delivered to this RP's own
    /// `backchannel_logout_uri`. `client_id` is the RP's own OAuth client: LoginFlow addresses
    /// the token to it (`aud`), never to an API.
    ///
    /// Checks (§2.6): header `typ: logout+jwt`, ES256 signature via the issuer's JWKS, `iss`
    /// (= configured issuer), `aud` (= `client_id`), the single `events` member present, `sub`
    /// and/or `sid` present, and — the one check only this method bothers with, since a stray
    /// `nonce` is precisely what would let an ID token be replayed as a logout token — **no
    /// `nonce` claim**. There is no `exp` check: OIDC Back-Channel Logout 1.0 deliberately leaves
    /// `exp` optional on this token type.
    ///
    /// Single-use enforcement of `jti` is the caller's responsibility: track delivered `jti`s
    /// (a [`crate::JtiReplayCache`] does) for as long as a reasonable delivery-retry window, and
    /// reject a repeat.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] for any token that fails a check;
    /// [`LoginFlowError::Jwks`] when the signing keys cannot be obtained.
    pub async fn verify_logout_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> LoginFlowResult<LogoutTokenClaims> {
        let kid = token_kid(token, LOGOUT_TOKEN_JWT_TYP, "a logout token")?;
        let key = self.jwks.key(&kid).await?;

        let mut validation = es256_validation(&self.config.issuer, client_id);
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
}

/// The only signature algorithm LoginFlow signs tokens with; a token naming any other `alg`
/// (`none`, `HS256` with the public key as secret, …) is refused before its key is looked up.
pub(crate) const ALLOWED_ALGORITHMS: [Algorithm; 1] = [Algorithm::ES256];

/// Header checks of an access token: `alg` in [`ALLOWED_ALGORITHMS`], `typ: at+jwt` (RFC 9068
/// §2.1: a refresh, ID or logout token, or anything else bearing a valid signature, never has
/// it) and a non-empty `kid`, which is returned.
pub(crate) fn access_token_kid(token: &str) -> LoginFlowResult<String> {
    token_kid(token, ACCESS_TOKEN_JWT_TYP, "an access token")
}

/// What an access token must name: the issuer, this API and this company.
pub(crate) struct AccessTokenExpectation<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub company_id: &'a str,
}

/// Claims checks of an access token signed by `key`: signature, `iss` = the issuer, `aud` = the
/// API, `exp` (with [`TOKEN_LEEWAY_SECS`]), and `company_id` = the company: an application can
/// belong to several companies and its API audience is per application, so `aud` alone does not
/// keep another company's token out. `exp`, `iss`, `aud` and `sub` must be present. Shared by
/// [`LoginFlowClient`] and the `testing` feature's `FakeVerifier`, so both check the same.
pub(crate) fn decode_access_claims(
    token: &str,
    key: &DecodingKey,
    expected: &AccessTokenExpectation<'_>,
) -> LoginFlowResult<AccessClaims> {
    let mut validation = es256_validation(expected.issuer, expected.audience);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = TOKEN_LEEWAY_SECS;
    let claims = decode::<AccessClaims>(token, key, &validation)
        .map(|data| data.claims)
        .map_err(|e| reject(format!("token rejected: {e}")))?;
    if claims.company_id != expected.company_id {
        return Err(reject("the token is for another company".to_string()));
    }
    Ok(claims)
}

/// Header checks shared by every token this SDK verifies — `alg` allowed, the expected `typ`
/// and a non-empty `kid`, which is returned.
fn token_kid(token: &str, expected_typ: &str, token_kind: &str) -> LoginFlowResult<String> {
    let header = decode_header(token).map_err(|e| reject(format!("malformed token: {e}")))?;
    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(reject(format!("unsupported algorithm {:?}", header.alg)));
    }
    if header.typ.as_deref() != Some(expected_typ) {
        return Err(reject(format!(
            "header typ {:?} is not {token_kind} (expected {:?})",
            header.typ, expected_typ
        )));
    }
    header
        .kid
        .filter(|k| !k.is_empty())
        .ok_or_else(|| reject("token has no kid".to_string()))
}

/// Validation pinned to [`ALLOWED_ALGORITHMS`], `issuer` and `audience`.
fn es256_validation(issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.algorithms = ALLOWED_ALGORITHMS.to_vec();
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation
}

fn reject(reason: String) -> LoginFlowError {
    debug!("Token rejected: {}", reason);
    LoginFlowError::authentication(format!("Invalid token: {reason}"))
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
