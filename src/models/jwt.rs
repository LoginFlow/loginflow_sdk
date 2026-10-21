//! JWT-related models for LoginFlow SDK

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::LoginFlowError;
use crate::models::access_code::SubjectKind;

/// `acr` (RFC 8176 §2 / OIDC Core §2) when the session was established with a phishing-resistant
/// factor (a hardware or software passkey) — the server's `acr_for_amr`
/// (`challenge_service.rs`) emits this only when `amr` carries `hwk`/`swk`.
pub const ACR_PHISHING_RESISTANT: &str = "urn:loginflow:acr:phr";
/// `acr` when two independent factors were used but neither is phishing-resistant
/// (e.g. password + email OTP, password + TOTP).
pub const ACR_MULTI_FACTOR: &str = "urn:loginflow:acr:mfa";
/// `acr` for a single, non-phishing-resistant factor (password alone, email OTP alone, a
/// federated login alone).
pub const ACR_SINGLE_FACTOR: &str = "urn:loginflow:acr:pwd";

/// The `typ` header value of an RFC 9068 access token. [`LoginFlowClient::verify_token`]
/// rejects any other header `typ`.
pub const ACCESS_TOKEN_JWT_TYP: &str = "at+jwt";

/// Claims of a LoginFlow access token (RFC 9068).
///
/// Carries the standard registered claims (`iss`, `sub`, `aud`, `exp`, `iat`) and the RFC 9068
/// claims (`client_id`, `scope`, `sid`, `auth_time`, `amr`, `acr`). The access token carries no
/// PII and no profile-level status: `sub` is the `company_users` id, never the user's email or
/// profile `user_id`. An email, when the caller actually needs one, is resolved live through
/// [`LoginFlowClient::userinfo`](crate::LoginFlowClient::userinfo) (scope `email`/`profile`) or
/// read off the ID token — never cached on the access token. Only obtained through
/// [`LoginFlowClient::verify_token`](crate::LoginFlowClient::verify_token), i.e. after the header
/// `typ`, ES256 signature, issuer, audience and expiration were checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// JWT ID (unique token identifier, used for revocation)
    pub jti: String,
    /// Issuer (e.g. "https://api.loginflow.dev")
    pub iss: String,
    /// Subject: the `company_users` id this token was issued for.
    pub sub: String,
    /// Audience: the application ID for access tokens
    pub aud: String,
    /// Expiration time (Unix seconds)
    pub exp: i64,
    /// Issued at (Unix seconds)
    pub iat: i64,
    /// The OAuth2/OIDC client that requested this token.
    #[serde(default)]
    pub client_id: String,
    /// Space-delimited granted scopes.
    #[serde(default)]
    pub scope: String,
    /// The browser/device session this token belongs to, when the grant has one
    /// (`client_credentials` tokens have none).
    #[serde(default)]
    pub sid: Option<String>,
    /// When the user last authenticated (Unix seconds).
    #[serde(default)]
    pub auth_time: i64,
    /// Authentication methods references (e.g. `["pwd"]`, `["pwd", "otp"]`).
    #[serde(default)]
    pub amr: Vec<String>,
    /// Authentication Context Class Reference (e.g. phishing-resistant passkey/DPoP login).
    #[serde(default)]
    pub acr: Option<String>,
    /// Company ID (opaque string, e.g. `CP-...`)
    pub company_id: String,
    /// Application ID (opaque string, e.g. `APP-...`)
    pub application_id: String,
    /// User role (user, app_admin, master)
    pub role: String,
    /// RFC 7800 confirmation claim. `Some` when this token is DPoP-bound (RFC 9449 §6): a
    /// resource request presenting it MUST also present a matching DPoP proof — see
    /// [`crate::dpop::verify_proof_matches_cnf`].
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
    /// Federations: the company whose credential actually authenticated this token's session,
    /// present ONLY when it differs from `company_id` — a `session`-level federation reuse or a
    /// cross-company Native SSO exchange. Absent on every ordinary, non-federated token: check
    /// `company_id` for authorization, never `auth_cid` (it names where the user logged IN, not
    /// what they are allowed to access).
    #[serde(default)]
    pub auth_cid: Option<String>,
    /// Access-code subjects only (a person or device issued a code through
    /// [`crate::AccessCodesClient`]): the issuer's own id of the subject. `sub` is then the
    /// LoginFlow subject id (`AS-...`), never this value. Read through
    /// [`ext_sub`](Self::ext_sub).
    #[serde(default)]
    pub ext_sub: Option<String>,
    /// Access-code subjects only: `person` or `device`. Read typed through
    /// [`subject_kind`](Self::subject_kind).
    #[serde(default)]
    pub subject_kind: Option<String>,
    /// Access-code subjects only: the issuer-defined profile (e.g. `Driver`, `Kiosk`), claim
    /// `ext_profile` — never the registered OIDC `profile` claim (a profile page URL). Read
    /// through [`ext_profile`](Self::ext_profile).
    #[serde(default)]
    pub ext_profile: Option<String>,
}

/// RFC 7800 §3.2: the token is a DPoP-bound access token (RFC 9449 §6) whose key's JWK thumbprint
/// (RFC 7638) is `jkt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    pub jkt: String,
}

/// The `typ` header value of an OIDC Back-Channel Logout 1.0 §2.4 logout token.
/// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token) rejects
/// any other header `typ`.
pub const LOGOUT_TOKEN_JWT_TYP: &str = "logout+jwt";

/// The one `events` member a valid logout token carries (OIDC Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT_URI: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Claims of an OIDC Back-Channel Logout 1.0 §2.4 logout token, delivered by `POST` to the RP's
/// own `backchannel_logout_uri` when a session ends. Only obtained through
/// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token), which
/// enforces every MUST/MUST NOT of §2.6 the claims alone cannot: no `exp` is required (logout
/// tokens are short-lived by delivery, not by claim), and there is deliberately no `is_active`
/// style helper — the whole point of this token is that the session it names is already gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    /// Single-use: the caller (not this SDK, which holds no storage) must reject a `jti` it has
    /// already processed (§2.6 point 10).
    pub jti: String,
    /// `{"http://schemas.openid.net/event/backchannel-logout": {}}` — checked for presence by
    /// [`LoginFlowClient::verify_logout_token`], not re-validated by the caller.
    pub events: serde_json::Value,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    /// MUST be absent (§2.6 point 7: a logout token is distinguished from an ID token partly by
    /// never carrying this). Captured only so [`LoginFlowClient::verify_logout_token`] can reject
    /// a token that has one, instead of silently ignoring it.
    #[serde(default)]
    pub nonce: Option<String>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl JwtClaims {
    /// Check if the token is past its `exp`
    pub fn is_expired(&self) -> bool {
        self.exp <= now_unix()
    }

    /// Remaining validity in seconds (negative when expired)
    pub fn remaining_validity(&self) -> i64 {
        self.exp - now_unix()
    }

    /// Whether this token is bound to a DPoP key (RFC 9449 §6) — if so, a resource request
    /// presenting it MUST also present a matching DPoP proof.
    pub fn is_dpop_bound(&self) -> bool {
        self.cnf.is_some()
    }

    /// `company_users.id` this token was issued for (`sub`, RFC 9068).
    pub fn company_user_id(&self) -> &str {
        &self.sub
    }

    /// The issuer's own id of an access-code subject (`ext_sub`); `None` on any other token.
    pub fn ext_sub(&self) -> Option<&str> {
        self.ext_sub.as_deref()
    }

    /// `subject_kind` of an access-code subject; `None` on any other token, and for a kind
    /// this SDK version does not know.
    pub fn subject_kind(&self) -> Option<SubjectKind> {
        self.subject_kind.as_deref().and_then(SubjectKind::parse)
    }

    /// The issuer-defined profile (`ext_profile` claim) of an access-code subject; `None` on any
    /// other token.
    pub fn ext_profile(&self) -> Option<&str> {
        self.ext_profile.as_deref()
    }

    /// Whether this token was minted for an access-code subject (it carries `ext_sub`).
    pub fn is_access_code_subject(&self) -> bool {
        self.ext_sub.is_some()
    }

    /// The scopes granted to this token, split on whitespace.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split_whitespace()
    }

    /// Whether `scope` was granted to this token.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().any(|granted| granted == scope)
    }

    /// Whether `method` (e.g. `"pwd"`, `"otp"`, `"totp"`) is among the authentication methods
    /// references used to establish this session.
    pub fn has_amr(&self, method: &str) -> bool {
        self.amr.iter().any(|m| m == method)
    }

    /// Whether the session was established with a phishing-resistant factor (a hardware or
    /// software passkey, WebAuthn L3) — the strongest `acr` LoginFlow issues. A passkey
    /// satisfies both the primary and the second factor in the same step, so this already
    /// implies [`has_mfa`](Self::has_mfa).
    pub fn is_phishing_resistant(&self) -> bool {
        self.acr.as_deref() == Some(ACR_PHISHING_RESISTANT)
    }

    /// Whether the session used two independent authentication factors — a passkey, or any
    /// other `acr` the server only issues after a second factor (TOTP, email OTP, recovery
    /// code, temporary access pass) confirmed the primary one.
    pub fn has_mfa(&self) -> bool {
        matches!(
            self.acr.as_deref(),
            Some(ACR_PHISHING_RESISTANT) | Some(ACR_MULTI_FACTOR)
        )
    }

    /// Seconds since `auth_time`. Negative when `auth_time` is in the future (clock skew); the
    /// caller decides what, if anything, to do with that — this is the raw figure
    /// [`require_recent_auth`](Self::require_recent_auth) is built on.
    pub fn auth_age_secs(&self) -> i64 {
        now_unix() - self.auth_time
    }

    /// RFC 9470 step-up gate for a backend's own sensitive endpoint (change password, change
    /// email, delete account, a payout, anything LoginFlow's own `change_password` already
    /// treats this way): rejects when the token's `auth_time` is older than `max_age_secs`.
    ///
    /// # Errors
    /// [`LoginFlowError::InsufficientUserAuthentication`] with `max_age_secs` set to the value
    /// passed in — the `actix` feature's `ResponseError` impl on [`LoginFlowError`] turns that
    /// into the same `401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication",
    /// max_age=<n>` challenge LoginFlow's own server sends, so the client re-authenticates and
    /// retries the same way it already knows how to.
    pub fn require_recent_auth(&self, max_age_secs: i64) -> Result<(), LoginFlowError> {
        if self.auth_age_secs() > max_age_secs {
            return Err(LoginFlowError::InsufficientUserAuthentication {
                max_age_secs: Some(max_age_secs.max(0) as u64),
            });
        }
        Ok(())
    }
}
