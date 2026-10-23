//! JWT-related models for LoginFlow SDK

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::dpop::now_unix;
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

/// The `typ` header value of an RFC 9068 access token. [`crate::TokenVerifier`] rejects any other
/// header `typ`.
pub const ACCESS_TOKEN_JWT_TYP: &str = "at+jwt";

/// The permissions an access token grants in its organization (`org_id`), for its API (`aud`)
/// only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenPermissions {
    /// The `permissions` claim. A token without an organization, and a machine
    /// (`client_credentials`) token, lists none.
    Listed(BTreeSet<String>),
    /// `permissions_overage: true`: the set did not fit in the token, and is read live from
    /// `POST /oauth2/introspect` by [`crate::TokenVerifier`] (which fails closed when it cannot).
    Overage,
}

/// The claims an access-code subject's token carries on top of the usual ones (a person or
/// device issued a code through [`crate::AccessCodesClient`]). `sub` is then the LoginFlow
/// subject id (`AS-...`), never [`ext_sub`](Self::ext_sub).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessSubjectClaims {
    /// The issuer's own id of the subject: the key a resource server looks its record up by.
    pub ext_sub: String,
    /// `person` or `device`; read typed through [`kind`](Self::kind).
    pub subject_kind: String,
    /// The issuer-defined profile (e.g. `Driver`, `Kiosk`), claim `ext_profile` — never the
    /// registered OIDC `profile` claim (a profile page URL).
    pub ext_profile: String,
}

impl AccessSubjectClaims {
    /// `subject_kind`, typed; `None` for a kind this SDK version does not know.
    pub fn kind(&self) -> Option<SubjectKind> {
        SubjectKind::parse(&self.subject_kind)
    }
}

/// Claims of a LoginFlow access token (RFC 9068) for one API.
///
/// `aud` is the audience of that API, `app` the application it belongs to, `org_id`/`org_ext`
/// the active organization and `permissions` what the token grants there, for this API only.
/// The token carries no PII and no account status: `sub` is the `company_users` id (or the
/// access-code subject id), never an email. Only obtained through [`crate::TokenVerifier`] (or
/// the `testing` feature's `FakeVerifier`), i.e. after the header `alg`/`typ`, the signature,
/// `iss`, `aud` and `exp` were checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AccessClaimsWire", into = "AccessClaimsWire")]
pub struct AccessClaims {
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// Issuer (e.g. `https://api.loginflow.dev`)
    pub iss: String,
    /// Subject: the `company_users` id, the access-code subject id, or the client_id of a
    /// `client_credentials` token.
    pub sub: String,
    /// Audience: the API this token is for (`LOGINFLOW_API` of the resource server).
    pub aud: String,
    /// Expiration time (Unix seconds)
    pub exp: i64,
    /// Issued at (Unix seconds)
    pub iat: i64,
    /// The OAuth2/OIDC client that requested this token.
    pub client_id: String,
    /// Space-delimited granted scopes.
    pub scope: String,
    /// The browser/device session this token belongs to (`client_credentials` tokens have none).
    pub sid: Option<String>,
    /// When the user last authenticated (Unix seconds).
    pub auth_time: i64,
    /// Authentication methods references (e.g. `["pwd"]`, `["pwd", "otp"]`).
    pub amr: Vec<String>,
    /// Authentication Context Class Reference.
    pub acr: Option<String>,
    /// Company ID (opaque string, e.g. `CP-...`)
    pub company_id: String,
    /// Application ID (`APP-...`) the API of `aud` belongs to.
    pub app: String,
    /// The active organization. `None` when the person has none (or several and picked none):
    /// such a token grants no permission.
    pub org_id: Option<String>,
    /// The product's own id of the active organization (`external_id`), when it has one.
    pub org_ext: Option<String>,
    /// What the token grants in `org_id`, for this API.
    pub permissions: TokenPermissions,
    /// RFC 7800 confirmation claim. `Some` when this token is DPoP-bound (RFC 9449 §6): a
    /// resource request presenting it MUST also present a matching DPoP proof.
    pub cnf: Option<CnfClaim>,
    /// Federations: the company whose credential actually authenticated this token's session,
    /// present ONLY when it differs from `company_id`. Authorization keys off `company_id` and
    /// the permissions, never this.
    pub auth_cid: Option<String>,
    /// Access-code subjects only.
    pub access_subject: Option<AccessSubjectClaims>,
}

/// The claims exactly as they travel in the token: `permissions` (a list) and
/// `permissions_overage` (a flag) are two claims, folded into [`TokenPermissions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessClaimsWire {
    jti: String,
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sid: Option<String>,
    #[serde(default)]
    auth_time: i64,
    #[serde(default)]
    amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acr: Option<String>,
    company_id: String,
    app: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    org_ext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "is_false")]
    permissions_overage: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cnf: Option<CnfClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_cid: Option<String>,
    #[serde(flatten)]
    access_subject: Option<AccessSubjectClaims>,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl TryFrom<AccessClaimsWire> for AccessClaims {
    type Error = String;

    fn try_from(wire: AccessClaimsWire) -> Result<Self, Self::Error> {
        let permissions = match (wire.permissions, wire.permissions_overage) {
            (Some(_), true) => {
                return Err("a token cannot list permissions and flag an overage".to_string());
            }
            (None, true) => TokenPermissions::Overage,
            (Some(listed), false) => TokenPermissions::Listed(listed.into_iter().collect()),
            (None, false) => TokenPermissions::Listed(BTreeSet::new()),
        };
        Ok(Self {
            jti: wire.jti,
            iss: wire.iss,
            sub: wire.sub,
            aud: wire.aud,
            exp: wire.exp,
            iat: wire.iat,
            client_id: wire.client_id,
            scope: wire.scope,
            sid: wire.sid,
            auth_time: wire.auth_time,
            amr: wire.amr,
            acr: wire.acr,
            company_id: wire.company_id,
            app: wire.app,
            org_id: wire.org_id,
            org_ext: wire.org_ext,
            permissions,
            cnf: wire.cnf,
            auth_cid: wire.auth_cid,
            access_subject: wire.access_subject,
        })
    }
}

impl From<AccessClaims> for AccessClaimsWire {
    fn from(claims: AccessClaims) -> Self {
        let (permissions, permissions_overage) = match claims.permissions {
            TokenPermissions::Listed(listed) => (Some(listed.into_iter().collect()), false),
            TokenPermissions::Overage => (None, true),
        };
        Self {
            jti: claims.jti,
            iss: claims.iss,
            sub: claims.sub,
            aud: claims.aud,
            exp: claims.exp,
            iat: claims.iat,
            client_id: claims.client_id,
            scope: claims.scope,
            sid: claims.sid,
            auth_time: claims.auth_time,
            amr: claims.amr,
            acr: claims.acr,
            company_id: claims.company_id,
            app: claims.app,
            org_id: claims.org_id,
            org_ext: claims.org_ext,
            permissions,
            permissions_overage,
            cnf: claims.cnf,
            auth_cid: claims.auth_cid,
            access_subject: claims.access_subject,
        }
    }
}

/// RFC 7800 §3.2: the token is a DPoP-bound access token (RFC 9449 §6) whose key's JWK thumbprint
/// (RFC 7638) is `jkt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CnfClaim {
    /// RFC 7638 thumbprint (base64url SHA-256) of the DPoP public key the token is bound to.
    pub jkt: String,
}

/// The `typ` header value of an OIDC Back-Channel Logout 1.0 §2.4 logout token.
/// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token) rejects
/// any other header `typ`.
pub const LOGOUT_TOKEN_JWT_TYP: &str = "logout+jwt";

/// The one `events` member a valid logout token carries (OIDC Back-Channel Logout 1.0 §2.4).
pub const BACKCHANNEL_LOGOUT_EVENT_URI: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Claims of an OIDC Back-Channel Logout 1.0 §2.4 logout token, delivered by `POST` to the RP's
/// own `backchannel_logout_uri` when a session ends. `aud` is the RP's client_id. Only obtained through
/// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token), which
/// enforces every MUST/MUST NOT of §2.6 the claims alone cannot: no `exp` is required (logout
/// tokens are short-lived by delivery, not by claim), and there is deliberately no `is_active`
/// style helper — the whole point of this token is that the session it names is already gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    /// Issuer: the configured `LOGINFLOW_ISSUER`.
    pub iss: String,
    /// The RP's own client_id.
    pub aud: String,
    /// Issued at (Unix seconds).
    pub iat: i64,
    /// Single-use: the caller (not this SDK, which holds no storage) must reject a `jti` it has
    /// already processed (§2.6 point 10).
    pub jti: String,
    /// `{"http://schemas.openid.net/event/backchannel-logout": {}}` — checked for presence by
    /// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token), not
    /// re-validated by the caller.
    pub events: serde_json::Value,
    /// The `company_users` id whose session ended.
    #[serde(default)]
    pub sub: Option<String>,
    /// The session that ended, when the logout is for one session.
    #[serde(default)]
    pub sid: Option<String>,
    /// MUST be absent (§2.6 point 7: a logout token is distinguished from an ID token partly by
    /// never carrying this). Captured only so
    /// [`LoginFlowClient::verify_logout_token`](crate::LoginFlowClient::verify_logout_token) can
    /// reject a token that has one, instead of silently ignoring it.
    #[serde(default)]
    pub nonce: Option<String>,
}

impl AccessClaims {
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

    /// Whether this token was minted for an access-code subject.
    pub fn is_access_code_subject(&self) -> bool {
        self.access_subject.is_some()
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
