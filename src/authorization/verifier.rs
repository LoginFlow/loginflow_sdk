//! Verification of the access token a resource request presents, framework-agnostic: the
//! token itself, its DPoP binding and the permissions it grants.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use log::warn;
use thiserror::Error;

use crate::authorization::header::{AuthScheme, AuthorizationHeader};
use crate::authorization::replay::JtiReplayCache;
use crate::client::LoginFlowClient;
use crate::dpop::{MAX_PROOF_AGE_SECS, now_unix, verify_proof_matches_cnf};
use crate::error::LoginFlowError;
use crate::models::{AccessClaims, TokenPermissions};
use crate::oauth2::IntrospectionClient;

/// How long a proof's `jti` is remembered: a proof passes the freshness check up to
/// [`MAX_PROOF_AGE_SECS`] either side of its `iat`.
pub const DPOP_REPLAY_WINDOW_SECS: i64 = 2 * MAX_PROOF_AGE_SECS;

/// What a resource request presents. No `Debug`: it holds the token.
#[derive(Clone, Copy)]
pub struct PresentedToken<'a> {
    pub authorization: &'a AuthorizationHeader,
    /// The one `DPoP` header value, when the request has one.
    pub dpop_proof: Option<&'a str>,
    /// HTTP method (`GET`, `POST`, ...), the proof's `htm`.
    pub method: &'a str,
    /// `scheme://host` the request reached, used for the proof's `htu` when the configuration
    /// has no `resource_base_url`.
    pub request_origin: &'a str,
    /// Request path, without the query string.
    pub path: &'a str,
}

/// A verified access token and the permissions it grants in its organization, for this API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAccess {
    pub claims: AccessClaims,
    /// The listed permissions, or the live ones for an overage token.
    pub permissions: BTreeSet<String>,
    /// The thumbprint of the DPoP key the request proved, for a DPoP-bound token.
    pub dpop_jkt: Option<String>,
}

/// Why a presented token was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The token, its binding or its proof does not hold (`401`). The reason is for logs only.
    #[error("invalid access token: {0}")]
    InvalidToken(String),
    /// What the decision needs (the signing keys, the live permissions) cannot be obtained
    /// (`503`): the request is refused, never let through.
    #[error("authorization unavailable: {0}")]
    Unavailable(String),
}

/// Boxed future of [`AccessVerifier::verify`].
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<VerifiedAccess, VerifyError>> + 'a>>;

/// What the permission gate verifies a request with: [`TokenVerifier`] in production, the
/// `testing` feature's `FakeVerifier` in a product's tests.
pub trait AccessVerifier: Send + Sync {
    fn verify<'a>(&'a self, presented: PresentedToken<'a>) -> VerifyFuture<'a>;
}

/// Verifies an access token against LoginFlow:
///
/// 1. the header `alg` is ES256 (the allow-list), `typ` is `at+jwt`, and the `kid` names a key
///    of the issuer's JWKS;
/// 2. the signature, `iss` (= `LOGINFLOW_ISSUER`), `aud` (= `LOGINFLOW_API`, this API only) and
///    `exp`;
/// 3. the DPoP binding (RFC 9449 §7.1): a `cnf`-bound token only under the `DPoP` scheme, with a
///    proof for this request's method and URL, bound to this token (`ath`), signed by the
///    token's key (`cnf.jkt`) and never seen before (`jti`, through the [`JtiReplayCache`]); a
///    token without `cnf` only under `Bearer`;
/// 4. the permissions: the listed ones, or — for a `permissions_overage` token — the live ones
///    from `POST /oauth2/introspect`, authenticated as this API's key. When introspection fails
///    the request fails ([`VerifyError::Unavailable`]): it never falls back to "no check".
#[derive(Clone)]
pub struct TokenVerifier {
    client: LoginFlowClient,
    replay: Arc<dyn JtiReplayCache>,
    introspection: IntrospectionClient,
}

impl TokenVerifier {
    /// `introspection` must authenticate as this API's own key (`LOGINFLOW_CLIENT_ID` /
    /// `LOGINFLOW_CLIENT_SECRET`): LoginFlow answers the permissions of a token only to the key
    /// of the token's API.
    pub fn new(
        client: LoginFlowClient,
        replay: Arc<dyn JtiReplayCache>,
        introspection: IntrospectionClient,
    ) -> Self {
        Self {
            client,
            replay,
            introspection,
        }
    }

    /// Verify what a request presents. See the type's documentation for every check.
    ///
    /// # Errors
    /// [`VerifyError::InvalidToken`] for a token, binding or proof that does not hold;
    /// [`VerifyError::Unavailable`] when the signing keys or the live permissions cannot be
    /// obtained.
    pub async fn verify_presented(
        &self,
        presented: &PresentedToken<'_>,
    ) -> Result<VerifiedAccess, VerifyError> {
        let token = presented.authorization.token.as_str();
        let claims = self
            .client
            .verify_access_token(token)
            .await
            .map_err(token_failure)?;
        let dpop_jkt = check_binding(
            &claims,
            presented,
            self.client.config().resource_base_url.as_deref(),
            self.replay.as_ref(),
        )?;
        let permissions = match &claims.permissions {
            TokenPermissions::Listed(listed) => listed.clone(),
            TokenPermissions::Overage => self.live_permissions(token, &claims).await?,
        };
        Ok(VerifiedAccess {
            claims,
            permissions,
            dpop_jkt,
        })
    }

    /// The permissions of an overage token, read live. Fails closed on any doubt.
    async fn live_permissions(
        &self,
        token: &str,
        claims: &AccessClaims,
    ) -> Result<BTreeSet<String>, VerifyError> {
        let answer = self
            .introspection
            .introspect_cached(token)
            .await
            .map_err(|e| {
                warn!("Overage permissions unavailable: {e}");
                VerifyError::Unavailable("the live permissions cannot be read".to_string())
            })?;
        if !answer.active {
            return Err(VerifyError::InvalidToken(
                "introspection reports the token inactive".to_string(),
            ));
        }
        if answer.org_id != claims.org_id {
            return Err(VerifyError::InvalidToken(
                "the token's organization is no longer its active one".to_string(),
            ));
        }
        answer
            .permissions
            .map(|listed| listed.into_iter().collect())
            .ok_or_else(|| {
                warn!("Introspection answered an overage token without its permissions");
                VerifyError::Unavailable("the live permissions cannot be read".to_string())
            })
    }
}

impl AccessVerifier for TokenVerifier {
    fn verify<'a>(&'a self, presented: PresentedToken<'a>) -> VerifyFuture<'a> {
        Box::pin(async move { self.verify_presented(&presented).await })
    }
}

/// A rejected token is a `401`; keys that cannot be obtained are a `503`.
pub(crate) fn token_failure(error: LoginFlowError) -> VerifyError {
    match error {
        LoginFlowError::Authentication(reason) => VerifyError::InvalidToken(reason),
        other => {
            warn!("Access token cannot be verified: {other}");
            VerifyError::Unavailable("the signing keys cannot be obtained".to_string())
        }
    }
}

/// RFC 9449 §7.1 scheme/binding matrix and single use of the proof. Returns the proved key's
/// thumbprint for a DPoP-bound token.
pub(crate) fn check_binding(
    claims: &AccessClaims,
    presented: &PresentedToken<'_>,
    resource_base_url: Option<&str>,
    replay: &dyn JtiReplayCache,
) -> Result<Option<String>, VerifyError> {
    match (claims.cnf.as_ref(), presented.authorization.scheme) {
        (None, AuthScheme::Bearer) => Ok(None),
        (None, AuthScheme::Dpop) => Err(VerifyError::InvalidToken(
            "the access token is not DPoP-bound: present it with the Bearer scheme".to_string(),
        )),
        (Some(_), AuthScheme::Bearer) => Err(VerifyError::InvalidToken(
            "a DPoP-bound access token must be presented with the DPoP scheme".to_string(),
        )),
        (Some(cnf), AuthScheme::Dpop) => {
            let proof = presented
                .dpop_proof
                .ok_or_else(|| VerifyError::InvalidToken("missing DPoP proof".to_string()))?;
            let htu = match resource_base_url {
                Some(base) => format!("{}{}", base.trim_end_matches('/'), presented.path),
                None => format!("{}{}", presented.request_origin, presented.path),
            };
            let verified = verify_proof_matches_cnf(
                proof,
                presented.method,
                &htu,
                &presented.authorization.token,
                &cnf.jkt,
            )
            .map_err(|e| VerifyError::InvalidToken(format!("invalid DPoP proof: {e}")))?;
            let replay_key = format!("{}:{}", verified.jkt, verified.claims.jti);
            if !replay.first_use(&replay_key, DPOP_REPLAY_WINDOW_SECS, now_unix()) {
                return Err(VerifyError::InvalidToken(
                    "the DPoP proof was already used".to_string(),
                ));
            }
            Ok(Some(verified.jkt))
        }
    }
}
