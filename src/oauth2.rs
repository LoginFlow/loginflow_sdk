//! `client_credentials` (service-to-service tokens) and RFC 7662 introspection.
//!
//! Both talk to the OIDC provider directly (`POST /oauth2/token` and
//! `POST /oauth2/introspect`), independent of [`crate::LoginFlowClient`]: a confidential client
//! calling another service, or a resource server validating a token it did not issue, has no
//! `LoginFlowConfig` of its own tenant to build one from.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::discovery::DiscoveryDocument;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::{expect_success, read_capped};

/// How long before the token's real expiry it is treated as stale and refreshed, so a caller
/// never races a token that expires mid-request.
const EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// Maximum size of a token/introspection response body.
const BODY_LIMIT: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct TokenResponseBody {
    access_token: String,
    expires_in: i64,
}

struct CachedToken {
    access_token: String,
    /// When this token should be treated as expired (real `exp` minus [`EXPIRY_MARGIN`]).
    stale_at: Instant,
}

impl CachedToken {
    fn is_fresh(&self) -> bool {
        Instant::now() < self.stale_at
    }
}

/// A `client_credentials` confidential client: fetches and caches an application-scoped access
/// token, refreshing it shortly before it expires. Concurrent callers share one refresh
/// (single-flight): only the first one past a stale cache sends the request, the rest await it.
///
/// Cloning is cheap: clones share the cached token and the HTTP connection pool.
#[derive(Clone)]
pub struct ClientCredentialsClient {
    http: Client,
    token_url: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    cached: Arc<Mutex<Option<CachedToken>>>,
}

impl ClientCredentialsClient {
    /// `token_url` is the full `/oauth2/token` URL (e.g. `{issuer}/oauth2/token`).
    pub fn new(
        http: Client,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: None,
            cached: Arc::new(Mutex::new(None)),
        }
    }

    /// Same as [`new`](Self::new), reading `token_endpoint` from a discovery document instead
    /// of a hardcoded path (the contract's own rule: "a client is never expected to hardcode a
    /// path" — `loginflow_api`'s `discovery_document.rs`).
    pub fn from_discovery(
        http: Client,
        discovery: &DiscoveryDocument,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            http,
            discovery.token_endpoint.clone(),
            client_id,
            client_secret,
        )
    }

    /// Requests `scope` on every token fetch (space-delimited, RFC 6749 §3.3).
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Returns a valid access token, serving the cached one when it is still fresh and fetching a
    /// new one otherwise. Concurrent calls past a stale cache are collapsed into one HTTP request.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when the server rejects the client credentials;
    /// network/parse errors otherwise.
    pub async fn access_token(&self) -> LoginFlowResult<String> {
        let mut guard = self.cached.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.is_fresh()
        {
            return Ok(cached.access_token.clone());
        }
        let fetched = self.fetch().await?;
        let access_token = fetched.access_token.clone();
        *guard = Some(fetched);
        Ok(access_token)
    }

    /// Drops the cached token, so the next [`access_token`](Self::access_token) call fetches a
    /// new one. Call it when a resource server rejects the cached token (`401`) before its
    /// `expires_in` ran out (e.g. it was revoked or the client's scopes changed).
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }

    /// Drops the cached token only if it is still `rejected`: a concurrent caller may already
    /// have replaced it with a fresh one, which must not be thrown away.
    pub(crate) async fn invalidate_if_current(&self, rejected: &str) {
        let mut guard = self.cached.lock().await;
        if guard
            .as_ref()
            .is_some_and(|cached| cached.access_token == rejected)
        {
            *guard = None;
        }
    }

    async fn fetch(&self) -> LoginFlowResult<CachedToken> {
        let mut form = vec![("grant_type", "client_credentials")];
        if let Some(scope) = &self.scope {
            form.push(("scope", scope.as_str()));
        }
        // `client_secret_basic` (RFC 6749 §2.3.1): the method the server MUST support for a
        // confidential client, and the one every endpoint advertises in discovery — never
        // `client_secret_post`, to match that.
        let response = expect_success(
            self.http
                .post(&self.token_url)
                .basic_auth(&self.client_id, Some(&self.client_secret))
                .form(&form)
                .send()
                .await?,
            "client_credentials token",
        )
        .await?;
        let body = read_capped(response, BODY_LIMIT)
            .await
            .map_err(|e| LoginFlowError::Network(e.to_string()))?;
        let parsed: TokenResponseBody = serde_json::from_slice(&body.bytes)
            .map_err(|e| LoginFlowError::ParseError(format!("invalid token response: {e}")))?;
        let ttl =
            Duration::from_secs(parsed.expires_in.max(0) as u64).saturating_sub(EXPIRY_MARGIN);
        Ok(CachedToken {
            access_token: parsed.access_token,
            stale_at: Instant::now() + ttl,
        })
    }
}

/// RFC 7662 token introspection response. Only `active` is guaranteed present; every other field
/// is `None` for an inactive token (the server's `{"active": false}` short form).
///
/// `org_id`, `org_ext` and `permissions` come only when the introspecting client is the key of
/// the token's API: the token's organization and its permissions for that API, recalculated
/// live — what [`crate::TokenVerifier`] reads for a token whose permissions did not fit in it
/// (`permissions_overage`).
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectionResponse {
    /// Whether the token is live and this client may learn about it.
    pub active: bool,
    /// The token's `sub`.
    pub sub: Option<String>,
    /// The client the token was issued to.
    pub client_id: Option<String>,
    /// The token's granted scopes, space-delimited.
    pub scope: Option<String>,
    /// Expiration time (Unix seconds).
    pub exp: Option<i64>,
    /// Issued at (Unix seconds).
    pub iat: Option<i64>,
    /// The token's issuer.
    pub iss: Option<String>,
    /// Always `Bearer` (RFC 7662), whether or not the token is DPoP-bound.
    pub token_type: Option<String>,
    /// The token's active organization (`null` when it has none).
    #[serde(default)]
    pub org_id: Option<String>,
    /// The product's own id of that organization, when it has one.
    #[serde(default)]
    pub org_ext: Option<String>,
    /// The permissions of the token's API held in `org_id`, recalculated live.
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

/// Longest a cached introspection answer is served from [`IntrospectionClient::introspect_cached`]
/// before a sensitive operation forces a fresh round trip. The access token itself stays valid
/// for its full lifetime (10 minutes by default); this cap is what actually bounds how long a
/// revoked token can keep passing a *sensitive* check after revocation.
pub const INTROSPECTION_CACHE_TTL: Duration = Duration::from_secs(30);

/// Upper bound on cached introspection answers; past it, the entry closest to expiry is evicted.
pub const INTROSPECTION_CACHE_MAX_ENTRIES: usize = 10_000;

struct CachedIntrospection {
    response: IntrospectionResponse,
    stale_at: Instant,
}

/// An RFC 7662 `/oauth2/introspect` client. Confidential clients only (the server refuses
/// introspection for any other client type).
#[derive(Clone)]
pub struct IntrospectionClient {
    http: Client,
    introspect_url: String,
    client_id: String,
    client_secret: String,
    cache: Arc<Mutex<HashMap<String, CachedIntrospection>>>,
}

impl IntrospectionClient {
    /// `introspect_url` is the full `/oauth2/introspect` URL.
    pub fn new(
        http: Client,
        introspect_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            introspect_url: introspect_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Same as [`new`](Self::new), reading `introspection_endpoint` from a discovery document
    /// instead of a hardcoded path.
    pub fn from_discovery(
        http: Client,
        discovery: &DiscoveryDocument,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            http,
            discovery.introspection_endpoint.clone(),
            client_id,
            client_secret,
        )
    }

    /// Introspects `token`, always with a fresh request — no caching. Use this for anything that
    /// is not itself a sensitive, revocation-sensitive check (for those, prefer
    /// [`introspect_cached`](Self::introspect_cached), which bounds the same network cost to at
    /// most one round trip every [`INTROSPECTION_CACHE_TTL`]).
    ///
    /// Never errors on an inactive/unknown token (RFC 7662 §2.2): that comes back as
    /// `Ok(IntrospectionResponse { active: false, .. })`, same as the server's answer to a caller
    /// that fails client authentication.
    pub async fn introspect(&self, token: &str) -> LoginFlowResult<IntrospectionResponse> {
        let form = [("token", token)];
        // `client_secret_basic` (RFC 6749 §2.3.1), same reasoning as `ClientCredentialsClient`.
        let response = expect_success(
            self.http
                .post(&self.introspect_url)
                .basic_auth(&self.client_id, Some(&self.client_secret))
                .form(&form)
                .send()
                .await?,
            "token introspection",
        )
        .await?;
        let body = read_capped(response, BODY_LIMIT)
            .await
            .map_err(|e| LoginFlowError::Network(e.to_string()))?;
        serde_json::from_slice(&body.bytes)
            .map_err(|e| LoginFlowError::ParseError(format!("invalid introspection response: {e}")))
    }

    /// Introspection for a sensitive operation (money movement, destructive action, privilege
    /// change): the local signature check an access token normally gets
    /// ([`crate::TokenVerifier`]) only proves the token was valid when it was
    /// *issued* — it says nothing about a revocation that happened a second ago. This adds a
    /// live check against the server, but caches the answer for at most
    /// [`INTROSPECTION_CACHE_TTL`] (30 s) per token, so a burst of sensitive calls for the same
    /// caller does not turn into a network round trip each.
    ///
    /// An `active: false` answer is never cached — there is no reason to keep re-serving a
    /// rejection past the moment the server actually reported it (and it would otherwise mask a
    /// token that becomes active again, e.g. one that was never valid being retried with a
    /// corrected value).
    pub async fn introspect_cached(&self, token: &str) -> LoginFlowResult<IntrospectionResponse> {
        {
            let mut cache = self.cache.lock().await;
            cache.retain(|_, entry| entry.stale_at > Instant::now());
            if let Some(entry) = cache.get(token) {
                return Ok(entry.response.clone());
            }
        }
        let response = self.introspect(token).await?;
        if response.active {
            let mut cache = self.cache.lock().await;
            if cache.len() >= INTROSPECTION_CACHE_MAX_ENTRIES {
                let soonest = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.stale_at)
                    .map(|(key, _)| key.clone());
                if let Some(key) = soonest {
                    cache.remove(&key);
                }
            }
            cache.insert(
                token.to_string(),
                CachedIntrospection {
                    response: response.clone(),
                    stale_at: Instant::now() + INTROSPECTION_CACHE_TTL,
                },
            );
        }
        Ok(response)
    }
}

/// An RFC 7009 `/oauth2/revoke` client: a confidential backend (holding `client_credentials` or
/// refresh tokens issued to it) authenticates with `client_secret_basic` to revoke one of its
/// own tokens early, instead of waiting out the natural `exp`. The server now requires
/// confidential-client authentication on this endpoint (RFC 7009 §2.1); a public client has no
/// business revoking a token through this SDK (`loginflow_auth` owns that side — end-user
/// sign-out goes through `/oauth2/end-session`/`/oauth2/device-logout`, not this endpoint).
#[derive(Clone)]
pub struct RevocationClient {
    http: Client,
    revoke_url: String,
    client_id: String,
    client_secret: String,
}

impl RevocationClient {
    /// `revoke_url` is the full `/oauth2/revoke` URL.
    pub fn new(
        http: Client,
        revoke_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            http,
            revoke_url: revoke_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }

    /// Same as [`new`](Self::new), reading `revocation_endpoint` from a discovery document
    /// instead of a hardcoded path.
    pub fn from_discovery(
        http: Client,
        discovery: &DiscoveryDocument,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self::new(
            http,
            discovery.revocation_endpoint.clone(),
            client_id,
            client_secret,
        )
    }

    /// Revokes `token` (access or refresh). RFC 7009 §2.2: the server answers `200` whether or
    /// not the token existed or belonged to this client — this never reveals which, so a
    /// successful call here is not proof the token was ever valid. Only a client authentication
    /// failure (wrong secret) is surfaced as an error.
    ///
    /// # Errors
    /// [`LoginFlowError::Authentication`] when the client credentials are rejected (`401`);
    /// network/parse errors otherwise.
    pub async fn revoke(&self, token: &str) -> LoginFlowResult<()> {
        let form = [("token", token)];
        expect_success(
            self.http
                .post(&self.revoke_url)
                .basic_auth(&self.client_id, Some(&self.client_secret))
                .form(&form)
                .send()
                .await?,
            "token revocation",
        )
        .await?;
        Ok(())
    }
}
