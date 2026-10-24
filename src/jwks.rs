//! Cache of the LoginFlow token signing keys (JWKS).
//!
//! LoginFlow signs every token with ES256 and names the key in the `kid`
//! header. The public keys are published at `GET {base_url}/oauth2/jwks`.
//! [`JwksCache`] downloads that set, keeps it for a TTL, and refreshes it:
//!
//! - when the cached set is older than the TTL;
//! - when a token names a `kid` the cached set does not contain (key
//!   rotation), at most once every [`JWKS_MIN_REFRESH_INTERVAL`].
//!
//! A failed refresh keeps the previously downloaded keys in service.
//! Concurrent refreshes are collapsed into one request (single flight), the
//! response body is capped at [`JWKS_BODY_LIMIT`] bytes, and only keys with
//! `kty=EC`, `crv=P-256` and `alg=ES256` are kept. Everything else in the set
//! is ignored.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::http::read_capped;

/// Maximum size of a JWKS response body, in bytes.
pub const JWKS_BODY_LIMIT: usize = 64 * 1024;

/// Minimum time between two JWKS downloads triggered by an unknown `kid` or by
/// a failed refresh.
pub const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Thread-safe, shareable cache of the issuer's ES256 verification keys.
pub struct JwksCache {
    http: Client,
    url: String,
    ttl: Duration,
    min_refresh_interval: Duration,
    state: RwLock<KeyState>,
    refresh_lock: Mutex<()>,
}

#[derive(Default)]
struct KeyState {
    keys: HashMap<String, DecodingKey>,
    /// Last successful download.
    fetched_at: Option<Instant>,
    /// Last download attempt, successful or not.
    attempted_at: Option<Instant>,
    /// Error of the last attempt, `None` when it succeeded.
    last_error: Option<String>,
    /// Incremented on every attempt; lets waiters see that a refresh already happened.
    generation: u64,
}

impl KeyState {
    fn is_fresh(&self, ttl: Duration) -> bool {
        self.fetched_at.is_some_and(|at| at.elapsed() < ttl)
    }

    fn attempted_within(&self, interval: Duration) -> bool {
        self.attempted_at.is_some_and(|at| at.elapsed() < interval)
    }

    fn lookup(&self, kid: &str) -> LoginFlowResult<DecodingKey> {
        self.keys.get(kid).cloned().ok_or_else(unknown_kid)
    }
}

impl JwksCache {
    /// Create an empty cache. Nothing is downloaded until the first lookup.
    ///
    /// * `http` - client used for the download (its timeout and user agent apply)
    /// * `url` - JWKS endpoint
    /// * `ttl` - how long a downloaded set stays fresh
    pub fn new(http: Client, url: impl Into<String>, ttl: Duration) -> Self {
        Self {
            http,
            url: url.into(),
            ttl,
            min_refresh_interval: JWKS_MIN_REFRESH_INTERVAL,
            state: RwLock::new(KeyState::default()),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Override the minimum interval between unknown-`kid` refreshes
    /// (default [`JWKS_MIN_REFRESH_INTERVAL`]).
    pub fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// The JWKS endpoint this cache downloads from.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Return the verification key for `kid`, downloading the key set if needed.
    ///
    /// When a refresh fails but keys were downloaded before, the cached keys
    /// keep being served (a warning is logged); the error surfaces only when no
    /// key set was ever obtained.
    ///
    /// # Errors
    /// - [`LoginFlowError::Authentication`] when no ES256 key with that `kid` is published.
    /// - [`LoginFlowError::Jwks`] when the key set cannot be downloaded or parsed.
    pub async fn key(&self, kid: &str) -> LoginFlowResult<DecodingKey> {
        let observed_generation = {
            let state = self.state.read().await;
            let fresh = state.is_fresh(self.ttl);
            if fresh && let Some(key) = state.keys.get(kid) {
                return Ok(key.clone());
            }
            if state.attempted_within(self.min_refresh_interval) {
                return match &state.last_error {
                    Some(err) if state.keys.is_empty() => Err(LoginFlowError::Jwks(err.clone())),
                    _ => state.lookup(kid),
                };
            }
            state.generation
        };

        let refreshed = self.refresh(observed_generation).await;
        let state = self.state.read().await;
        if let Err(err) = refreshed {
            if state.keys.is_empty() {
                return Err(err);
            }
            warn!(
                "LoginFlow JWKS refresh failed, serving the cached keys: {}",
                err
            );
        }
        state.lookup(kid)
    }

    /// Download the key set unless another task already did since `observed_generation`.
    async fn refresh(&self, observed_generation: u64) -> LoginFlowResult<()> {
        let _single_flight = self.refresh_lock.lock().await;

        {
            let state = self.state.read().await;
            if state.generation != observed_generation {
                return match &state.last_error {
                    Some(err) => Err(LoginFlowError::Jwks(err.clone())),
                    None => Ok(()),
                };
            }
        }

        debug!("Downloading LoginFlow JWKS from {}", self.url);
        let result = self.fetch().await;

        let mut state = self.state.write().await;
        state.generation += 1;
        state.attempted_at = Some(Instant::now());
        match result {
            Ok(keys) => {
                debug!("LoginFlow JWKS loaded with {} ES256 key(s)", keys.len());
                state.keys = keys;
                state.fetched_at = Some(Instant::now());
                state.last_error = None;
                Ok(())
            }
            Err(err) => {
                warn!("LoginFlow JWKS refresh failed: {}", err);
                state.last_error = Some(err.clone());
                Err(LoginFlowError::Jwks(err))
            }
        }
    }

    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, String> {
        let response = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            return Err(format!("JWKS endpoint answered {status}"));
        }
        if response
            .content_length()
            .is_some_and(|len| len > JWKS_BODY_LIMIT as u64)
        {
            return Err(format!("JWKS response exceeds {JWKS_BODY_LIMIT} bytes"));
        }

        let body = read_capped(response, JWKS_BODY_LIMIT)
            .await
            .map_err(|e| format!("reading body failed: {e}"))?;
        if body.exceeded {
            return Err(format!("JWKS response exceeds {JWKS_BODY_LIMIT} bytes"));
        }

        let set: RawJwkSet = serde_json::from_slice(&body.bytes)
            .map_err(|e| format!("invalid JWKS document: {e}"))?;
        let keys: HashMap<String, DecodingKey> = set
            .keys
            .into_iter()
            .filter_map(RawJwk::into_es256_key)
            .collect();
        if keys.is_empty() {
            return Err("JWKS contains no usable ES256 key".to_string());
        }
        Ok(keys)
    }
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("url", &self.url)
            .field("ttl", &self.ttl)
            .field("min_refresh_interval", &self.min_refresh_interval)
            .finish()
    }
}

fn unknown_kid() -> LoginFlowError {
    LoginFlowError::authentication("Token signed with an unknown key")
}

#[derive(Debug, Deserialize)]
struct RawJwkSet {
    keys: Vec<RawJwk>,
}

/// One JWK, parsed loosely so a key of an unsupported type never breaks the whole set.
#[derive(Debug, Deserialize)]
struct RawJwk {
    kty: Option<String>,
    crv: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl RawJwk {
    /// Keep only `kty=EC`, `crv=P-256`, `alg=ES256` signature keys that carry a `kid`.
    fn into_es256_key(self) -> Option<(String, DecodingKey)> {
        let supported = self.kty.as_deref() == Some("EC")
            && self.crv.as_deref() == Some("P-256")
            && self.alg.as_deref() == Some("ES256")
            && self.key_use.as_deref().is_none_or(|u| u == "sig");
        if !supported {
            return None;
        }
        let kid = self.kid.filter(|k| !k.is_empty())?;
        let key = DecodingKey::from_ec_components(self.x.as_deref()?, self.y.as_deref()?).ok()?;
        Some((kid, key))
    }
}
