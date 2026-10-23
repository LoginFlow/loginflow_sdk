//! Single use of a DPoP proof (RFC 9449 §11.1): a proof's `jti` is accepted once while the proof
//! could still pass the freshness check.

use std::collections::HashMap;
use std::sync::Mutex;

use log::error;

/// Records proof identifiers and answers whether one is seen for the first time.
///
/// An implementation shared by every instance of the API (e.g. a Redis `SET NX EX`) is what
/// stops a proof replayed against another instance; [`InMemoryJtiReplayCache`] only covers the
/// instance it lives in.
pub trait JtiReplayCache: Send + Sync {
    /// Record `jti` until `now + ttl` (Unix seconds) and return `true`, or return `false` when
    /// it was already recorded and has not expired. Return `false` as well whenever the answer
    /// cannot be known: a replay check fails closed.
    fn first_use(&self, jti: &str, ttl: i64, now: i64) -> bool;
}

/// Default capacity of [`InMemoryJtiReplayCache`].
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 100_000;

/// A per-process [`JtiReplayCache`]. Expired entries are dropped on every call; when the live
/// entries reach the capacity, a new `jti` is refused (fails closed) rather than evicting one
/// that could then be replayed.
pub struct InMemoryJtiReplayCache {
    capacity: usize,
    seen: Mutex<HashMap<String, i64>>,
}

impl InMemoryJtiReplayCache {
    /// A cache holding at most [`DEFAULT_REPLAY_CACHE_CAPACITY`] live entries.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_REPLAY_CACHE_CAPACITY)
    }

    /// A cache holding at most `capacity` live entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            seen: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryJtiReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JtiReplayCache for InMemoryJtiReplayCache {
    fn first_use(&self, jti: &str, ttl: i64, now: i64) -> bool {
        let Ok(mut seen) = self.seen.lock() else {
            error!("DPoP replay cache lock poisoned: refusing the proof");
            return false;
        };
        seen.retain(|_, expires_at| *expires_at > now);
        if seen.contains_key(jti) {
            return false;
        }
        if seen.len() >= self.capacity {
            error!("DPoP replay cache full: refusing the proof");
            return false;
        }
        seen.insert(jti.to_string(), now + ttl.max(0));
        true
    }
}
