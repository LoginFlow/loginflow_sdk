//! `InMemoryJtiReplayCache`: a proof identifier is accepted once while it could still pass the
//! freshness check, again once that window is over, and the cache fails closed when full.

use loginflow_sdk::{InMemoryJtiReplayCache, JtiReplayCache};

#[test]
fn a_jti_is_accepted_once_within_its_window() {
    let cache = InMemoryJtiReplayCache::new();

    assert!(cache.first_use("jkt:jti-1", 120, 1_000));
    assert!(
        !cache.first_use("jkt:jti-1", 120, 1_060),
        "replayed inside the window"
    );
    assert!(cache.first_use("jkt:jti-2", 120, 1_060), "another jti");
    assert!(
        cache.first_use("jkt:jti-1", 120, 1_121),
        "the window is over"
    );
}

/// TEST_CHARTER
/// Requirement: when the live entries reach the capacity, a new `jti` is refused instead of
/// evicting a live one (which could then be replayed).
/// Oracle: `first_use` answers.
/// Risk edge: a flood of proofs pushing a captured proof out of the cache to replay it.
/// Layer: unit.
/// Counterfactual: evicting the oldest entry to make room accepts the third `jti` and then the
/// replay of the first.
#[test]
fn a_full_cache_refuses_instead_of_evicting() {
    let cache = InMemoryJtiReplayCache::with_capacity(2);

    assert!(cache.first_use("a", 120, 1_000));
    assert!(cache.first_use("b", 120, 1_000));
    assert!(!cache.first_use("c", 120, 1_000), "full: refused");
    assert!(!cache.first_use("a", 120, 1_010), "still a replay");
    assert!(
        cache.first_use("c", 120, 1_200),
        "expired entries make room"
    );
}
