//! JwksCache: refresh policy, single flight, body cap and key filtering.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{FakeServer, JWKS_PATH, Reply, TestKey, jwks, jwks_server};
use loginflow_sdk::{JwksCache, LoginFlowError};
use serde_json::json;

fn cache_for(server: &FakeServer) -> JwksCache {
    JwksCache::new(
        reqwest::Client::new(),
        format!("{}{}", server.base_url, JWKS_PATH),
        Duration::from_secs(600),
    )
}

#[tokio::test]
async fn unknown_kid_triggers_exactly_one_refresh_then_rejects() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let cache = cache_for(&server).with_min_refresh_interval(Duration::ZERO);
    cache.key("kid-a").await.expect("warm the cache");
    assert_eq!(server.hits(JWKS_PATH), 1);

    let result = cache.key("kid-unknown").await;

    assert!(
        matches!(result, Err(LoginFlowError::Authentication { .. })),
        "{result:?}"
    );
    assert_eq!(
        server.hits(JWKS_PATH),
        2,
        "exactly one refresh for the unknown kid"
    );
}

#[tokio::test]
async fn unknown_kid_refreshes_at_most_once_per_interval() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let cache = cache_for(&server).with_min_refresh_interval(Duration::from_millis(300));
    cache.key("kid-a").await.expect("warm the cache");
    tokio::time::sleep(Duration::from_millis(350)).await;

    for _ in 0..5 {
        assert!(cache.key("kid-unknown").await.is_err());
    }
    assert_eq!(server.hits(JWKS_PATH), 2, "one refresh, then throttled");

    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(cache.key("kid-unknown").await.is_err());
    assert_eq!(
        server.hits(JWKS_PATH),
        3,
        "the next interval allows one more refresh"
    );
}

#[tokio::test]
async fn rotated_key_is_picked_up_by_the_unknown_kid_refresh() {
    let key_a = TestKey::a();
    let key_b = TestKey::b();
    let server = jwks_server(jwks(&[key_a.public_jwk()])).await;
    let cache = cache_for(&server).with_min_refresh_interval(Duration::ZERO);
    cache.key("kid-a").await.expect("warm the cache");

    let rotated = jwks(&[key_a.public_jwk(), key_b.public_jwk()]);
    server.set_responder(move |_| Reply::ok(rotated.clone()));

    cache.key("kid-b").await.expect("new key after rotation");
    assert_eq!(server.hits(JWKS_PATH), 2);
}

#[tokio::test]
async fn concurrent_lookups_on_a_cold_cache_download_once() {
    let key = TestKey::a();
    let document = jwks(&[key.public_jwk()]);
    let server =
        FakeServer::start(move |_| Reply::ok(document.clone()).delayed(Duration::from_millis(150)))
            .await;
    let cache = Arc::new(cache_for(&server));

    let lookups: Vec<_> = (0..16)
        .map(|_| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.key("kid-a").await })
        })
        .collect();
    for lookup in lookups {
        lookup.await.expect("join").expect("key");
    }

    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[tokio::test]
async fn only_ec_p256_es256_signature_keys_are_accepted() {
    let key = TestKey::a();
    let mut p384 = key.with_kid("kid-p384");
    p384["crv"] = json!("P-384");
    let mut es384 = key.with_kid("kid-es384");
    es384["alg"] = json!("ES384");
    let mut no_alg = key.with_kid("kid-no-alg");
    no_alg.as_object_mut().expect("object").remove("alg");
    let mut encryption = key.with_kid("kid-enc");
    encryption["use"] = json!("enc");
    let rsa = json!({ "kty": "RSA", "alg": "RS256", "kid": "kid-rsa", "n": "sXch", "e": "AQAB" });
    let hmac = json!({ "kty": "oct", "alg": "HS256", "kid": "kid-oct", "k": "c2VjcmV0" });
    let server = jwks_server(jwks(&[
        rsa,
        hmac,
        p384,
        es384,
        no_alg,
        encryption,
        key.public_jwk(),
    ]))
    .await;
    let cache = cache_for(&server);

    cache.key("kid-a").await.expect("the ES256 key");
    for kid in [
        "kid-rsa",
        "kid-oct",
        "kid-p384",
        "kid-es384",
        "kid-no-alg",
        "kid-enc",
    ] {
        assert!(
            matches!(
                cache.key(kid).await,
                Err(LoginFlowError::Authentication { .. })
            ),
            "{kid} must be ignored"
        );
    }
}

#[tokio::test]
async fn key_set_without_usable_keys_is_an_error() {
    let rsa = json!({ "kty": "RSA", "alg": "RS256", "kid": "kid-rsa", "n": "sXch", "e": "AQAB" });
    let server = jwks_server(jwks(&[rsa])).await;
    let cache = cache_for(&server);

    assert!(matches!(
        cache.key("kid-rsa").await,
        Err(LoginFlowError::Jwks(_))
    ));
}

#[tokio::test]
async fn failing_jwks_endpoint_is_an_error_and_is_not_hammered() {
    let server = FakeServer::start(|_| Reply::status(500, "{}")).await;
    let cache = cache_for(&server);

    for _ in 0..3 {
        assert!(matches!(
            cache.key("kid-a").await,
            Err(LoginFlowError::Jwks(_))
        ));
    }
    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[tokio::test]
async fn failed_ttl_refresh_keeps_serving_cached_keys() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    // TTL zero: every lookup is stale and triggers a refresh.
    let cache = JwksCache::new(
        reqwest::Client::new(),
        format!("{}{}", server.base_url, JWKS_PATH),
        Duration::ZERO,
    )
    .with_min_refresh_interval(Duration::ZERO);
    cache.key("kid-a").await.expect("initial download");

    server.set_responder(|_| Reply::status(500, "{}"));

    cache
        .key("kid-a")
        .await
        .expect("cached key served while the JWKS endpoint fails");
    assert_eq!(server.hits(JWKS_PATH), 2, "the refresh was attempted");
    assert!(
        matches!(
            cache.key("kid-unknown").await,
            Err(LoginFlowError::Authentication { .. })
        ),
        "an unknown kid is still rejected"
    );
}
