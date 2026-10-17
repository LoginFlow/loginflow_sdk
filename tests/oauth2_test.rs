//! `ClientCredentialsClient` (caching), `IntrospectionClient` (RFC 7662 parsing) and
//! `RevocationClient` (RFC 7009).

mod common;

use common::{FakeServer, Reply};
use loginflow_sdk::{
    ClientCredentialsClient, DiscoveryDocument, IntrospectionClient, RevocationClient,
};
use reqwest::Client;
use serde_json::json;

/// TEST_CHARTER
/// Requirement: `ClientCredentialsClient::access_token` caches the token and only fetches a new
/// one once the cached one is stale (RFC 6749 §4.4: cache until shortly before expiry,
/// single-flight).
/// Oracle: the number of `POST /oauth2/token` requests the fake server recorded.
/// Risk edge: a service client calling `access_token()` on every outgoing request must not hit
/// the token endpoint every time — that would defeat the point of `client_credentials` caching.
/// Layer: unit/integration against the in-process `FakeServer` (real HTTP over loopback).
/// Counterfactual: a `ClientCredentialsClient` that never caches (always fetches) makes this
/// test's second assertion (`hits == 1`) fail, since three calls would hit the server three times.
#[tokio::test]
async fn client_credentials_token_is_cached_across_calls() {
    let server = FakeServer::start(|_| {
        Reply::ok(
            json!({ "access_token": "app-token-1", "token_type": "Bearer", "expires_in": 900 })
                .to_string(),
        )
    })
    .await;
    let client = ClientCredentialsClient::new(
        Client::new(),
        format!("{}/oauth2/token", server.base_url),
        "svc-client",
        "svc-secret",
    );

    let first = client.access_token().await.expect("first token");
    let second = client.access_token().await.expect("second token (cached)");
    let third = client.access_token().await.expect("third token (cached)");

    assert_eq!(first, "app-token-1");
    assert_eq!(second, "app-token-1");
    assert_eq!(third, "app-token-1");
    assert_eq!(
        server.hits("/oauth2/token"),
        1,
        "three calls must share one cached token"
    );
}

/// A client whose cached token already expired fetches a fresh one (the cache is not permanent).
#[tokio::test]
async fn client_credentials_refetches_once_the_cached_token_is_stale() {
    let server = FakeServer::start(|_| {
        Reply::ok(
            json!({ "access_token": "app-token-1", "token_type": "Bearer", "expires_in": 0 })
                .to_string(),
        )
    })
    .await;
    let client = ClientCredentialsClient::new(
        Client::new(),
        format!("{}/oauth2/token", server.base_url),
        "svc-client",
        "svc-secret",
    );

    client.access_token().await.expect("first token");
    client.access_token().await.expect("second token");

    assert_eq!(
        server.hits("/oauth2/token"),
        2,
        "an expires_in of 0 must never be served from cache"
    );
}

/// TEST_CHARTER
/// Requirement: `IntrospectionClient::introspect` parses the RFC 7662 response shape the server
/// sends: `active`, `sub`, `client_id`, `scope`, `exp`, `iat`, `iss`, `token_type`.
/// Oracle: the parsed `IntrospectionResponse` fields.
/// Risk edge: an inactive/unknown token's short `{"active": false}` form (no other fields) must
/// still parse, not error.
/// Layer: unit against the in-process `FakeServer`.
/// Counterfactual: a typo in a field name (e.g. `active_introspection` sending `"sub"` under a
/// different key) makes `introspection.sub` come back `None` and this test fails.
#[tokio::test]
async fn introspection_parses_an_active_token() {
    let server = FakeServer::start(|_| {
        Reply::ok(
            json!({
                "active": true, "sub": "cu-1", "client_id": "app-one", "scope": "openid profile",
                "exp": 1_900_000_000i64, "iat": 1_899_999_000i64, "iss": "https://issuer.example",
                "token_type": "Bearer"
            })
            .to_string(),
        )
    })
    .await;
    let client = IntrospectionClient::new(
        Client::new(),
        format!("{}/oauth2/introspect", server.base_url),
        "confidential-client",
        "secret",
    );

    let introspection = client
        .introspect("some-access-token")
        .await
        .expect("introspect");

    assert!(introspection.active);
    assert_eq!(introspection.sub.as_deref(), Some("cu-1"));
    assert_eq!(introspection.client_id.as_deref(), Some("app-one"));
    assert_eq!(introspection.scope.as_deref(), Some("openid profile"));
    assert_eq!(introspection.exp, Some(1_900_000_000));
}

/// The short `{"active": false}` form (an inactive, unknown or foreign-client token) parses too.
#[tokio::test]
async fn introspection_parses_an_inactive_token() {
    let server = FakeServer::start(|_| Reply::ok(json!({ "active": false }).to_string())).await;
    let client = IntrospectionClient::new(
        Client::new(),
        format!("{}/oauth2/introspect", server.base_url),
        "confidential-client",
        "secret",
    );

    let introspection = client
        .introspect("unknown-token")
        .await
        .expect("introspect");

    assert!(!introspection.active);
    assert_eq!(introspection.sub, None);
}

/// TEST_CHARTER
/// Requirement: `IntrospectionClient::introspect_cached` serves the same answer for up to
/// `INTROSPECTION_CACHE_TTL` without a new network round trip — the whole point of a sensitive
/// operation using this over `introspect` is bounding the cost, not eliminating the live check.
/// Oracle: the number of `POST /oauth2/introspect` requests the fake server recorded.
/// Risk edge: caching an `active: false` answer would mask a token that becomes valid again
/// within the TTL window — that case must always hit the network.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: a version of `introspect_cached` that never caches makes the first
/// assertion (`hits == 1` after two active-token calls) fail with `hits == 2`.
#[tokio::test]
async fn introspect_cached_serves_an_active_answer_from_cache() {
    let server =
        FakeServer::start(|_| Reply::ok(json!({ "active": true, "sub": "cu-1" }).to_string()))
            .await;
    let client = IntrospectionClient::new(
        Client::new(),
        format!("{}/oauth2/introspect", server.base_url),
        "confidential-client",
        "secret",
    );

    let first = client
        .introspect_cached("some-access-token")
        .await
        .expect("first introspection");
    let second = client
        .introspect_cached("some-access-token")
        .await
        .expect("second introspection (cached)");

    assert!(first.active);
    assert!(second.active);
    assert_eq!(
        server.hits("/oauth2/introspect"),
        1,
        "two calls for the same token within the TTL must share one network round trip"
    );
}

/// An `active: false` answer is never cached: the next call for the same token hits the network
/// again, so a token that becomes valid shortly after is never masked by a stale rejection.
#[tokio::test]
async fn introspect_cached_never_caches_an_inactive_answer() {
    let server = FakeServer::start(|_| Reply::ok(json!({ "active": false }).to_string())).await;
    let client = IntrospectionClient::new(
        Client::new(),
        format!("{}/oauth2/introspect", server.base_url),
        "confidential-client",
        "secret",
    );

    client
        .introspect_cached("unknown-token")
        .await
        .expect("first introspection");
    client
        .introspect_cached("unknown-token")
        .await
        .expect("second introspection");

    assert_eq!(
        server.hits("/oauth2/introspect"),
        2,
        "an inactive answer must never be served from cache"
    );
}

/// TEST_CHARTER
/// Requirement: `RevocationClient::revoke` authenticates with `client_secret_basic` (RFC 6749
/// §2.3.1 / RFC 7009 §2.1), which the server now requires on `/oauth2/revoke`.
/// Oracle: the `Authorization` header and `token` form field the fake server recorded.
/// Risk edge: a revoke call sent without client authentication would be silently accepted by a
/// server that used to allow it — this SDK must never regress to that.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: a `RevocationClient` that forgets `.basic_auth(...)` makes the
/// `authorization` header assertion fail (`None` instead of the Basic value).
#[tokio::test]
async fn revoke_authenticates_with_client_secret_basic_and_sends_the_token() {
    let server = FakeServer::start(|_| Reply::ok(String::new())).await;
    let client = RevocationClient::new(
        Client::new(),
        format!("{}/oauth2/revoke", server.base_url),
        "confidential-client",
        "secret",
    );

    client
        .revoke("some-refresh-or-access-token")
        .await
        .expect("revoke");

    let req = server.last();
    assert_eq!(req.method, "POST");
    assert_eq!(req.path(), "/oauth2/revoke");
    assert!(
        req.header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
        "revoke must authenticate the client, not just send client_id"
    );
    assert!(req.body.contains("token=some-refresh-or-access-token"));
}

/// A client authentication failure (wrong secret) is surfaced as an error, not swallowed as a
/// no-op success — RFC 7009 §2.1 only hides whether the *token* was valid, never a rejected
/// client.
#[tokio::test]
async fn revoke_with_rejected_client_credentials_is_an_error() {
    let server = FakeServer::start(|_| {
        Reply::status(
            401,
            json!({ "error": { "code": "UNAUTHORIZED", "message": "invalid_client" } }).to_string(),
        )
    })
    .await;
    let client = RevocationClient::new(
        Client::new(),
        format!("{}/oauth2/revoke", server.base_url),
        "confidential-client",
        "wrong-secret",
    );

    let result = client.revoke("some-token").await;

    assert!(
        result.is_err(),
        "a rejected client must surface as an error"
    );
}

/// `from_discovery` resolves each endpoint from the document instead of a hardcoded path — the
/// same server contract `ClientCredentialsClient`/`IntrospectionClient`/`RevocationClient`'s
/// `new` already talks to, just not assembled by this SDK.
#[tokio::test]
async fn from_discovery_constructors_use_the_documents_endpoints() {
    let server = FakeServer::start(|_| {
        Reply::ok(
            json!({ "access_token": "t", "token_type": "Bearer", "expires_in": 900 }).to_string(),
        )
    })
    .await;
    let discovery = DiscoveryDocument {
        issuer: "https://api.loginflow.test".to_string(),
        jwks_uri: format!("{}/oauth2/jwks", server.base_url),
        authorization_endpoint: format!("{}/oauth2/authorize", server.base_url),
        token_endpoint: format!("{}/oauth2/token", server.base_url),
        userinfo_endpoint: format!("{}/oauth2/userinfo", server.base_url),
        introspection_endpoint: format!("{}/oauth2/introspect", server.base_url),
        revocation_endpoint: format!("{}/oauth2/revoke", server.base_url),
        end_session_endpoint: format!("{}/oauth2/end-session", server.base_url),
        authorization_challenge_endpoint: None,
        login_options_endpoint: None,
        device_logout_endpoint: None,
        global_logout_endpoint: None,
    };

    let client = ClientCredentialsClient::from_discovery(
        Client::new(),
        &discovery,
        "svc-client",
        "svc-secret",
    );

    client.access_token().await.expect("token via discovery");

    assert_eq!(server.last().path(), "/oauth2/token");
}
