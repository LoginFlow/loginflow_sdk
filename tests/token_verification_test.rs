//! Local verification of LoginFlow access tokens: ES256 only, key chosen by
//! `kid` from the issuer's JWKS, then issuer / audience / expiration checks.

mod common;

use common::{
    APP_ID, COMPANY_ID, ISSUER, JWKS_PATH, Reply, TestKey, USER_ID, access_claims, claims_with,
    client_for, jwks, jwks_server, now,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use loginflow_sdk::LoginFlowError;
use loginflow_sdk::jwks::JWKS_BODY_LIMIT;
use serde_json::json;

fn assert_rejected(result: Result<loginflow_sdk::JwtClaims, LoginFlowError>) -> String {
    match result {
        Ok(claims) => panic!("token accepted: {claims:?}"),
        Err(LoginFlowError::Authentication(msg)) => msg,
        Err(other) => panic!("expected an authentication error, got {other:?}"),
    }
}

#[tokio::test]
async fn es256_access_token_signed_by_a_published_key_verifies() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let claims = client
        .verify_token(&key.sign(&access_claims()))
        .await
        .expect("valid token");

    assert_eq!(claims.sub, USER_ID);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.aud, APP_ID);
    let user = client
        .extract_user_from_token(&key.sign(&access_claims()))
        .await
        .expect("user");
    assert_eq!(user.company_user_id.to_string(), USER_ID);
}

// Federations: `auth_cid` names the AUTHENTICATING company, present only on a cross-company
// token (a `session`-level federation reuse or Native SSO exchange) — the SDK must surface it on
// both the raw claims and `AuthenticatedUser`, and never fabricate one when the server never
// sent it.
#[tokio::test]
async fn auth_cid_is_exposed_on_claims_and_authenticated_user_when_present() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let other_company = "33333333-3333-3333-3333-333333333333";
    let claims_json = claims_with("auth_cid", serde_json::json!(other_company));

    let claims = client
        .verify_token(&key.sign(&claims_json))
        .await
        .expect("valid token");
    assert_eq!(claims.auth_cid.as_deref(), Some(other_company));

    let user = client
        .extract_user_from_token(&key.sign(&claims_json))
        .await
        .expect("user");
    assert_eq!(
        user.auth_cid,
        Some(other_company.parse::<uuid::Uuid>().expect("uuid"))
    );
    assert_eq!(
        user.company_id,
        COMPANY_ID.parse::<uuid::Uuid>().expect("uuid")
    );

    // Counterfactual: an ordinary token (no `auth_cid` sent by the server at all) must never
    // have one fabricated — same-company tokens are the overwhelming majority.
    let ordinary_claims = client
        .verify_token(&key.sign(&access_claims()))
        .await
        .expect("valid token");
    assert_eq!(ordinary_claims.auth_cid, None);
    let ordinary_user = client
        .extract_user_from_token(&key.sign(&access_claims()))
        .await
        .expect("user");
    assert_eq!(ordinary_user.auth_cid, None);
}

#[tokio::test]
async fn jwks_is_downloaded_once_and_reused() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    for _ in 0..3 {
        client
            .verify_token(&key.sign(&access_claims()))
            .await
            .expect("valid token");
    }

    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[tokio::test]
async fn hs256_token_is_rejected_even_with_a_known_kid() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(key.kid.clone());
    let token = encode(
        &header,
        &access_claims(),
        &EncodingKey::from_secret(b"legacy-signing-secret"),
    )
    .expect("sign");

    assert_rejected(client.verify_token(&token).await);
    assert_eq!(
        server.hits(JWKS_PATH),
        0,
        "an HS256 token must not trigger a JWKS download"
    );
}

#[tokio::test]
async fn token_without_kid_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("at+jwt".to_string());
    let token = encode(&header, &access_claims(), &key.encoding).expect("sign");

    let msg = assert_rejected(client.verify_token(&token).await);
    assert!(msg.contains("kid"), "{msg}");
}

#[tokio::test]
async fn token_signed_by_another_key_under_a_published_kid_is_rejected() {
    let published = TestKey::a();
    let attacker = TestKey::b();
    let server = jwks_server(jwks(&[published.public_jwk()])).await;
    let client = client_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(published.kid.clone());
    let token = encode(&header, &access_claims(), &attacker.encoding).expect("sign");

    assert_rejected(client.verify_token(&token).await);
}

#[tokio::test]
async fn token_from_another_issuer_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    assert_rejected(
        client
            .verify_token(&key.sign(&claims_with("iss", json!("https://evil.example"))))
            .await,
    );
}

#[tokio::test]
async fn token_for_another_application_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    assert_rejected(
        client
            .verify_token(&key.sign(&claims_with("aud", json!("other-application"))))
            .await,
    );
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    assert_rejected(
        client
            .verify_token(&key.sign(&claims_with("exp", json!(now() - 120))))
            .await,
    );
}

#[tokio::test]
async fn token_expired_within_the_leeway_is_accepted() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    client
        .verify_token(&key.sign(&claims_with("exp", json!(now() - 10))))
        .await
        .expect("within 30 s leeway");
}

/// A TOTP-challenge/password-reset token (or any other non-access LoginFlow JWT) is never typed
/// `at+jwt` — the server mints those with header `typ: "JWT"` — so the header check alone, not a
/// `token_type` claim (removed: the access token carries no such claim anymore), is what rejects
/// a token-confusion attempt here.
#[tokio::test]
async fn a_non_access_token_header_typ_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("JWT".to_string());
    let token = encode(&header, &access_claims(), &key.encoding).expect("sign");

    let msg = assert_rejected(client.verify_token(&token).await);
    assert!(msg.contains("typ"), "{msg}");
}

#[tokio::test]
async fn token_without_sub_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut claims = access_claims();
    claims.as_object_mut().expect("object").remove("sub");

    assert_rejected(client.verify_token(&key.sign(&claims)).await);
}

#[tokio::test]
async fn token_carrying_unknown_extra_claims_still_parses() {
    // `JwtClaims` must not break on a server adding a field it doesn't know about yet.
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let claims = client
        .verify_token(&key.sign(&claims_with("some_future_claim", json!("x"))))
        .await
        .expect("valid token");

    assert_eq!(claims.sub, USER_ID);
}

#[tokio::test]
async fn jwks_body_over_the_limit_is_rejected() {
    let key = TestKey::a();
    let padding = "x".repeat(JWKS_BODY_LIMIT);
    let oversized = json!({ "keys": [key.public_jwk()], "padding": padding }).to_string();
    let server = jwks_server(oversized).await;
    let client = client_for(&server);

    let result = client.verify_token(&key.sign(&access_claims())).await;

    assert!(
        matches!(&result, Err(LoginFlowError::Jwks(msg)) if msg.contains("exceeds")),
        "{result:?}"
    );
}

#[tokio::test]
async fn jwks_body_over_the_limit_without_content_length_is_rejected() {
    let key = TestKey::a();
    let padding = "x".repeat(JWKS_BODY_LIMIT);
    let oversized = json!({ "keys": [key.public_jwk()], "padding": padding }).to_string();
    let server =
        common::FakeServer::start(move |_| Reply::ok(oversized.clone()).without_content_length())
            .await;
    let client = client_for(&server);

    let result = client.verify_token(&key.sign(&access_claims())).await;

    assert!(
        matches!(&result, Err(LoginFlowError::Jwks(msg)) if msg.contains("exceeds")),
        "{result:?}"
    );
}

#[tokio::test]
async fn unknown_kid_is_rejected_without_a_second_download_inside_the_refresh_interval() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    client
        .verify_token(&key.sign(&access_claims()))
        .await
        .expect("warm the cache");

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("kid-unknown".to_string());
    let unknown = encode(&header, &access_claims(), &key.encoding).expect("sign");
    assert_rejected(client.verify_token(&unknown).await);
    assert_rejected(client.verify_token(&unknown).await);

    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[test]
fn client_requires_an_issuer() {
    let mut config = loginflow_sdk::LoginFlowConfig {
        base_url: "https://api.loginflow.test".into(),
        api_version: 1,
        company_id: "c".into(),
        application_id: APP_ID.into(),
        timeout_secs: 5,
        user_agent: None,
        issuer: String::new(),
        jwks_url: None,
        jwks_cache_ttl_secs: 600,
    };
    assert!(matches!(
        loginflow_sdk::LoginFlowClient::new(config.clone()),
        Err(LoginFlowError::Config(_))
    ));

    config.issuer = ISSUER.into();
    assert_eq!(
        config.resolved_jwks_url(),
        "https://api.loginflow.test/oauth2/jwks"
    );
    assert!(loginflow_sdk::LoginFlowClient::new(config).is_ok());
}

#[tokio::test]
async fn non_uuid_company_or_application_id_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    for field in ["company_id", "application_id"] {
        let token = key.sign(&claims_with(field, json!("not-a-uuid")));
        match client.extract_user_from_token(&token).await {
            Err(LoginFlowError::Authentication(_)) => {}
            other => panic!("{field}: expected an authentication error, got {other:?}"),
        }
    }
}

/// TEST_CHARTER
/// Requirement: `verify_token` enforces the RFC 9068 §2.1 header `typ: at+jwt`;
/// a token with a different (or missing) `typ` must be rejected before any claim is trusted, even
/// when it carries a syntactically valid access-token claim set and a valid signature.
/// Oracle: `verify_token`'s `Result` — `Err(Authentication(_))`, never `Ok`.
/// Risk edge: token-type confusion (an ID token or any other JWT signed by the same key reused as
/// an access token).
/// Layer: unit, against `TestKey`'s real ES256 signing (no network beyond the JWKS fetch).
/// Counterfactual: removing the `typ` check in `verify_token` makes this test accept the token
/// (and pass), so the test only holds while the check is in place.
#[tokio::test]
async fn access_token_with_the_wrong_header_typ_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let wrong_typ = key.sign_with_typ(&access_claims(), Some("JWT"));
    assert_rejected(client.verify_token(&wrong_typ).await);

    let no_typ = key.sign_with_typ(&access_claims(), None);
    assert_rejected(client.verify_token(&no_typ).await);

    // The control case (the real `typ`) still verifies, so the rejection above is about `typ`,
    // not an unrelated claim.
    let correct_typ = key.sign(&access_claims());
    client
        .verify_token(&correct_typ)
        .await
        .expect("the at+jwt token must verify");
}
