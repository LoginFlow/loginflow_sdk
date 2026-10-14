//! Local verification of LoginFlow access tokens: ES256 only, key chosen by
//! `kid` from the issuer's JWKS, then issuer / audience / expiration /
//! token_type / status checks.

mod common;

use common::{
    APP_ID, ISSUER, JWKS_PATH, Reply, TestKey, USER_ID, access_claims, claims_with, client_for,
    jwks, jwks_server, now,
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

    assert_eq!(claims.user_id, USER_ID);
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.aud, APP_ID);
    assert_eq!(claims.token_type, "access");
    let user = client
        .extract_user_from_token(&key.sign(&access_claims()))
        .await
        .expect("user");
    assert_eq!(user.user_id.to_string(), USER_ID);
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
    let token = encode(
        &Header::new(Algorithm::ES256),
        &access_claims(),
        &key.encoding,
    )
    .expect("sign");

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

#[tokio::test]
async fn refresh_token_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let msg = assert_rejected(
        client
            .verify_token(&key.sign(&claims_with("token_type", json!("refresh"))))
            .await,
    );
    assert!(msg.contains("token_type"), "{msg}");
}

#[tokio::test]
async fn totp_challenge_and_password_reset_tokens_are_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    for token_type in ["totp_challenge", "password_reset"] {
        // Non-access tokens carry aud = issuer; even with the app audience they must fail.
        assert_rejected(
            client
                .verify_token(&key.sign(&claims_with("token_type", json!(token_type))))
                .await,
        );
        let mut claims = claims_with("token_type", json!(token_type));
        claims["aud"] = json!(ISSUER);
        assert_rejected(client.verify_token(&key.sign(&claims)).await);
    }
}

#[tokio::test]
async fn token_without_token_type_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut claims = access_claims();
    claims.as_object_mut().expect("object").remove("token_type");

    let msg = assert_rejected(client.verify_token(&key.sign(&claims)).await);
    assert!(msg.contains("token_type"), "{msg}");
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
async fn inactive_user_token_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    assert_rejected(
        client
            .verify_token(&key.sign(&claims_with("status", json!("inactive"))))
            .await,
    );
}

#[tokio::test]
async fn token_carrying_both_exp_and_expires_in_parses() {
    // v0.4.x aliased exp -> expires_in and iat -> created_at, so a token with both failed to parse.
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let claims = client
        .verify_token(&key.sign(&access_claims()))
        .await
        .expect("valid token");

    assert!(claims.expires_in.is_some());
    assert!(claims.created_at.is_some());
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
