//! Local verification of LoginFlow access tokens by `TokenVerifier`: ES256 only, key chosen by
//! `kid` from the issuer's JWKS, then issuer / audience (this API) / expiration checks.

mod common;

use common::{
    API_AUDIENCE, APP_ID, COMPANY_ID, ISSUER, JWKS_PATH, OTHER_API_AUDIENCE, Reply, TestKey,
    USER_ID, access_claims, claims_with, config_for, jwks, jwks_server, now, verifier_for,
    verifier_with, verify_bearer,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use loginflow_sdk::jwks::JWKS_BODY_LIMIT;
use loginflow_sdk::{LoginFlowError, VerifiedAccess, VerifyError};
use serde_json::json;

fn assert_rejected(result: Result<VerifiedAccess, VerifyError>) -> String {
    match result {
        Ok(access) => panic!("token accepted: {:?}", access.claims),
        Err(VerifyError::InvalidToken(msg)) => msg,
        Err(other) => panic!("expected an invalid-token error, got {other:?}"),
    }
}

#[tokio::test]
async fn es256_access_token_signed_by_a_published_key_verifies() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    let access = verify_bearer(&verifier, &key.sign(&access_claims()))
        .await
        .expect("valid token");

    assert_eq!(access.claims.sub, USER_ID);
    assert_eq!(access.claims.iss, ISSUER);
    assert_eq!(access.claims.aud, API_AUDIENCE);
    assert_eq!(access.claims.app, APP_ID);
    assert_eq!(access.claims.company_id, COMPANY_ID);
    assert!(access.permissions.contains("rutafacil.drivers.list"));
    assert_eq!(access.dpop_jkt, None);
}

// Federations: `auth_cid` names the AUTHENTICATING company, present only on a cross-company
// token (a `session`-level federation reuse or Native SSO exchange) — the SDK must surface it,
// and never fabricate one when the server never sent it.
#[tokio::test]
async fn auth_cid_is_exposed_on_claims_when_present() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let other_company = "CP-OTHER";
    let claims_json = claims_with("auth_cid", serde_json::json!(other_company));

    let access = verify_bearer(&verifier, &key.sign(&claims_json))
        .await
        .expect("valid token");
    assert_eq!(access.claims.auth_cid.as_deref(), Some(other_company));
    assert_eq!(access.claims.company_id, COMPANY_ID);

    // Counterfactual: an ordinary token (no `auth_cid` sent by the server at all) must never
    // have one fabricated — same-company tokens are the overwhelming majority.
    let ordinary = verify_bearer(&verifier, &key.sign(&access_claims()))
        .await
        .expect("valid token");
    assert_eq!(ordinary.claims.auth_cid, None);
}

#[tokio::test]
async fn jwks_is_downloaded_once_and_reused() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    for _ in 0..3 {
        verify_bearer(&verifier, &key.sign(&access_claims()))
            .await
            .expect("valid token");
    }

    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[tokio::test]
async fn hs256_token_is_rejected_even_with_a_known_kid() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(key.kid.clone());
    let token = encode(
        &header,
        &access_claims(),
        &EncodingKey::from_secret(b"legacy-signing-secret"),
    )
    .expect("sign");

    assert_rejected(verify_bearer(&verifier, &token).await);
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
    let verifier = verifier_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("at+jwt".to_string());
    let token = encode(&header, &access_claims(), &key.encoding).expect("sign");

    let msg = assert_rejected(verify_bearer(&verifier, &token).await);
    assert!(msg.contains("kid"), "{msg}");
}

#[tokio::test]
async fn token_signed_by_another_key_under_a_published_kid_is_rejected() {
    let published = TestKey::a();
    let attacker = TestKey::b();
    let server = jwks_server(jwks(&[published.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(published.kid.clone());
    let token = encode(&header, &access_claims(), &attacker.encoding).expect("sign");

    assert_rejected(verify_bearer(&verifier, &token).await);
}

#[tokio::test]
async fn token_from_another_issuer_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    assert_rejected(
        verify_bearer(
            &verifier,
            &key.sign(&claims_with("iss", json!("https://evil.example"))),
        )
        .await,
    );
}

/// TEST_CHARTER
/// Requirement: a token is accepted only by the API it was minted for (`aud` = `LOGINFLOW_API`):
/// a token of another API of the same application, LoginFlow's own token (`aud` = the issuer)
/// and a token addressed to the application id are all rejected.
/// Oracle: `verify_presented`'s `Result`.
/// Risk edge: one API replaying another API's token (spec §10).
/// Layer: unit against real ES256 signing and the in-process JWKS.
/// Counterfactual: pinning the validation audience to anything but `api_audience` (e.g. the
/// application) makes the other-API token pass.
#[tokio::test]
async fn token_for_another_api_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    for audience in [OTHER_API_AUDIENCE, ISSUER, APP_ID] {
        let msg = assert_rejected(
            verify_bearer(&verifier, &key.sign(&claims_with("aud", json!(audience)))).await,
        );
        assert!(msg.contains("Audience"), "{audience}: {msg}");
    }
    verify_bearer(&verifier, &key.sign(&access_claims()))
        .await
        .expect("the token of this API verifies");
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    assert_rejected(
        verify_bearer(
            &verifier,
            &key.sign(&claims_with("exp", json!(now() - 120))),
        )
        .await,
    );
}

#[tokio::test]
async fn token_expired_within_the_leeway_is_accepted() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    verify_bearer(&verifier, &key.sign(&claims_with("exp", json!(now() - 10))))
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
    let verifier = verifier_for(&server);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    header.typ = Some("JWT".to_string());
    let token = encode(&header, &access_claims(), &key.encoding).expect("sign");

    let msg = assert_rejected(verify_bearer(&verifier, &token).await);
    assert!(msg.contains("typ"), "{msg}");
}

#[tokio::test]
async fn token_without_sub_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let mut claims = access_claims();
    claims.as_object_mut().expect("object").remove("sub");

    assert_rejected(verify_bearer(&verifier, &key.sign(&claims)).await);
}

#[tokio::test]
async fn token_carrying_unknown_extra_claims_still_parses() {
    // `AccessClaims` must not break on a server adding a field it doesn't know about yet.
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    let access = verify_bearer(
        &verifier,
        &key.sign(&claims_with("some_future_claim", json!("x"))),
    )
    .await
    .expect("valid token");

    assert_eq!(access.claims.sub, USER_ID);
}

#[tokio::test]
async fn jwks_body_over_the_limit_is_rejected() {
    let key = TestKey::a();
    let padding = "x".repeat(JWKS_BODY_LIMIT);
    let oversized = json!({ "keys": [key.public_jwk()], "padding": padding }).to_string();
    let server = jwks_server(oversized).await;
    let verifier = verifier_for(&server);

    let result = verify_bearer(&verifier, &key.sign(&access_claims())).await;

    assert!(
        matches!(&result, Err(VerifyError::Unavailable(_))),
        "{:?}",
        result.err()
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
    let verifier = verifier_for(&server);

    let result = verify_bearer(&verifier, &key.sign(&access_claims())).await;

    assert!(
        matches!(&result, Err(VerifyError::Unavailable(_))),
        "{:?}",
        result.err()
    );
}

#[tokio::test]
async fn unknown_kid_is_rejected_without_a_second_download_inside_the_refresh_interval() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    verify_bearer(&verifier, &key.sign(&access_claims()))
        .await
        .expect("warm the cache");

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("kid-unknown".to_string());
    let unknown = encode(&header, &access_claims(), &key.encoding).expect("sign");
    assert_rejected(verify_bearer(&verifier, &unknown).await);
    assert_rejected(verify_bearer(&verifier, &unknown).await);

    assert_eq!(server.hits(JWKS_PATH), 1);
}

#[test]
fn client_requires_an_issuer() {
    let mut config = loginflow_sdk::LoginFlowConfig {
        base_url: "https://api.loginflow.test".into(),
        api_version: 1,
        company_id: "c".into(),
        api_audience: API_AUDIENCE.into(),
        timeout_secs: 5,
        user_agent: None,
        issuer: String::new(),
        jwks_url: None,
        jwks_cache_ttl_secs: 600,
        resource_base_url: None,
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

/// TEST_CHARTER
/// Requirement: the verifier accepts the identifiers LoginFlow really issues — `company_id`
/// `CP-...`, `app` `APP-...`, and a `client_credentials` `sub` that is a client_id slug, not a
/// UUID — and surfaces them unchanged.
/// Oracle: the `Result` of `verify_presented` and the ids on the returned claims.
/// Risk edge: parsing claim ids as UUIDs rejects every real token (SDK <= 0.6 bug).
/// Layer: unit against `TestKey`'s real ES256 signing and the in-process JWKS server.
/// Counterfactual: re-introducing UUID parsing of `sub`/`company_id`/`app` turns the
/// `expect("real ids")` below into a panic.
#[tokio::test]
async fn real_prefixed_ids_and_a_client_id_subject_are_accepted() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let mut config = config_for(&server);
    config.company_id = "CP-01JABCDEF".into();
    let client = loginflow_sdk::LoginFlowClient::new(config).expect("client");
    let verifier = verifier_with(client, &server);
    let mut claims = access_claims();
    claims["sub"] = json!("billing-service");
    claims["company_id"] = json!("CP-01JABCDEF");
    claims["app"] = json!("APP-01JABCDEF");
    claims["auth_cid"] = json!("CP-01JOTHER");

    let access = verify_bearer(&verifier, &key.sign(&claims))
        .await
        .expect("real ids");

    assert_eq!(access.claims.sub, "billing-service");
    assert_eq!(access.claims.company_id, "CP-01JABCDEF");
    assert_eq!(access.claims.app, "APP-01JABCDEF");
    assert_eq!(access.claims.auth_cid.as_deref(), Some("CP-01JOTHER"));
}

/// TEST_CHARTER
/// Requirement: the verifier enforces the RFC 9068 §2.1 header `typ: at+jwt`;
/// a token with a different (or missing) `typ` must be rejected before any claim is trusted, even
/// when it carries a syntactically valid access-token claim set and a valid signature.
/// Oracle: `verify_presented`'s `Result` — `Err(InvalidToken(_))`, never `Ok`.
/// Risk edge: token-type confusion (an ID token or any other JWT signed by the same key reused as
/// an access token).
/// Layer: unit, against `TestKey`'s real ES256 signing (no network beyond the JWKS fetch).
/// Counterfactual: removing the `typ` check in `access_token_kid` makes this test accept the token
/// (and pass), so the test only holds while the check is in place.
#[tokio::test]
async fn access_token_with_the_wrong_header_typ_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);

    let wrong_typ = key.sign_with_typ(&access_claims(), Some("JWT"));
    assert_rejected(verify_bearer(&verifier, &wrong_typ).await);

    let no_typ = key.sign_with_typ(&access_claims(), None);
    assert_rejected(verify_bearer(&verifier, &no_typ).await);

    // The control case (the real `typ`) still verifies, so the rejection above is about `typ`,
    // not an unrelated claim.
    let correct_typ = key.sign(&access_claims());
    verify_bearer(&verifier, &correct_typ)
        .await
        .expect("the at+jwt token must verify");
}
