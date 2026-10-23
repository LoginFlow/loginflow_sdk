//! OIDC Back-Channel Logout 1.0 §2.6: `LoginFlowClient::verify_logout_token` checks header
//! `typ`, signature/issuer/audience (the RP's client_id), the single `events` member,
//! `sub`/`sid` presence, and
//! rejects a token carrying a `nonce` (the one thing an attacker would add to replay an ID
//! token as a logout token).

mod common;

use common::{API_AUDIENCE, ISSUER, TestKey, client_for, jwks, jwks_server, now};
use serde_json::json;

/// The RP's OAuth client: LoginFlow addresses a logout token to it.
const RP_CLIENT_ID: &str = "console";

fn logout_claims() -> serde_json::Value {
    json!({
        "iss": ISSUER,
        "aud": RP_CLIENT_ID,
        "iat": now(),
        "jti": "logout-jti-1",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        "sub": "cu-1",
        "sid": "sid-1",
    })
}

#[tokio::test]
async fn a_well_formed_logout_token_verifies() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let token = key.sign_with_typ(&logout_claims(), Some("logout+jwt"));
    let claims = client
        .verify_logout_token(&token, RP_CLIENT_ID)
        .await
        .expect("a well-formed logout token must verify");

    assert_eq!(claims.sub, Some("cu-1".to_string()));
    assert_eq!(claims.sid, Some("sid-1".to_string()));
}

#[tokio::test]
async fn a_logout_token_carrying_a_nonce_is_rejected() {
    // Counterfactual for the test above: the ONLY thing that changes is an added `nonce` — same
    // signature, same issuer/audience, same events. If this does not get rejected, the `nonce`
    // check does nothing.
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let mut claims = logout_claims();
    claims["nonce"] = json!("should-never-be-here");
    let token = key.sign_with_typ(&claims, Some("logout+jwt"));

    let result = client.verify_logout_token(&token, RP_CLIENT_ID).await;
    assert!(
        result.is_err(),
        "a logout token with a nonce must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn a_logout_token_without_sub_or_sid_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let mut claims = logout_claims();
    claims.as_object_mut().unwrap().remove("sub");
    claims.as_object_mut().unwrap().remove("sid");
    let token = key.sign_with_typ(&claims, Some("logout+jwt"));

    let result = client.verify_logout_token(&token, RP_CLIENT_ID).await;
    assert!(result.is_err(), "got {result:?}");
}

#[tokio::test]
async fn an_access_token_typ_is_rejected_as_a_logout_token() {
    // A valid, otherwise well-formed token typed `at+jwt` must never be accepted here — the
    // `typ` check is what tells a logout token apart from any other LoginFlow-issued JWT.
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let token = key.sign_with_typ(&logout_claims(), Some("at+jwt"));
    let result = client.verify_logout_token(&token, RP_CLIENT_ID).await;
    assert!(result.is_err(), "got {result:?}");
}

/// TEST_CHARTER
/// Requirement: a logout token is accepted only when its `aud` is the RP's client_id — the one
/// LoginFlow addresses it to (`LogoutTokenClaims::new` in the API) — and never because its
/// `aud` is the API's audience.
/// Oracle: `verify_logout_token`'s `Result`.
/// Risk edge: a logout token minted for another RP ending this RP's sessions.
/// Layer: unit against real ES256 signing and the in-process JWKS.
/// Counterfactual: validating `aud` against the configured API audience rejects the RP's own
/// token (first assertion) and accepts the API-addressed one (second).
#[tokio::test]
async fn a_logout_token_for_another_audience_is_rejected() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);

    let token = key.sign_with_typ(&logout_claims(), Some("logout+jwt"));
    client
        .verify_logout_token(&token, RP_CLIENT_ID)
        .await
        .expect("the RP's own logout token verifies");

    let mut for_api = logout_claims();
    for_api["aud"] = json!(API_AUDIENCE);
    let token = key.sign_with_typ(&for_api, Some("logout+jwt"));
    assert!(
        client
            .verify_logout_token(&token, RP_CLIENT_ID)
            .await
            .is_err()
    );
}
