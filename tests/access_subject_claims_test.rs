//! Access-code subjects: a token minted for a subject issued through
//! `/v1/service/access-codes` carries `ext_sub` (the issuer's own id), `subject_kind` and
//! `ext_profile` at the top level (never `profile`, the registered OIDC claim for a profile
//! page URL); the SDK surfaces them on the verified claims and on
//! `AuthenticatedUser`, so a resource server maps the token to its own record. An ordinary
//! token has none of them.

mod common;

use common::{TestKey, access_claims, client_for, jwks, jwks_server};
use loginflow_sdk::SubjectKind;

const SUBJECT_ID: &str = "AS-3f9c2a7d1e4b8c6a0d5f7e9b1c3a5d7f";

fn access_subject_claims() -> serde_json::Value {
    let mut claims = access_claims();
    claims["sub"] = serde_json::json!(SUBJECT_ID);
    claims["ext_sub"] = serde_json::json!("driver:42");
    claims["subject_kind"] = serde_json::json!("person");
    claims["ext_profile"] = serde_json::json!("Driver");
    // A registered OIDC `profile` claim (a URL) must never be read as the issuer's label.
    claims["profile"] = serde_json::json!("https://example.com/people/42");
    claims
}

/// TEST_CHARTER
/// Requirement: `verify_token` exposes `ext_sub`, `subject_kind` (typed) and `ext_profile` of an
/// access-code subject's token, and `extract_user_from_token` copies them onto
/// `AuthenticatedUser`.
/// Oracle: the accessors and fields of the values returned for a signed token.
/// Risk edge: without them a resource server only sees `sub` (a LoginFlow id it never stored)
/// and cannot find the driver/kiosk in its own database.
/// Layer: integration — a real ES256 token verified against the fake JWKS endpoint.
/// Counterfactual: dropping the claim fields (or the copy in `from_claims`) fails every
/// assertion on them.
#[tokio::test]
async fn access_subject_claims_are_exposed_on_claims_and_authenticated_user() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let token = key.sign(&access_subject_claims());

    let claims = client.verify_token(&token).await.expect("valid token");
    assert_eq!(claims.sub, SUBJECT_ID);
    assert_eq!(claims.ext_sub(), Some("driver:42"));
    assert_eq!(claims.subject_kind(), Some(SubjectKind::Person));
    assert_eq!(claims.ext_profile(), Some("Driver"));
    assert!(claims.is_access_code_subject());

    let user = client.extract_user_from_token(&token).await.expect("user");
    assert_eq!(user.company_user_id, SUBJECT_ID);
    assert_eq!(user.ext_sub.as_deref(), Some("driver:42"));
    assert_eq!(user.subject_kind.as_deref(), Some("person"));
    assert_eq!(user.ext_profile.as_deref(), Some("Driver"));
}

#[tokio::test]
async fn ordinary_token_has_no_access_subject_claims() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let token = key.sign(&access_claims());

    let claims = client.verify_token(&token).await.expect("valid token");
    assert_eq!(claims.ext_sub(), None);
    assert_eq!(claims.subject_kind(), None);
    assert_eq!(claims.ext_profile(), None);
    assert!(!claims.is_access_code_subject());

    let user = client.extract_user_from_token(&token).await.expect("user");
    assert_eq!(user.ext_sub, None);
    assert_eq!(user.subject_kind, None);
    assert_eq!(user.ext_profile, None);
}

/// A `subject_kind` this SDK does not know is not invented into one it does.
#[tokio::test]
async fn unknown_subject_kind_is_not_mapped() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let client = client_for(&server);
    let mut claims_json = access_subject_claims();
    claims_json["subject_kind"] = serde_json::json!("robot");

    let claims = client
        .verify_token(&key.sign(&claims_json))
        .await
        .expect("valid token");

    assert_eq!(claims.subject_kind(), None);
    assert_eq!(claims.ext_sub(), Some("driver:42"));
}
