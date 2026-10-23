//! Access-code subjects: a token minted for a subject issued through
//! `/v1/service/access-codes` carries `ext_sub` (the issuer's own id), `subject_kind` and
//! `ext_profile` at the top level (never `profile`, the registered OIDC claim for a profile
//! page URL); the SDK surfaces them on the verified claims (`access_subject`), so a resource
//! server maps the token to its own record. An ordinary token has none of them.

mod common;

use common::{TestKey, access_claims, jwks, jwks_server, verifier_for, verify_bearer};
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
/// Requirement: the verifier exposes `ext_sub`, `subject_kind` (typed) and `ext_profile` of an
/// access-code subject's token as `AccessClaims::access_subject`.
/// Oracle: the fields of the claims returned for a signed token.
/// Risk edge: without them a resource server only sees `sub` (a LoginFlow id it never stored)
/// and cannot find the driver/kiosk in its own database.
/// Layer: integration — a real ES256 token verified against the fake JWKS endpoint.
/// Counterfactual: dropping the flattened `access_subject` fails every assertion on it.
#[tokio::test]
async fn access_subject_claims_are_exposed_on_the_claims() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let token = key.sign(&access_subject_claims());

    let claims = verify_bearer(&verifier, &token)
        .await
        .expect("valid token")
        .claims;
    assert_eq!(claims.sub, SUBJECT_ID);
    let subject = claims.access_subject.as_ref().expect("access subject");
    assert_eq!(subject.ext_sub, "driver:42");
    assert_eq!(subject.kind(), Some(SubjectKind::Person));
    assert_eq!(subject.ext_profile, "Driver");
    assert!(claims.is_access_code_subject());
}

#[tokio::test]
async fn ordinary_token_has_no_access_subject_claims() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let token = key.sign(&access_claims());

    let claims = verify_bearer(&verifier, &token)
        .await
        .expect("valid token")
        .claims;
    assert_eq!(claims.access_subject, None);
    assert!(!claims.is_access_code_subject());
}

/// A `subject_kind` this SDK does not know is not invented into one it does.
#[tokio::test]
async fn unknown_subject_kind_is_not_mapped() {
    let key = TestKey::a();
    let server = jwks_server(jwks(&[key.public_jwk()])).await;
    let verifier = verifier_for(&server);
    let mut claims_json = access_subject_claims();
    claims_json["subject_kind"] = serde_json::json!("robot");

    let claims = verify_bearer(&verifier, &key.sign(&claims_json))
        .await
        .expect("valid token")
        .claims;

    let subject = claims.access_subject.as_ref().expect("access subject");
    assert_eq!(subject.kind(), None);
    assert_eq!(subject.ext_sub, "driver:42");
}
