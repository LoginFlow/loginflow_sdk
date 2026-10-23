//! `AccessClaims` helpers a resource server needs from a verified access token: the RFC 8176
//! `acr` helpers, the RFC 9470 step-up gate, and the shape of the permission claims.

use std::collections::BTreeSet;

use loginflow_sdk::LoginFlowError;
use loginflow_sdk::models::{
    ACR_MULTI_FACTOR, ACR_PHISHING_RESISTANT, ACR_SINGLE_FACTOR, AccessClaims, TokenPermissions,
};
use serde_json::json;

fn claims(acr: Option<&str>, auth_time: i64) -> AccessClaims {
    AccessClaims {
        jti: "jti-1".to_string(),
        iss: "https://api.loginflow.test".to_string(),
        sub: "company-user-1".to_string(),
        aud: "app-1".to_string(),
        exp: now() + 900,
        iat: now(),
        client_id: "client-1".to_string(),
        scope: "openid".to_string(),
        sid: Some("sid-1".to_string()),
        auth_time,
        amr: vec![],
        acr: acr.map(str::to_string),
        company_id: "company-1".to_string(),
        app: "APP-1".to_string(),
        org_id: Some("org-1".to_string()),
        org_ext: None,
        permissions: TokenPermissions::Listed(BTreeSet::new()),
        cnf: None,
        auth_cid: None,
        access_subject: None,
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64
}

#[test]
fn phishing_resistant_acr_is_recognized_and_counts_as_mfa() {
    let c = claims(Some(ACR_PHISHING_RESISTANT), now());
    assert!(c.is_phishing_resistant());
    assert!(c.has_mfa());
}

#[test]
fn mfa_acr_counts_as_mfa_but_is_not_phishing_resistant() {
    let c = claims(Some(ACR_MULTI_FACTOR), now());
    assert!(!c.is_phishing_resistant());
    assert!(c.has_mfa());
}

#[test]
fn single_factor_acr_is_neither_phishing_resistant_nor_mfa() {
    let c = claims(Some(ACR_SINGLE_FACTOR), now());
    assert!(!c.is_phishing_resistant());
    assert!(!c.has_mfa());
}

#[test]
fn absent_acr_is_neither_phishing_resistant_nor_mfa() {
    let c = claims(None, now());
    assert!(!c.is_phishing_resistant());
    assert!(!c.has_mfa());
}

#[test]
fn recent_auth_within_the_window_passes() {
    let c = claims(Some(ACR_SINGLE_FACTOR), now() - 60);
    assert!(c.require_recent_auth(300).is_ok());
}

/// RED→GREEN: before `require_recent_auth` existed, there was no way to tell a stale
/// authentication apart from a fresh one without hand-rolling the `auth_time` subtraction. The
/// contrafactual: an `auth_time` 600 s in the past must be rejected when `max_age` is 300 s —
/// flipping either side (accepting it, or comparing with the wrong sign) makes this fail.
#[test]
fn stale_auth_time_past_max_age_is_rejected_with_the_rfc9470_challenge() {
    let c = claims(Some(ACR_SINGLE_FACTOR), now() - 600);
    let err = c.require_recent_auth(300).expect_err("must be stale");
    match err {
        LoginFlowError::InsufficientUserAuthentication { max_age_secs } => {
            assert_eq!(max_age_secs, Some(300));
        }
        other => panic!("expected InsufficientUserAuthentication, got {other:?}"),
    }
}

#[test]
fn auth_age_secs_is_the_raw_difference_from_now() {
    let c = claims(Some(ACR_SINGLE_FACTOR), now() - 42);
    let age = c.auth_age_secs();
    assert!((40..=44).contains(&age), "age was {age}");
}

fn wire_claims() -> serde_json::Value {
    json!({
        "jti": "jti-1", "iss": "https://api.loginflow.test", "sub": "CU-1",
        "aud": "https://drivers.api.test", "exp": now() + 600, "iat": now(),
        "client_id": "console", "scope": "openid", "company_id": "CP-1", "app": "APP-1",
        "org_id": "org-1", "org_ext": "client-7",
    })
}

/// TEST_CHARTER
/// Requirement: the two permission claims fold into one `TokenPermissions`: `permissions` →
/// `Listed`, `permissions_overage: true` → `Overage`, neither → `Listed(empty)`; both at once is
/// a malformed token, refused.
/// Oracle: the deserialized value (or the error) of a claims JSON.
/// Risk edge: a token flagged as overage that also lists a (stale or forged) set must never be
/// trusted with that set.
/// Layer: unit (serde shape of the wire contract).
/// Counterfactual: accepting `(Some(list), true)` as `Listed(list)` makes the last assertion fail.
#[test]
fn permission_claims_fold_into_token_permissions() {
    let mut listed = wire_claims();
    listed["permissions"] = json!(["app.drivers.list", "app.drivers.list", "app.fleet.read"]);
    let claims: AccessClaims = serde_json::from_value(listed).expect("listed");
    assert_eq!(
        claims.permissions,
        TokenPermissions::Listed(BTreeSet::from([
            "app.drivers.list".to_string(),
            "app.fleet.read".to_string()
        ]))
    );
    assert_eq!(claims.org_ext.as_deref(), Some("client-7"));

    let mut overage = wire_claims();
    overage["permissions_overage"] = json!(true);
    let claims: AccessClaims = serde_json::from_value(overage).expect("overage");
    assert_eq!(claims.permissions, TokenPermissions::Overage);

    let claims: AccessClaims = serde_json::from_value(wire_claims()).expect("none");
    assert_eq!(
        claims.permissions,
        TokenPermissions::Listed(BTreeSet::new())
    );

    let mut both = wire_claims();
    both["permissions"] = json!(["app.drivers.list"]);
    both["permissions_overage"] = json!(true);
    assert!(serde_json::from_value::<AccessClaims>(both).is_err());
}

/// The application travels as `app` (the audience is the API): a token without it is refused,
/// and a legacy `role` claim, should a server still send one, grants nothing — it is not read.
#[test]
fn app_is_required_and_a_role_claim_is_not_read() {
    let mut without_app = wire_claims();
    without_app.as_object_mut().expect("object").remove("app");
    assert!(serde_json::from_value::<AccessClaims>(without_app).is_err());

    let mut with_role = wire_claims();
    with_role["role"] = json!("master");
    let claims: AccessClaims = serde_json::from_value(with_role).expect("parses");
    assert_eq!(
        claims.permissions,
        TokenPermissions::Listed(BTreeSet::new())
    );
    let reserialized = serde_json::to_value(&claims).expect("serialize");
    assert!(reserialized.get("role").is_none());
}
