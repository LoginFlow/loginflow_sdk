//! `JwtClaims` helpers a resource server needs from a verified access token: the RFC 8176 `acr`
//! helpers, and the RFC 9470 step-up gate.

use loginflow_sdk::LoginFlowError;
use loginflow_sdk::models::{
    ACR_MULTI_FACTOR, ACR_PHISHING_RESISTANT, ACR_SINGLE_FACTOR, JwtClaims,
};

fn claims(acr: Option<&str>, auth_time: i64) -> JwtClaims {
    JwtClaims {
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
        application_id: "app-1".to_string(),
        role: "user".to_string(),
        cnf: None,
        auth_cid: None,
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
