//! RFC 9449 DPoP proof verification for a resource server: `dpop::verify_proof_matches_cnf`
//! must accept a proof whose embedded key matches the access token's `cnf.jkt`, and reject one
//! whose key does not — the actual bug this exists to prevent (any valid DPoP key can forge *a*
//! proof; only the token's own key may present *this* token).

mod common;

use common::{TestKey, build_dpop_proof, jwk_thumbprint, now};
use loginflow_sdk::dpop::{DpopError, access_token_hash, verify_proof_matches_cnf};

fn build_proof(key: &TestKey, htm: &str, htu: &str, jti: &str, ath: Option<&str>) -> String {
    build_dpop_proof(key, htm, htu, jti, ath, now())
}

#[test]
fn a_proof_matching_the_tokens_cnf_jkt_verifies_and_the_jkt_is_the_real_thumbprint() {
    let key = TestKey::a();
    let access_token = "the-access-token";
    let ath = access_token_hash(access_token);
    let proof = build_proof(
        &key,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        "jti-1",
        Some(&ath),
    );

    let cnf_jkt = jwk_thumbprint(&key);
    let verified = verify_proof_matches_cnf(
        &proof,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        access_token,
        &cnf_jkt,
    )
    .expect("a proof from the token's own key must verify");

    assert_eq!(verified.jkt, cnf_jkt);
}

#[test]
fn a_proof_from_a_different_key_than_the_tokens_cnf_jkt_is_rejected() {
    // Counterfactual for the test above: same request, same access token, a VALID DPoP
    // proof — just signed by a different key than the one `cnf.jkt` names. This is the one
    // real-world attack `verify_proof_matches_cnf` exists to stop.
    let signer = TestKey::b();
    let access_token = "the-access-token";
    let ath = access_token_hash(access_token);
    let proof = build_proof(
        &signer,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        "jti-2",
        Some(&ath),
    );

    let cnf_jkt = jwk_thumbprint(&TestKey::a());
    let result = verify_proof_matches_cnf(
        &proof,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        access_token,
        &cnf_jkt,
    );

    assert!(
        result.is_err(),
        "a proof signed by the wrong key must be rejected, got {result:?}"
    );
}

#[test]
fn a_proof_with_the_wrong_ath_is_rejected() {
    let key = TestKey::a();
    let proof = build_proof(
        &key,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        "jti-3",
        Some("wrong-ath"),
    );

    let cnf_jkt = jwk_thumbprint(&key);
    let result = verify_proof_matches_cnf(
        &proof,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        "the-access-token",
        &cnf_jkt,
    );

    assert!(result.is_err(), "got {result:?}");
}

#[test]
fn a_proof_for_a_different_htu_is_rejected() {
    let key = TestKey::a();
    let access_token = "the-access-token";
    let ath = access_token_hash(access_token);
    let proof = build_proof(
        &key,
        "POST",
        "https://api.loginflow.dev/oauth2/token",
        "jti-4",
        Some(&ath),
    );

    let cnf_jkt = jwk_thumbprint(&key);
    // Same proof, but checked against a different URL than the one it was minted for.
    let result = verify_proof_matches_cnf(
        &proof,
        "POST",
        "https://api.loginflow.dev/oauth2/device-logout",
        access_token,
        &cnf_jkt,
    );

    assert!(result.is_err(), "got {result:?}");
}

#[test]
fn a_proof_issued_outside_the_freshness_window_is_rejected_as_stale() {
    let key = TestKey::a();
    let access_token = "the-access-token";
    let ath = access_token_hash(access_token);
    let cnf_jkt = jwk_thumbprint(&key);
    let htu = "https://api.loginflow.dev/oauth2/token";

    for iat in [now() - 120, now() + 120] {
        let proof = build_dpop_proof(&key, "POST", htu, "jti-stale", Some(&ath), iat);
        let result = verify_proof_matches_cnf(&proof, "POST", htu, access_token, &cnf_jkt);
        assert!(
            matches!(result, Err(DpopError::Stale)),
            "a proof with iat {iat} must be stale, got {result:?}"
        );
    }
}
