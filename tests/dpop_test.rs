//! RFC 9449 DPoP proof verification for a resource server: `dpop::verify_proof_matches_cnf`
//! must accept a proof whose embedded key matches the access token's `cnf.jkt`, and reject one
//! whose key does not — the actual bug this exists to prevent (any valid DPoP key can forge *a*
//! proof; only the token's own key may present *this* token).

mod common;

use common::{TestKey, now};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, Header, encode};
use loginflow_sdk::dpop::{DpopError, access_token_hash, verify_proof_matches_cnf};
use serde_json::json;

fn build_proof(key: &TestKey, htm: &str, htu: &str, jti: &str, ath: Option<&str>) -> String {
    build_proof_at(key, htm, htu, jti, ath, now())
}

fn build_proof_at(
    key: &TestKey,
    htm: &str,
    htu: &str,
    jti: &str,
    ath: Option<&str>,
    iat: i64,
) -> String {
    let jwk = Jwk::from_encoding_key(&key.encoding, Algorithm::ES256).expect("jwk");
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);
    let mut claims = json!({ "htm": htm, "htu": htu, "iat": iat, "jti": jti });
    if let Some(ath) = ath {
        claims["ath"] = json!(ath);
    }
    encode(&header, &claims, &key.encoding).expect("sign proof")
}

/// The proof's own key's thumbprint, computed the same way the real `cnf.jkt` would be, for a
/// test to assert against — built by letting `verify_proof_matches_cnf` succeed once with
/// `cnf_jkt` set to whatever it actually resolves to is circular, so this walks the proof
/// through the same RFC 7638 computation the server-side issuer uses, independently, so the
/// test does not just assert "it didn't error".
fn thumbprint_of(key: &TestKey) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = Jwk::from_encoding_key(&key.encoding, Algorithm::ES256).expect("jwk");
    let jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(params) = jwk.algorithm else {
        panic!("not an EC key")
    };
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        params.x, params.y
    );
    URL_SAFE_NO_PAD.encode(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes()).as_ref(),
    )
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

    let cnf_jkt = thumbprint_of(&key);
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

    let cnf_jkt = thumbprint_of(&TestKey::a());
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

    let cnf_jkt = thumbprint_of(&key);
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

    let cnf_jkt = thumbprint_of(&key);
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
    let cnf_jkt = thumbprint_of(&key);
    let htu = "https://api.loginflow.dev/oauth2/token";

    for iat in [now() - 120, now() + 120] {
        let proof = build_proof_at(&key, "POST", htu, "jti-stale", Some(&ath), iat);
        let result = verify_proof_matches_cnf(&proof, "POST", htu, access_token, &cnf_jkt);
        assert!(
            matches!(result, Err(DpopError::Stale)),
            "a proof with iat {iat} must be stale, got {result:?}"
        );
    }
}
