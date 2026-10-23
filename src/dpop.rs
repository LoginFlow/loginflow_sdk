//! RFC 9449 (DPoP) proof verification for a Rust backend acting as a resource server: checks a
//! presented proof against the `cnf.jkt` an access token carries ([`crate::models::CnfClaim`]).
//! Pure JOSE: single use of a proof's `jti` is [`crate::TokenVerifier`]'s job, through a
//! [`crate::JtiReplayCache`].

use aws_lc_rs::digest::{self, SHA256};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 9449 §4.2 payload. `ath`/`nonce` are present only when the request calls for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopClaims {
    pub htm: String,
    pub htu: String,
    pub iat: i64,
    pub jti: String,
    #[serde(default)]
    pub ath: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    #[error("malformed DPoP proof")]
    Malformed,
    #[error("the DPoP proof's signature does not verify")]
    Signature,
    #[error("the DPoP proof's htm/htu does not match this request")]
    MethodOrUrlMismatch,
    #[error("the DPoP proof's iat is outside the allowed freshness window")]
    Stale,
    #[error("the DPoP proof does not bind the presented access token (ath mismatch)")]
    AccessTokenMismatch,
    #[error("the DPoP proof's key does not match the token's cnf.jkt")]
    KeyMismatch,
}

/// How much clock skew/network latency a proof's `iat` may have, either direction.
pub const MAX_PROOF_AGE_SECS: i64 = 60;

/// A verified proof: its claims plus `jkt`, the RFC 7638 thumbprint of the embedded key — this is
/// what [`verify_proof_matches_cnf`] compares against a token's `cnf.jkt`.
#[derive(Debug, Clone)]
pub struct VerifiedDpopProof {
    pub claims: DpopClaims,
    pub jkt: String,
}

/// `BASE64URL(SHA256(ASCII(access_token)))` — RFC 9449 §4.2's `ath` claim.
pub fn access_token_hash(access_token: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, access_token.as_bytes()).as_ref())
}

/// Strips query/fragment, matching RFC 9449 §4.3's `htu` requirement — the proof binds to the
/// request's path, not its query string.
pub fn normalize_htu(url: &str) -> String {
    url.split(['?', '#']).next().unwrap_or(url).to_string()
}

/// Verifies a DPoP proof's structure, signature, `htm`/`htu`, freshness and (when
/// `access_token` is `Some`) `ath` — everything RFC 9449 §4.3 needs except replay (`jti`
/// single use, which [`crate::TokenVerifier`] enforces) and a server-issued nonce (not every
/// deployment requires one; a caller that does checks the proof's own `nonce` claim against
/// whatever it handed out).
pub fn verify_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
) -> Result<VerifiedDpopProof, DpopError> {
    let mut parts = proof.split('.');
    let (Some(header_b64), Some(_payload_b64), Some(_sig_b64)) =
        (parts.next(), parts.next(), parts.next())
    else {
        return Err(DpopError::Malformed);
    };
    if parts.next().is_some() {
        return Err(DpopError::Malformed);
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| DpopError::Malformed)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| DpopError::Malformed)?;
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(DpopError::Malformed);
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(DpopError::Malformed);
    }
    // RFC 9449 §4.2: the embedded key MUST be ES256/P-256 for a DPoP proof.
    let jwk = header.get("jwk").ok_or(DpopError::Malformed)?;
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err(DpopError::Malformed);
    }
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::Malformed)?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::Malformed)?;
    let decoding_key = DecodingKey::from_ec_components(x, y).map_err(|_| DpopError::Malformed)?;

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims::<&str>(&[]);
    let claims = decode::<DpopClaims>(proof, &decoding_key, &validation)
        .map(|data| data.claims)
        .map_err(|_| DpopError::Signature)?;

    if claims.htm != htm || claims.htu != normalize_htu(htu) {
        return Err(DpopError::MethodOrUrlMismatch);
    }
    let now = now_unix();
    if (now - claims.iat).abs() > MAX_PROOF_AGE_SECS {
        return Err(DpopError::Stale);
    }
    if let Some(token) = access_token {
        let expected_ath = access_token_hash(token);
        if claims.ath.as_deref() != Some(expected_ath.as_str()) {
            return Err(DpopError::AccessTokenMismatch);
        }
    }

    Ok(VerifiedDpopProof {
        jkt: thumbprint(x, y),
        claims,
    })
}

/// [`verify_proof`], plus the one check that actually matters for a resource server holding an
/// access token's `cnf.jkt`: the proof's own key must BE that key, not merely be a valid DPoP
/// proof on its own. Skipping this and only calling [`verify_proof`] is the classic
/// DPoP-implementation bug — any valid DPoP key can forge *a* proof; only the token's own key
/// may legitimately present *this* token (RFC 9449 §6/§7.1).
pub fn verify_proof_matches_cnf(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: &str,
    cnf_jkt: &str,
) -> Result<VerifiedDpopProof, DpopError> {
    let verified = verify_proof(proof, htm, htu, Some(access_token))?;
    if verified.jkt != cnf_jkt {
        return Err(DpopError::KeyMismatch);
    }
    Ok(verified)
}

/// RFC 7638 thumbprint: SHA-256 over the canonical JSON of the REQUIRED EC members, in
/// lexicographic key order — `crv`, `kty`, `x`, `y`.
fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(digest::digest(&SHA256, canonical.as_bytes()).as_ref())
}

/// Current Unix time in seconds (0 if the clock is before the epoch).
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
