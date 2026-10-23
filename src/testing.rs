//! Test helpers for a product's own `tests/` (feature `testing`, as a dev-dependency only):
//!
//! - [`assert_router_covers_manifest`]: every permission of `permissions.yaml` guards a route;
//! - [`assert_no_unrouted_registrations`]: no route is registered outside the
//!   [`PermissionRouter`](crate::actix::PermissionRouter) (a raw actix registration would be
//!   refused at runtime anyway, `403 permission_unmapped`; this catches it before deploy);
//! - [`FakeVerifier`] and [`signed_test_token`]: tokens a test signs itself and a verifier that
//!   needs no LoginFlow server, with the same header, claims and DPoP checks as
//!   [`TokenVerifier`](crate::TokenVerifier).
//!
//! The assertions panic, like `assert!`: they are meant for `#[test]` functions.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};

use crate::actix::BuiltRouter;
use crate::authorization::manifest::PermissionManifest;
use crate::authorization::replay::InMemoryJtiReplayCache;
use crate::authorization::verifier::{
    AccessVerifier, PresentedToken, VerifiedAccess, VerifyError, VerifyFuture, check_binding,
    token_failure,
};
use crate::client::{access_token_kid, decode_access_claims};
use crate::dpop::now_unix;
use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::{ACCESS_TOKEN_JWT_TYP, AccessClaims, TokenPermissions};

/// `iss` of the tokens [`FakeVerifier`] signs and accepts.
pub const FAKE_ISSUER: &str = "https://loginflow.test";

/// `kid` of the [`FakeVerifier`] key.
pub const FAKE_KID: &str = "loginflow-test-key";

/// Code that registers an actix route by itself, bypassing the permission router.
const RAW_REGISTRATIONS: &[&str] = &[
    "#[get(",
    "#[post(",
    "#[put(",
    "#[patch(",
    "#[delete(",
    "#[head(",
    "#[options(",
    "#[trace(",
    "#[connect(",
    "#[route(",
    "#[routes]",
    "#[actix_web::get(",
    "#[actix_web::post(",
    "#[actix_web::put(",
    "#[actix_web::patch(",
    "#[actix_web::delete(",
    "#[actix_web::head(",
    "#[actix_web::route(",
    "#[actix_web::routes]",
    "web::resource(",
    "web::scope(",
    "web::route(",
    "web::method(",
    "web::get()",
    "web::post()",
    "web::put()",
    "web::patch()",
    "web::delete()",
    "web::head()",
    "Resource::new(",
    "Scope::new(",
    ".route(\"",
];

/// Panics unless every permission of `manifest` guards at least one route of `router`. A
/// permission no route checks is one a role can grant without effect — or a route that was
/// meant to check it and does not.
pub fn assert_router_covers_manifest(router: &BuiltRouter, manifest: &PermissionManifest) {
    let routed = router.routed_permissions();
    let unrouted: Vec<String> = manifest
        .entries()
        .into_iter()
        .map(|entry| entry.key)
        .filter(|key| !routed.contains(key.as_str()))
        .collect();
    assert!(
        unrouted.is_empty(),
        "permissions of the manifest no route requires: {unrouted:?}"
    );
}

/// Panics when a Rust file under `src_root` registers an actix route outside the
/// `PermissionRouter` (`#[get(...)]` and the other route macros, `web::resource`, `web::scope`,
/// `web::get()`..., `App::route("...")`), listing every `file:line`.
pub fn assert_no_unrouted_registrations(src_root: &Path) {
    let mut files = Vec::new();
    collect_rust_files(src_root, &mut files);
    let mut found = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let next = lines
                .get(index + 1)
                .map(|l| l.trim_start())
                .unwrap_or_default();
            let raw_route_split = code.ends_with(".route(") && next.starts_with('"');
            if raw_route_split || RAW_REGISTRATIONS.iter().any(|raw| code.contains(raw)) {
                found.push(format!("{}:{}: {}", file.display(), index + 1, code));
            }
        }
    }
    assert!(
        found.is_empty(),
        "routes registered outside the PermissionRouter:\n{}",
        found.join("\n")
    );
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

/// A verifier for tests: accepts the tokens [`signed_test_token`] signs with its own throwaway
/// key, with every check of [`TokenVerifier`](crate::TokenVerifier) except the JWKS download and
/// introspection — an overage token is refused with `503`, as when introspection is down.
pub struct FakeVerifier {
    audience: String,
    encoding: EncodingKey,
    decoding: DecodingKey,
    replay: InMemoryJtiReplayCache,
}

impl FakeVerifier {
    /// A verifier for the API whose audience is `audience`, with a fresh P-256 key.
    ///
    /// # Errors
    /// [`LoginFlowError::Config`] when the key cannot be generated.
    pub fn new(audience: impl Into<String>) -> LoginFlowResult<Self> {
        let failure = |what: &str| LoginFlowError::Config(format!("test signing key: {what}"));
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map_err(|_| failure("generation failed"))?;
        let pkcs8 = pair
            .to_pkcs8v1()
            .map_err(|_| failure("PKCS#8 export failed"))?;
        let encoding = EncodingKey::from_ec_der(pkcs8.as_ref());
        let jwk = Jwk::from_encoding_key(&encoding, Algorithm::ES256)
            .map_err(|e| failure(&e.to_string()))?;
        let AlgorithmParameters::EllipticCurve(params) = jwk.algorithm else {
            return Err(failure("not an EC key"));
        };
        let decoding = DecodingKey::from_ec_components(&params.x, &params.y)
            .map_err(|e| failure(&e.to_string()))?;
        Ok(Self {
            audience: audience.into(),
            encoding,
            decoding,
            replay: InMemoryJtiReplayCache::new(),
        })
    }

    /// The audience this verifier accepts.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Valid claims for this verifier's API: `sub` in `org_id` (when `Some`) with `permissions`
    /// listed, expiring in 10 minutes. Change any field before signing.
    pub fn claims(&self, sub: &str, org_id: Option<&str>, permissions: &[&str]) -> AccessClaims {
        let now = now_unix();
        AccessClaims {
            jti: format!("test-{sub}-{now}"),
            iss: FAKE_ISSUER.to_string(),
            sub: sub.to_string(),
            aud: self.audience.clone(),
            exp: now + 600,
            iat: now,
            client_id: "test-client".to_string(),
            scope: "openid".to_string(),
            sid: Some("test-session".to_string()),
            auth_time: now,
            amr: vec!["pwd".to_string()],
            acr: None,
            company_id: "CP-TEST".to_string(),
            app: "APP-TEST".to_string(),
            org_id: org_id.map(str::to_string),
            org_ext: None,
            permissions: TokenPermissions::Listed(
                permissions
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<BTreeSet<_>>(),
            ),
            cnf: None,
            auth_cid: None,
            access_subject: None,
        }
    }
}

impl AccessVerifier for FakeVerifier {
    fn verify<'a>(&'a self, presented: PresentedToken<'a>) -> VerifyFuture<'a> {
        Box::pin(async move {
            let token = presented.authorization.token.as_str();
            let kid = access_token_kid(token).map_err(token_failure)?;
            if kid != FAKE_KID {
                return Err(VerifyError::InvalidToken(format!("unknown kid {kid}")));
            }
            let claims = decode_access_claims(token, &self.decoding, FAKE_ISSUER, &self.audience)
                .map_err(token_failure)?;
            let dpop_jkt = check_binding(&claims, &presented, None, &self.replay)?;
            let permissions = match &claims.permissions {
                TokenPermissions::Listed(listed) => listed.clone(),
                TokenPermissions::Overage => {
                    return Err(VerifyError::Unavailable(
                        "FakeVerifier has no introspection".to_string(),
                    ));
                }
            };
            Ok(VerifiedAccess {
                claims,
                permissions,
                dpop_jkt,
            })
        })
    }
}

/// `claims` as an access token (`typ: at+jwt`, ES256) signed by `verifier`'s key.
///
/// # Errors
/// [`LoginFlowError::Config`] when the token cannot be signed.
pub fn signed_test_token(
    verifier: &FakeVerifier,
    claims: &AccessClaims,
) -> LoginFlowResult<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(FAKE_KID.to_string());
    header.typ = Some(ACCESS_TOKEN_JWT_TYP.to_string());
    encode(&header, claims, &verifier.encoding)
        .map_err(|e| LoginFlowError::Config(format!("cannot sign the test token: {e}")))
}
