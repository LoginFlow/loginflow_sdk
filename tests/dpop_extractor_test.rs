//! RFC 9449 §7.1 at the Actix extractor: a DPoP-bound access token (`cnf.jkt`) is only accepted
//! under the `DPoP` scheme with a proof signed by the token's own key, and a plain token only
//! under `Bearer`.

#![cfg(feature = "actix")]

mod common;

use actix_web::dev::Payload;
use actix_web::http::{Method, StatusCode};
use actix_web::test::TestRequest;
use actix_web::{FromRequest, HttpRequest, web};
use common::{
    FakeServer, TestKey, access_claims, build_dpop_proof, claims_with, client_for, config_for,
    jwk_thumbprint, jwks, jwks_server, now,
};
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::actix::AuthMiddleware;
use loginflow_sdk::dpop::access_token_hash;
use serde_json::json;

const HOST: &str = "rs.example.test";
const PATH: &str = "/v1/orders";

/// The `htu` the extractor derives from the request when no public base URL is configured.
fn request_htu() -> String {
    format!("http://{HOST}{PATH}")
}

/// Access token signed by the JWKS key `a`, bound (`cnf.jkt`) to the DPoP key `b`.
fn bound_token() -> String {
    TestKey::a().sign(&claims_with(
        "cnf",
        json!({ "jkt": jwk_thumbprint(&TestKey::b()) }),
    ))
}

fn plain_token() -> String {
    TestKey::a().sign(&access_claims())
}

/// Valid proof for `POST {htu}` binding `token`, signed by `key`.
fn proof(key: &TestKey, htu: &str, token: &str) -> String {
    build_dpop_proof(
        key,
        "POST",
        htu,
        "proof-jti-1",
        Some(&access_token_hash(token)),
        now(),
    )
}

async fn server() -> FakeServer {
    jwks_server(jwks(&[TestKey::a().public_jwk()])).await
}

fn request(client: LoginFlowClient, authorization: &str, dpop: Option<&str>) -> HttpRequest {
    let mut builder = TestRequest::default()
        .method(Method::POST)
        .uri(PATH)
        .insert_header(("Host", HOST))
        .insert_header(("Authorization", authorization))
        .app_data(web::Data::new(client));
    if let Some(dpop) = dpop {
        builder = builder.insert_header(("DPoP", dpop));
    }
    builder.to_http_request()
}

async fn status(req: &HttpRequest) -> StatusCode {
    match AuthMiddleware::from_request(req, &mut Payload::None).await {
        Ok(_) => StatusCode::OK,
        Err(err) => err.as_response_error().status_code(),
    }
}

/// TEST_CHARTER
/// Requirement: RFC 9449 §7.1 — a DPoP-bound token presented with the `Bearer` scheme is
/// rejected, even when a valid proof from the token's own key rides along.
/// Oracle: the HTTP status `AuthMiddleware` resolves to (401).
/// Risk edge: a stolen DPoP-bound token replayed as a plain bearer token by someone without the
/// private key.
/// Layer: integration — the real actix extractor, real ES256 token and proof, in-process JWKS.
/// Counterfactual: dropping the `cnf` check in `verify_request` accepts the request (200).
#[actix_web::test]
async fn bound_token_presented_as_bearer_is_unauthorized() {
    let server = server().await;
    let token = bound_token();
    let req = request(
        client_for(&server),
        &format!("Bearer {token}"),
        Some(&proof(&TestKey::b(), &request_htu(), &token)),
    );

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}

/// TEST_CHARTER
/// Requirement: a DPoP-bound token under the `DPoP` scheme with a valid proof — signed by the
/// key `cnf.jkt` names, for this request's method and URL, binding this token — is accepted.
/// Oracle: `AuthMiddleware` resolves to `Ok`, exposing the token.
/// Risk edge: the scheme must be parsed case-insensitively (`DPoP`, `dpop`).
/// Layer: integration — real actix extractor, real token and proof.
/// Counterfactual: an extractor that only accepts `Bearer` rejects both requests.
#[actix_web::test]
async fn bound_token_with_dpop_scheme_and_matching_proof_is_accepted() {
    let server = server().await;
    let token = bound_token();
    for scheme in ["DPoP", "dpop"] {
        let req = request(
            client_for(&server),
            &format!("{scheme} {token}"),
            Some(&proof(&TestKey::b(), &request_htu(), &token)),
        );

        let auth = AuthMiddleware::from_request(&req, &mut Payload::None)
            .await
            .unwrap_or_else(|err| panic!("{scheme}: rejected: {err}"));
        assert_eq!(auth.token(), token);
        // The verified proof is handed to the caller for its own `jti` replay check.
        assert_eq!(
            auth.dpop_proof().map(|proof| proof.claims.jti.as_str()),
            Some("proof-jti-1")
        );
        assert_eq!(
            auth.dpop_proof().map(|proof| proof.jkt.clone()),
            Some(jwk_thumbprint(&TestKey::b()))
        );
    }
}

/// TEST_CHARTER
/// Requirement: with `LoginFlowConfig::resource_base_url` set, the expected `htu` is that public
/// base URL + the request path, not the connection's scheme/host (behind a reverse proxy the
/// connection sees an internal host).
/// Oracle: `AuthMiddleware` accepts the proof minted for the public URL and rejects the one
/// minted for the connection-derived URL.
/// Risk edge: deriving `htu` from the connection behind a proxy rejects every legitimate proof.
/// Layer: integration — real extractor and config.
/// Counterfactual: ignoring `resource_base_url` flips both outcomes.
#[actix_web::test]
async fn configured_resource_base_url_defines_the_expected_htu() {
    let server = server().await;
    let mut config = config_for(&server);
    config.resource_base_url = Some("https://public.example.test/".into());
    let client = LoginFlowClient::new(config).expect("client");
    let token = bound_token();

    let public = request(
        client.clone(),
        &format!("DPoP {token}"),
        Some(&proof(
            &TestKey::b(),
            &format!("https://public.example.test{PATH}"),
            &token,
        )),
    );
    assert_eq!(status(&public).await, StatusCode::OK);

    let connection_derived = request(
        client,
        &format!("DPoP {token}"),
        Some(&proof(&TestKey::b(), &request_htu(), &token)),
    );
    assert_eq!(status(&connection_derived).await, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn plain_token_exposes_no_dpop_proof() {
    let server = server().await;
    let req = request(
        client_for(&server),
        &format!("Bearer {}", plain_token()),
        None,
    );

    let auth = AuthMiddleware::from_request(&req, &mut Payload::None)
        .await
        .expect("bearer token accepted");
    assert!(auth.dpop_proof().is_none());
}

#[actix_web::test]
async fn bound_token_with_dpop_scheme_but_no_proof_is_unauthorized() {
    let server = server().await;
    let token = bound_token();
    let req = request(client_for(&server), &format!("DPoP {token}"), None);

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}

/// Counterfactual for the acceptance test: same request, a valid proof signed by a key other
/// than the one `cnf.jkt` names.
#[actix_web::test]
async fn bound_token_with_a_proof_from_another_key_is_unauthorized() {
    let server = server().await;
    let token = bound_token();
    let req = request(
        client_for(&server),
        &format!("DPoP {token}"),
        Some(&proof(&TestKey::a(), &request_htu(), &token)),
    );

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn bound_token_with_a_proof_for_another_url_is_unauthorized() {
    let server = server().await;
    let token = bound_token();
    let req = request(
        client_for(&server),
        &format!("DPoP {token}"),
        Some(&proof(
            &TestKey::b(),
            &format!("http://{HOST}/v1/other"),
            &token,
        )),
    );

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn bound_token_with_two_dpop_headers_is_unauthorized() {
    let server = server().await;
    let token = bound_token();
    let valid = proof(&TestKey::b(), &request_htu(), &token);
    let req = TestRequest::default()
        .method(Method::POST)
        .uri(PATH)
        .insert_header(("Host", HOST))
        .insert_header(("Authorization", format!("DPoP {token}")))
        .append_header(("DPoP", valid.clone()))
        .append_header(("DPoP", valid))
        .app_data(web::Data::new(client_for(&server)))
        .to_http_request();

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn plain_token_with_bearer_scheme_is_accepted() {
    let server = server().await;
    for scheme in ["Bearer", "bearer"] {
        let req = request(
            client_for(&server),
            &format!("{scheme} {}", plain_token()),
            None,
        );

        assert_eq!(status(&req).await, StatusCode::OK, "{scheme}");
    }
}

/// A token that is not DPoP-bound has no `cnf.jkt` to match a proof against: presenting it under
/// the `DPoP` scheme is rejected, proof or not.
#[actix_web::test]
async fn plain_token_with_dpop_scheme_is_unauthorized() {
    let server = server().await;
    let token = plain_token();
    let req = request(
        client_for(&server),
        &format!("DPoP {token}"),
        Some(&proof(&TestKey::b(), &request_htu(), &token)),
    );

    assert_eq!(status(&req).await, StatusCode::UNAUTHORIZED);
}
