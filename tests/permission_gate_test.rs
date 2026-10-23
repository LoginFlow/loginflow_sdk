//! The permission gate with the real `TokenVerifier`: signed ES256 tokens against an in-process
//! JWKS, `aud` per API, the organization and permission checks, DPoP (scheme matrix, `htm`/`htu`,
//! `cnf.jkt`, single-use `jti`) and overage permissions read through introspection, failing
//! closed with `503`.

#![cfg(feature = "actix")]

mod common;

use std::sync::Arc;

use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode};
use actix_web::test as actix_test;
use actix_web::{App, HttpResponse};
use common::{
    INTROSPECT_PATH, JWKS_PATH, ORG_ID, OTHER_API_AUDIENCE, Reply, TestKey, USER_ID, access_claims,
    build_dpop_proof, claims_with, config_for, jwk_thumbprint, jwks, manifest, now, verifier_with,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use loginflow_sdk::actix::{Authorized, BuiltRouter, PermissionRouter};
use loginflow_sdk::dpop::access_token_hash;
use loginflow_sdk::{LoginFlowClient, TokenVerifier};
use serde_json::{Value, json};

const HOST: &str = "rs.example.test";

async fn list_drivers(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "sub": auth.sub(),
        "org": auth.org_id(),
        "org_ext": auth.org_external_id(),
        "jkt": auth.dpop_jkt(),
        "permissions": auth.permissions(),
    }))
}

async fn create_driver(auth: Authorized) -> HttpResponse {
    HttpResponse::Created().json(json!({ "org": auth.org_id() }))
}

fn router() -> BuiltRouter {
    PermissionRouter::new(Arc::new(manifest()))
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            list_drivers,
        )
        .route(
            Method::POST,
            "/drivers",
            "rutafacil.drivers.create",
            create_driver,
        )
        .build()
        .expect("router")
}

/// Fake LoginFlow: the JWKS of key `a`, and `introspect` answering `/oauth2/introspect`.
async fn loginflow(
    introspect: impl Fn(&common::RecordedRequest) -> Reply + Send + Sync + 'static,
) -> common::FakeServer {
    let document = jwks(&[TestKey::a().public_jwk()]);
    common::FakeServer::start(move |req| match req.path() {
        JWKS_PATH => Reply::ok(document.clone()),
        INTROSPECT_PATH => introspect(req),
        _ => Reply::status(404, "{}"),
    })
    .await
}

struct Gate {
    server: common::FakeServer,
    verifier: Arc<TokenVerifier>,
}

impl Gate {
    async fn new() -> Self {
        Self::with_introspection(|_| Reply::status(500, "{}")).await
    }

    async fn with_introspection(
        introspect: impl Fn(&common::RecordedRequest) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let server = loginflow(introspect).await;
        let client = LoginFlowClient::new(config_for(&server)).expect("client");
        let verifier = Arc::new(verifier_with(client, &server));
        Self { server, verifier }
    }

    async fn with_client(client_for: impl FnOnce(&common::FakeServer) -> LoginFlowClient) -> Self {
        let server = loginflow(|_| Reply::status(500, "{}")).await;
        let client = client_for(&server);
        let verifier = Arc::new(verifier_with(client, &server));
        Self { server, verifier }
    }

    /// Send every request to ONE app (one verifier, one replay cache), in order.
    async fn send_all(&self, requests: Vec<actix_test::TestRequest>) -> Vec<(StatusCode, Value)> {
        let router = router();
        let app = actix_test::init_service(
            App::new()
                .wrap(router.gate(self.verifier.clone()))
                .configure(|cfg| router.configure(cfg)),
        )
        .await;
        let mut answers = Vec::new();
        for request in requests {
            let response: ServiceResponse = app
                .call(request.insert_header(("Host", HOST)).to_request())
                .await
                .expect("response")
                .map_into_boxed_body();
            let status = response.status();
            let body = actix_test::read_body(response).await;
            let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            answers.push((status, value));
        }
        answers
    }

    async fn send(&self, request: actix_test::TestRequest) -> (StatusCode, Value) {
        self.send_all(vec![request]).await.remove(0)
    }
}

fn get_drivers(authorization: &str) -> actix_test::TestRequest {
    actix_test::TestRequest::get()
        .uri("/drivers")
        .insert_header(("Authorization", authorization.to_string()))
}

fn bearer(claims: &Value) -> String {
    format!("Bearer {}", TestKey::a().sign(claims))
}

/// TEST_CHARTER
/// Requirement: a token for this API, with an organization and the route's permission, reaches
/// the handler, which reads the caller (sub, org, org_ext, permissions) from `Authorized`.
/// Oracle: `200` and the handler's JSON body built from `Authorized`.
/// Risk edge: the handler must get the org from the verified token, never from the request.
/// Layer: integration — actix app + gate + real `TokenVerifier` + in-process JWKS.
/// Counterfactual: a gate that does not insert `Authorized` answers `500` here.
#[actix_web::test]
async fn a_token_with_the_permission_reaches_the_handler_with_its_caller() {
    let gate = Gate::new().await;

    let (status, body) = gate.send(get_drivers(&bearer(&access_claims()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sub"], json!(USER_ID));
    assert_eq!(body["org"], json!(ORG_ID));
    assert_eq!(body["org_ext"], json!("client-7"));
    assert_eq!(body["permissions"], json!(["rutafacil.drivers.list"]));
    assert_eq!(body["jkt"], Value::Null);
}

/// TEST_CHARTER
/// Requirement: the route's permission must be in the token's permissions (`403
/// permission_denied`), and a token without an active organization grants nothing (`403
/// organization_required`) even if it lists the permission.
/// Oracle: status and body `error`.
/// Risk edge: OWASP API5 (function-level authorization) and a cross-organization token.
/// Layer: integration — real gate and verifier.
/// Counterfactual: skipping `require(permission)` lets the POST through with `201`; skipping the
/// org check serves the org-less token.
#[actix_web::test]
async fn the_route_permission_and_an_organization_are_required() {
    let gate = Gate::new().await;

    let create = actix_test::TestRequest::post()
        .uri("/drivers")
        .insert_header(("Authorization", bearer(&access_claims())));
    let (status, body) = gate.send(create).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("permission_denied"));
    assert!(
        !body.to_string().contains("rutafacil.drivers.create"),
        "the missing permission is not disclosed: {body}"
    );

    let mut no_org = access_claims();
    no_org.as_object_mut().expect("object").remove("org_id");
    let (status, body) = gate.send(get_drivers(&bearer(&no_org))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], json!("organization_required"));
}

/// TEST_CHARTER
/// Requirement: every token check refuses with the same fixed `401 invalid_token` body — a
/// token for another API of the application (`aud`), an algorithm outside the allow-list
/// (HS256), another issuer, an expired token, a non-access `typ`, no `Authorization`.
/// Oracle: status, body and `WWW-Authenticate` for each.
/// Risk edge: one API replaying another API's token; alg confusion; leaking why a token failed.
/// Layer: integration — real gate and verifier.
/// Counterfactual: validating `aud` against the application lets the other-API token through
/// (`200`).
#[actix_web::test]
async fn every_token_check_refuses_with_the_same_invalid_token_answer() {
    let gate = Gate::new().await;
    let mut hs256 = Header::new(Algorithm::HS256);
    hs256.kid = Some(TestKey::a().kid.clone());
    hs256.typ = Some("at+jwt".to_string());
    let hs256_token = encode(
        &hs256,
        &access_claims(),
        &EncodingKey::from_secret(b"secret"),
    )
    .expect("sign");

    let refused = [
        (
            "other API",
            bearer(&claims_with("aud", json!(OTHER_API_AUDIENCE))),
        ),
        ("HS256", format!("Bearer {hs256_token}")),
        (
            "issuer",
            bearer(&claims_with("iss", json!("https://evil.example"))),
        ),
        ("expired", bearer(&claims_with("exp", json!(now() - 120)))),
        (
            "typ",
            format!(
                "Bearer {}",
                TestKey::a().sign_with_typ(&access_claims(), Some("JWT"))
            ),
        ),
        (
            "scheme",
            format!("Basic {}", TestKey::a().sign(&access_claims())),
        ),
    ];
    for (case, authorization) in refused {
        let (status, body) = gate.send(get_drivers(&authorization)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            body,
            json!({ "error": "invalid_token", "error_type": "Authentication" }),
            "{case}"
        );
    }

    let (status, _) = gate
        .send(actix_test::TestRequest::get().uri("/drivers"))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no Authorization header");
}

/// TEST_CHARTER
/// Requirement: the gate accepts only tokens of the company this API is configured for
/// (`LOGINFLOW_COMPANY`). An application can belong to several companies
/// (`company_applications`) and its API audience is per application, so a token of another
/// company carries this API's `aud`, a valid signature and the route permission.
/// Oracle: status and body of the gate's answer.
/// Risk edge: cross-company access through a shared API audience (tenant isolation).
/// Layer: integration — real gate and verifier over an in-process JWKS server.
/// Counterfactual: removing the `company_id` comparison lets the other-company token reach the
/// handler (`200`).
#[actix_web::test]
async fn a_token_of_another_company_is_an_invalid_token() {
    let gate = Gate::new().await;

    let (status, body) = gate
        .send(get_drivers(&bearer(&claims_with(
            "company_id",
            json!("CP-ANOTHER-COMPANY"),
        ))))
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body,
        json!({ "error": "invalid_token", "error_type": "Authentication" })
    );
    let (status, _) = gate.send(get_drivers(&bearer(&access_claims()))).await;
    assert_eq!(status, StatusCode::OK, "own company");
}

// ---------------------------------------------------------------------------------------------
// DPoP
// ---------------------------------------------------------------------------------------------

fn htu() -> String {
    format!("http://{HOST}/drivers")
}

/// Access token signed by the JWKS key `a`, bound (`cnf.jkt`) to the DPoP key `b`.
fn bound_token() -> String {
    TestKey::a().sign(&claims_with(
        "cnf",
        json!({ "jkt": jwk_thumbprint(&TestKey::b()) }),
    ))
}

fn proof(key: &TestKey, htm: &str, htu: &str, jti: &str, token: &str) -> String {
    build_dpop_proof(key, htm, htu, jti, Some(&access_token_hash(token)), now())
}

fn dpop_get(token: &str, proof: Option<String>) -> actix_test::TestRequest {
    let request = get_drivers(&format!("DPoP {token}"));
    match proof {
        Some(proof) => request.insert_header(("DPoP", proof)),
        None => request,
    }
}

/// TEST_CHARTER
/// Requirement: a DPoP-bound token is accepted under the `DPoP` scheme with a proof for this
/// request (`htm`, `htu`, `ath`) signed by the token's key, ONCE: the same proof again is
/// refused (`jti` single use, RFC 9449 §11.1).
/// Oracle: `200` with the proved `jkt` for the first request, `401` for the replay, `200` for a
/// fresh proof.
/// Risk edge: a captured request (token + proof) replayed within the proof's freshness window.
/// Layer: integration — one app, one `InMemoryJtiReplayCache`, real proofs.
/// Counterfactual: not recording the `jti` serves the replay with `200`.
#[actix_web::test]
async fn a_dpop_proof_is_accepted_once() {
    let gate = Gate::new().await;
    let token = bound_token();
    let first = proof(&TestKey::b(), "GET", &htu(), "proof-1", &token);

    let answers = gate
        .send_all(vec![
            dpop_get(&token, Some(first.clone())),
            dpop_get(&token, Some(first)),
            dpop_get(
                &token,
                Some(proof(&TestKey::b(), "GET", &htu(), "proof-2", &token)),
            ),
        ])
        .await;

    assert_eq!(answers[0].0, StatusCode::OK, "{}", answers[0].1);
    assert_eq!(answers[0].1["jkt"], json!(jwk_thumbprint(&TestKey::b())));
    assert_eq!(answers[1].0, StatusCode::UNAUTHORIZED, "replayed proof");
    assert_eq!(answers[2].0, StatusCode::OK, "fresh proof");
}

/// RFC 9449 §7.1 and §4.3: the scheme must match the binding, and the proof must be the
/// token's key's, for this method and URL, alone in its header.
#[actix_web::test]
async fn a_dpop_binding_that_does_not_hold_is_refused() {
    let gate = Gate::new().await;
    let token = bound_token();
    let plain = TestKey::a().sign(&access_claims());
    let valid = || proof(&TestKey::b(), "GET", &htu(), "proof-x", &token);

    let cases = vec![
        (
            "bound token as Bearer",
            get_drivers(&format!("Bearer {token}")).insert_header(("DPoP", valid())),
        ),
        ("no proof", dpop_get(&token, None)),
        (
            "proof from another key",
            dpop_get(
                &token,
                Some(proof(&TestKey::a(), "GET", &htu(), "p-a", &token)),
            ),
        ),
        (
            "proof for another URL",
            dpop_get(
                &token,
                Some(proof(
                    &TestKey::b(),
                    "GET",
                    &format!("http://{HOST}/other"),
                    "p-u",
                    &token,
                )),
            ),
        ),
        (
            "proof for another method",
            dpop_get(
                &token,
                Some(proof(&TestKey::b(), "POST", &htu(), "p-m", &token)),
            ),
        ),
        (
            "two DPoP headers",
            get_drivers(&format!("DPoP {token}"))
                .append_header(("DPoP", valid()))
                .append_header(("DPoP", valid())),
        ),
        (
            "plain token under DPoP",
            dpop_get(
                &plain,
                Some(proof(&TestKey::b(), "GET", &htu(), "p-p", &plain)),
            ),
        ),
    ];
    for (case, request) in cases {
        let (status, _) = gate.send(request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}");
    }
}

/// Behind a reverse proxy the configured public base URL, not the connection, is the `htu`.
#[actix_web::test]
async fn the_configured_resource_base_url_defines_the_htu() {
    let gate = Gate::with_client(|server| {
        let mut config = config_for(server);
        config.resource_base_url = Some("https://public.example.test/".into());
        LoginFlowClient::new(config).expect("client")
    })
    .await;
    let token = bound_token();

    let answers = gate
        .send_all(vec![
            dpop_get(
                &token,
                Some(proof(
                    &TestKey::b(),
                    "GET",
                    "https://public.example.test/drivers",
                    "pub-1",
                    &token,
                )),
            ),
            dpop_get(
                &token,
                Some(proof(&TestKey::b(), "GET", &htu(), "conn-1", &token)),
            ),
        ])
        .await;

    assert_eq!(answers[0].0, StatusCode::OK, "public URL proof");
    assert_eq!(
        answers[1].0,
        StatusCode::UNAUTHORIZED,
        "connection URL proof"
    );
}

// ---------------------------------------------------------------------------------------------
// Overage
// ---------------------------------------------------------------------------------------------

fn overage_claims() -> Value {
    let mut claims = access_claims();
    let object = claims.as_object_mut().expect("object");
    object.remove("permissions");
    object.insert("permissions_overage".to_string(), json!(true));
    claims
}

/// TEST_CHARTER
/// Requirement: an overage token's permissions are read live from `/oauth2/introspect`,
/// authenticated as this API's key, and decide the route.
/// Oracle: `200` with the introspected permissions in `Authorized`; the introspection request's
/// `Authorization: Basic` and `token` form field.
/// Risk edge: an overage token treated as "no permissions" (denies everything) or as "all".
/// Layer: integration — real verifier against the in-process introspection endpoint.
/// Counterfactual: not calling introspection leaves the permission set empty (`403`).
#[actix_web::test]
async fn an_overage_token_is_decided_by_the_introspected_permissions() {
    let gate = Gate::with_introspection(|_| {
        Reply::ok(
            json!({
                "active": true,
                "org_id": ORG_ID,
                "permissions": ["rutafacil.drivers.list", "rutafacil.fleet.read"],
            })
            .to_string(),
        )
    })
    .await;

    let (status, body) = gate.send(get_drivers(&bearer(&overage_claims()))).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["permissions"],
        json!(["rutafacil.drivers.list", "rutafacil.fleet.read"])
    );
    let introspection = gate
        .server
        .requests()
        .into_iter()
        .find(|r| r.path() == INTROSPECT_PATH);
    let introspection = introspection.expect("introspection called");
    assert!(
        introspection
            .header("authorization")
            .is_some_and(|v| v.starts_with("Basic "))
    );
    assert!(
        introspection.body.starts_with("token="),
        "{}",
        introspection.body
    );
}

/// TEST_CHARTER
/// Requirement: when the live permissions of an overage token cannot be read — introspection
/// answers 5xx, answers without `permissions`, or is unreachable — the request is refused with
/// `503`, never let through; an inactive token, or one whose organization is no longer its
/// active one, is `401`.
/// Oracle: status and the fixed body.
/// Risk edge: failing open on an introspection outage.
/// Layer: integration — real verifier and introspection client.
/// Counterfactual: falling back to the (empty) token set answers `403`, not `503`; falling back
/// to "allow" answers `200`.
#[actix_web::test]
async fn an_overage_token_fails_closed_when_introspection_cannot_answer() {
    let cases: Vec<(&str, Reply, StatusCode)> = vec![
        ("5xx", Reply::status(500, "{}"), StatusCode::SERVICE_UNAVAILABLE),
        (
            "no permissions",
            Reply::ok(json!({ "active": true, "org_id": ORG_ID }).to_string()),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            "inactive",
            Reply::ok(json!({ "active": false }).to_string()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "other organization",
            Reply::ok(
                json!({ "active": true, "org_id": "org-other", "permissions": ["rutafacil.drivers.list"] })
                    .to_string(),
            ),
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (case, reply, expected) in cases {
        let gate = Gate::with_introspection(move |_| reply.clone()).await;
        let (status, body) = gate.send(get_drivers(&bearer(&overage_claims()))).await;
        assert_eq!(status, expected, "{case}: {body}");
        if expected == StatusCode::SERVICE_UNAVAILABLE {
            assert_eq!(
                body,
                json!({ "error": "authorization_unavailable", "error_type": "ServiceUnavailable" }),
                "{case}"
            );
        }
    }

    // Unreachable: the introspection endpoint points at a closed port.
    let server = loginflow(|_| Reply::status(500, "{}")).await;
    let client = LoginFlowClient::new(config_for(&server)).expect("client");
    let unreachable = loginflow_sdk::IntrospectionClient::new(
        reqwest::Client::new(),
        "http://127.0.0.1:9/oauth2/introspect",
        "drivers-api",
        "secret",
    );
    let verifier = Arc::new(TokenVerifier::new(
        client,
        Arc::new(loginflow_sdk::InMemoryJtiReplayCache::new()),
        unreachable,
    ));
    let gate = Gate { server, verifier };
    let (status, _) = gate.send(get_drivers(&bearer(&overage_claims()))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "unreachable");
}
