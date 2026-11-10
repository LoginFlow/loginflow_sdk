//! Machine access on the receiving API: a machine token (`client_credentials` for this API, no
//! `sid`, `sub` = `client_id`, no organization) is accepted only on routes declared for machines
//! and only with the route's permission; a person's token is refused on a machine-only route.

#![cfg(feature = "testing")]

mod common;

use std::sync::Arc;

use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode};
use actix_web::test as actix_test;
use actix_web::{App, HttpResponse};
use common::{
    API_AUDIENCE, APP_ID, COMPANY_ID, ISSUER, JWKS_PATH, Reply, TestKey, client_for, jwks,
    manifest, now, verifier_with,
};
use loginflow_sdk::actix::{Authorized, BuiltRouter, Caller, MachineAuthorized, PermissionRouter};
use loginflow_sdk::testing::{FakeVerifier, signed_test_token};
use loginflow_sdk::{AccessVerifier, TokenVerifier};
use serde_json::{Value, json};

const CALLER: &str = "payments-caller-1a2b3c4d";

async fn person_drivers(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "org": auth.org_id() }))
}

async fn machine_issue_code(auth: MachineAuthorized) -> HttpResponse {
    HttpResponse::Ok()
        .json(json!({ "client": auth.client_id(), "permissions": auth.permissions() }))
}

async fn fleet(caller: Caller) -> HttpResponse {
    let who = match &caller {
        Caller::Person(person) => json!({ "person": person.sub(), "org": person.org_id() }),
        Caller::Machine(machine) => json!({ "machine": machine.client_id() }),
    };
    HttpResponse::Ok().json(who)
}

fn router() -> BuiltRouter {
    PermissionRouter::new(Arc::new(manifest()))
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            person_drivers,
        )
        .machine(
            Method::POST,
            "/drivers/codes",
            "rutafacil.drivers.issueCode",
            machine_issue_code,
        )
        .person_or_machine(Method::GET, "/fleet", "rutafacil.fleet.read", fleet)
        .build()
        .expect("router")
}

async fn call(
    verifier: Arc<dyn AccessVerifier>,
    method: Method,
    path: &str,
    token: &str,
) -> (StatusCode, Value) {
    let router = router();
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier))
            .configure(|cfg| router.configure(cfg)),
    )
    .await;
    let request = actix_test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response: ServiceResponse = app
        .call(request)
        .await
        .expect("response")
        .map_into_boxed_body();
    let status = response.status();
    let body = actix_test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn fake() -> Arc<FakeVerifier> {
    Arc::new(FakeVerifier::new(API_AUDIENCE).expect("verifier"))
}

/// TEST_CHARTER
/// Requirement: a machine token holding the route's permission is accepted on a route declared
/// with `PermissionRouter::machine`, without any organization, and the handler reads the
/// calling client from `MachineAuthorized`.
/// Oracle: `200` and the `client_id` the handler answered.
/// Risk edge: the person gate's `organization_required` refusing every machine token.
/// Layer: the actix gate with the `FakeVerifier` (same header/claims checks as `TokenVerifier`).
/// Counterfactual: a gate that treats every token as a person answers `403
/// organization_required` here.
#[actix_web::test]
async fn a_machine_token_with_the_permission_passes_a_machine_route() {
    let verifier = fake();
    let token = signed_test_token(
        &verifier,
        &verifier.machine_claims(CALLER, &["rutafacil.drivers.issueCode"]),
    )
    .expect("token");

    let (status, body) = call(verifier, Method::POST, "/drivers/codes", &token).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["client"], CALLER);
    assert_eq!(body["permissions"], json!(["rutafacil.drivers.issueCode"]));
}

/// TEST_CHARTER
/// Requirement: a machine token is never accepted on a route declared for persons, even when it
/// lists that route's permission.
/// Oracle: `403 {"error":"machine_not_allowed"}`.
/// Risk edge: a machine reaching a person route and its organization-scoped handler.
/// Layer: actix gate + `FakeVerifier`.
/// Counterfactual: a gate that admits machine tokens on every route answers anything but
/// `machine_not_allowed`.
#[actix_web::test]
async fn a_machine_token_is_refused_on_a_person_route() {
    let verifier = fake();
    let token = signed_test_token(
        &verifier,
        &verifier.machine_claims(CALLER, &["rutafacil.drivers.list"]),
    )
    .expect("token");

    let (status, body) = call(verifier, Method::GET, "/drivers", &token).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "machine_not_allowed");
}

/// Requirement: a machine token without the route's permission is refused on a machine route.
/// Oracle: `403 {"error":"permission_denied"}`.
/// Counterfactual: skipping the permission check for machines answers `200`.
#[actix_web::test]
async fn a_machine_token_without_the_permission_is_refused() {
    let verifier = fake();
    let token = signed_test_token(
        &verifier,
        &verifier.machine_claims(CALLER, &["rutafacil.fleet.read"]),
    )
    .expect("token");

    let (status, body) = call(verifier, Method::POST, "/drivers/codes", &token).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "permission_denied");
}

/// TEST_CHARTER
/// Requirement: a person's token is refused on a machine-only route, even with the permission
/// and an organization.
/// Oracle: `403 {"error":"person_not_allowed"}`.
/// Risk edge: a person reaching an endpoint meant for system-to-system calls only.
/// Layer: actix gate + `FakeVerifier`.
/// Counterfactual: a gate that only checks the permission answers `200`.
#[actix_web::test]
async fn a_person_token_is_refused_on_a_machine_only_route() {
    let verifier = fake();
    let token = signed_test_token(
        &verifier,
        &verifier.claims("CU-1", Some("org-1"), &["rutafacil.drivers.issueCode"]),
    )
    .expect("token");

    let (status, body) = call(verifier, Method::POST, "/drivers/codes", &token).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "person_not_allowed");
}

/// Requirement: a route declared for both admits a person (with an organization) and a machine,
/// each with the permission, and the handler tells them apart through `Caller`.
/// Oracle: `200` and who the handler saw.
#[actix_web::test]
async fn a_route_for_both_admits_a_person_and_a_machine() {
    let verifier = fake();
    let person = signed_test_token(
        &verifier,
        &verifier.claims("CU-1", Some("org-1"), &["rutafacil.fleet.read"]),
    )
    .expect("person token");
    let machine = signed_test_token(
        &verifier,
        &verifier.machine_claims(CALLER, &["rutafacil.fleet.read"]),
    )
    .expect("machine token");

    let (person_status, person_body) = call(verifier.clone(), Method::GET, "/fleet", &person).await;
    let (machine_status, machine_body) = call(verifier, Method::GET, "/fleet", &machine).await;

    assert_eq!(person_status, StatusCode::OK, "{person_body}");
    assert_eq!(person_body, json!({ "person": "CU-1", "org": "org-1" }));
    assert_eq!(machine_status, StatusCode::OK, "{machine_body}");
    assert_eq!(machine_body, json!({ "machine": CALLER }));
}

/// Requirement: a person's token with no organization stays refused on a route for both.
/// Oracle: `403 {"error":"organization_required"}`.
#[actix_web::test]
async fn a_person_without_an_organization_is_refused_on_a_route_for_both() {
    let verifier = fake();
    let token = signed_test_token(
        &verifier,
        &verifier.claims("CU-1", None, &["rutafacil.fleet.read"]),
    )
    .expect("token");

    let (status, body) = call(verifier, Method::GET, "/fleet", &token).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "organization_required");
}

/// Requirement: a machine route's permission must be declared in `permissions.yaml`.
/// Oracle: `RouteMapError::UnknownPermission` from `build`.
#[test]
fn a_machine_route_with_an_undeclared_permission_is_refused_at_build() {
    let built = PermissionRouter::new(Arc::new(manifest()))
        .machine(
            Method::POST,
            "/drivers/codes",
            "rutafacil.drivers.unknown",
            machine_issue_code,
        )
        .build();

    assert!(matches!(
        built,
        Err(loginflow_sdk::actix::RouteMapError::UnknownPermission { .. })
    ));
}

/// TEST_CHARTER
/// Requirement: a machine token exactly as `loginflow_api` issues it for
/// `grant_type=client_credentials&resource=<this API>` (claims of `docs/api/oauth2/token.md`
/// "Machine access to a product API": `sub` = `client_id`, no `sid`, no `org_id`, `amr`
/// `["client_credentials"]`, `permissions` listed) passes the real `TokenVerifier` and the gate of
/// a machine route.
/// Oracle: `200` with the client id.
/// Risk edge: the wire claims not parsing, or not being recognised as a machine.
/// Layer: actix gate + the real `TokenVerifier` against an in-process JWKS.
/// Counterfactual: recognising machines by anything the API does not send (e.g. requiring
/// `org_id`) answers `403`.
#[actix_web::test]
async fn the_api_shaped_machine_token_passes_the_real_verifier() {
    let document = jwks(&[TestKey::a().public_jwk()]);
    let server = common::FakeServer::start(move |req| match req.path() {
        JWKS_PATH => Reply::ok(document.clone()),
        _ => Reply::status(404, "{}"),
    })
    .await;
    let verifier: Arc<TokenVerifier> = Arc::new(verifier_with(client_for(&server), &server));
    let now = now();
    let token = TestKey::a().sign(&json!({
        "iss": ISSUER, "sub": CALLER, "client_id": CALLER, "aud": API_AUDIENCE,
        "jti": "machine-jti-1", "iat": now, "exp": now + 600, "auth_time": now,
        "amr": ["client_credentials"], "scope": "rutafacil.drivers.issueCode",
        "company_id": COMPANY_ID, "app": APP_ID, "permissions": ["rutafacil.drivers.issueCode"],
    }));

    let (status, body) = call(verifier, Method::POST, "/drivers/codes", &token).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["client"], CALLER);
}
