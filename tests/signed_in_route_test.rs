//! Signed-in routes (`PermissionRouter::signed_in`): a person's token, verified exactly as on a
//! permission route, reaches the handler without an organization or a permission; a machine
//! token and an access-code subject's token are refused; the route table and the `testing`
//! helpers keep their guarantees with such routes in it.

#![cfg(feature = "testing")]

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use actix_web::dev::{Service, ServiceResponse};
use actix_web::http::{Method, StatusCode};
use actix_web::test as actix_test;
use actix_web::{App, HttpResponse};
use common::{
    API_AUDIENCE, COMPANY_ID, JWKS_PATH, Reply, TestKey, access_claims, build_dpop_proof,
    claims_with, client_for, jwk_thumbprint, jwks, manifest, now, temp_dir, verifier_with,
};
use loginflow_sdk::actix::{Authorized, BuiltRouter, PermissionRouter, RouteMapError, SignedIn};
use loginflow_sdk::dpop::access_token_hash;
use loginflow_sdk::testing::{
    FakeVerifier, assert_no_unrouted_registrations, assert_router_covers_manifest,
    signed_test_token,
};
use loginflow_sdk::{AccessSubjectClaims, AccessVerifier};
use serde_json::{Value, json};

const HOST: &str = "rs.example.test";

async fn found_company(person: SignedIn) -> HttpResponse {
    HttpResponse::Created().json(json!({
        "sub": person.sub(),
        "org": person.org_id(),
        "company": person.claims().company_id,
        "jkt": person.dpop_jkt(),
        "token": person.access_token(),
    }))
}

async fn asks_for_authorized(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "org": auth.org_id() }))
}

async fn list_drivers(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "org": auth.org_id(), "token": auth.access_token() }))
}

fn router() -> BuiltRouter {
    PermissionRouter::new(Arc::new(manifest()))
        .signed_in(Method::POST, "/companies", found_company)
        .signed_in(Method::GET, "/me/organization", asks_for_authorized)
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            list_drivers,
        )
        .build()
        .expect("router")
}

async fn send(
    verifier: Arc<dyn AccessVerifier>,
    requests: Vec<actix_test::TestRequest>,
) -> Vec<(StatusCode, Value)> {
    let router = router();
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier))
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
        answers.push((status, serde_json::from_slice(&body).unwrap_or(Value::Null)));
    }
    answers
}

async fn post_companies(
    verifier: Arc<dyn AccessVerifier>,
    authorization: &str,
) -> (StatusCode, Value) {
    let request = actix_test::TestRequest::post()
        .uri("/companies")
        .insert_header(("Authorization", authorization.to_string()));
    send(verifier, vec![request]).await.remove(0)
}

fn fake() -> Arc<FakeVerifier> {
    Arc::new(FakeVerifier::new(API_AUDIENCE).expect("verifier"))
}

fn token(verifier: &FakeVerifier, claims: &loginflow_sdk::AccessClaims) -> String {
    signed_test_token(verifier, claims).expect("token")
}

/// TEST_CHARTER
/// Requirement: a person's verified token WITHOUT an organization (and without any permission)
/// reaches a signed-in route, and the handler reads who they are from `SignedIn`: `sub`, no
/// organization, the verified claims and the very token the request presented (to forward as
/// `actor_token`).
/// Oracle: `201` and the handler's JSON body built from `SignedIn`.
/// Risk edge: the person gate's `organization_required` blocking every "create my company".
/// Layer: actix gate + `FakeVerifier` (same header/claims checks as `TokenVerifier`).
/// Counterfactual: admitting signed-in routes through the permission path answers `403
/// organization_required`; a gate that does not insert `SignedIn` answers `500`.
#[actix_web::test]
async fn a_person_without_an_organization_reaches_a_signed_in_route() {
    let verifier = fake();
    let presented = token(&verifier, &verifier.claims("CU-1", None, &[]));

    let (status, body) = post_companies(verifier, &format!("Bearer {presented}")).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["sub"], "CU-1");
    assert_eq!(body["org"], Value::Null);
    assert_eq!(body["company"], loginflow_sdk::testing::FAKE_COMPANY_ID);
    assert_eq!(body["jkt"], Value::Null);
    assert_eq!(body["token"], json!(presented));
}

/// Requirement: a person who already has an organization also passes; `org_id` shows it.
/// Oracle: `201` with `org`.
#[actix_web::test]
async fn a_person_with_an_organization_passes_and_sees_it() {
    let verifier = fake();
    let presented = token(&verifier, &verifier.claims("CU-1", Some("org-1"), &[]));

    let (status, body) = post_companies(verifier, &format!("Bearer {presented}")).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["org"], "org-1");
}

/// TEST_CHARTER
/// Requirement: signed-in routes are for people only: a `client_credentials` (machine) token is
/// `403 machine_not_allowed` and an access-code subject's token is `403
/// access_subject_not_allowed`, the same body shape as every other gate refusal.
/// Oracle: status and body `error`.
/// Risk edge: a machine key or a device code founding organizations as if it were a person.
/// Layer: actix gate + `FakeVerifier`.
/// Counterfactual: admitting any verified token (no person check) answers `201` for both.
#[actix_web::test]
async fn machine_and_access_code_subject_tokens_are_refused() {
    let verifier = fake();
    let machine = token(&verifier, &verifier.machine_claims("payments-caller", &[]));
    let mut subject_claims = verifier.claims("AS-1", None, &[]);
    subject_claims.access_subject = Some(AccessSubjectClaims {
        ext_sub: "driver:7".into(),
        subject_kind: "person".into(),
        ext_profile: "Driver".into(),
    });
    let subject = token(&verifier, &subject_claims);

    let (machine_status, machine_body) =
        post_companies(verifier.clone(), &format!("Bearer {machine}")).await;
    let (subject_status, subject_body) =
        post_companies(verifier, &format!("Bearer {subject}")).await;

    assert_eq!(machine_status, StatusCode::FORBIDDEN);
    assert_eq!(
        machine_body,
        json!({ "error": "machine_not_allowed", "error_type": "Authorization" })
    );
    assert_eq!(subject_status, StatusCode::FORBIDDEN);
    assert_eq!(
        subject_body,
        json!({ "error": "access_subject_not_allowed", "error_type": "Authorization" })
    );
}

/// TEST_CHARTER
/// Requirement: the token is verified exactly as on a permission route: no token, another API's
/// `aud`, another company, an expired token or a wrong signature are `401 invalid_token`.
/// Oracle: status and body `error` of each answer.
/// Risk edge: "no permission required" read as "no verification".
/// Layer: actix gate + `FakeVerifier`.
/// Counterfactual: treating a signed-in route like a public one answers `201` for every case.
#[actix_web::test]
async fn a_token_that_does_not_verify_is_refused() {
    let verifier = fake();
    let other_api = FakeVerifier::new("https://billing.api.test").expect("other verifier");
    let mut other_company = verifier.claims("CU-1", None, &[]);
    other_company.company_id = "CP-OTHER".into();
    let mut expired = verifier.claims("CU-1", None, &[]);
    expired.exp = now() - 3600;
    let foreign_key = FakeVerifier::new(API_AUDIENCE).expect("foreign key");

    let cases = [
        ("no token", None),
        (
            "another API",
            Some(token(&other_api, &other_api.claims("CU-1", None, &[]))),
        ),
        ("another company", Some(token(&verifier, &other_company))),
        ("expired", Some(token(&verifier, &expired))),
        (
            "another signing key",
            Some(token(&foreign_key, &foreign_key.claims("CU-1", None, &[]))),
        ),
    ];
    for (case, presented) in cases {
        let mut request = actix_test::TestRequest::post().uri("/companies");
        if let Some(presented) = presented {
            request = request.insert_header(("Authorization", format!("Bearer {presented}")));
        }
        let (status, body) = send(verifier.clone(), vec![request]).await.remove(0);
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{case}: {body}");
        assert_eq!(body["error"], "invalid_token", "{case}");
    }
}

/// TEST_CHARTER
/// Requirement: a DPoP-bound person's token passes a signed-in route with a proof for it, once:
/// the same proof again is `401`, and the handler sees the proved key's thumbprint.
/// Oracle: the statuses and `jkt` of three answers.
/// Risk edge: a stolen bound token (or a replayed proof) founding an organization.
/// Layer: actix gate + the real `TokenVerifier` against an in-process JWKS.
/// Counterfactual: skipping the binding check accepts the replayed proof (`201`).
#[actix_web::test]
async fn a_dpop_bound_token_needs_a_fresh_proof() {
    let document = jwks(&[TestKey::a().public_jwk()]);
    let server = common::FakeServer::start(move |req| match req.path() {
        JWKS_PATH => Reply::ok(document.clone()),
        _ => Reply::status(404, "{}"),
    })
    .await;
    let verifier = Arc::new(verifier_with(client_for(&server), &server));
    let mut claims = claims_with("cnf", json!({ "jkt": jwk_thumbprint(&TestKey::b()) }));
    claims["org_id"] = Value::Null;
    claims["org_ext"] = Value::Null;
    claims["permissions"] = json!([]);
    let bound = TestKey::a().sign(&claims);
    let htu = format!("http://{HOST}/companies");
    let proof = |jti: &str| {
        build_dpop_proof(
            &TestKey::b(),
            "POST",
            &htu,
            jti,
            Some(&access_token_hash(&bound)),
            now(),
        )
    };
    let dpop_post = |proof: String| {
        actix_test::TestRequest::post()
            .uri("/companies")
            .insert_header(("Authorization", format!("DPoP {bound}")))
            .insert_header(("DPoP", proof))
    };

    let answers = send(
        verifier,
        vec![
            dpop_post(proof("proof-1")),
            dpop_post(proof("proof-1")),
            dpop_post(proof("proof-2")),
        ],
    )
    .await;

    assert_eq!(answers[0].0, StatusCode::CREATED, "{}", answers[0].1);
    assert_eq!(answers[0].1["jkt"], json!(jwk_thumbprint(&TestKey::b())));
    assert_eq!(answers[0].1["company"], COMPANY_ID);
    assert_eq!(answers[1].0, StatusCode::UNAUTHORIZED, "replayed proof");
    assert_eq!(answers[2].0, StatusCode::CREATED, "fresh proof");
}

/// Requirement: `Authorized` keeps its guarantee (a verified organization and the route's
/// permission): a signed-in route's handler that asks for it gets a `500`, never an
/// `Authorized` without them — even for a token that has an organization.
/// Oracle: `500`.
/// Counterfactual: inserting `Authorized` on signed-in routes answers `200`.
#[actix_web::test]
async fn authorized_is_not_available_on_a_signed_in_route() {
    let verifier = fake();
    let presented = token(&verifier, &verifier.claims("CU-1", Some("org-1"), &[]));
    let request = actix_test::TestRequest::get()
        .uri("/me/organization")
        .insert_header(("Authorization", format!("Bearer {presented}")));

    let (status, _) = send(verifier, vec![request]).await.remove(0);

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// Requirement: one way to read the token to forward: `Authorized::access_token` on a
/// permission route returns the token the gate verified, like `SignedIn::access_token`.
/// Oracle: the handler's `token`.
#[actix_web::test]
async fn authorized_exposes_the_verified_token_too() {
    let verifier = fake();
    let presented = token(
        &verifier,
        &verifier.claims("CU-1", Some("org-1"), &["rutafacil.drivers.list"]),
    );
    let request = actix_test::TestRequest::get()
        .uri("/drivers")
        .insert_header(("Authorization", format!("Bearer {presented}")));

    let (status, body) = send(verifier, vec![request]).await.remove(0);

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token"], json!(presented));
}

/// Requirement: the token never shows in `Debug` (a caller logged with `{:?}`).
/// Oracle: the formatted `SignedIn` and `Authorized` do not contain the token.
/// Counterfactual: a derived `Debug` on the stored token prints it.
#[actix_web::test]
async fn the_token_never_shows_in_debug() {
    async fn debug_both(person: SignedIn) -> HttpResponse {
        HttpResponse::Ok().body(format!("{person:?}"))
    }
    async fn debug_authorized(auth: Authorized) -> HttpResponse {
        HttpResponse::Ok().body(format!("{auth:?}"))
    }
    let router = PermissionRouter::new(Arc::new(manifest()))
        .signed_in(Method::GET, "/signed-in", debug_both)
        .route(
            Method::GET,
            "/authorized",
            "rutafacil.drivers.list",
            debug_authorized,
        )
        .build()
        .expect("router");
    let verifier = fake();
    let presented = token(
        &verifier,
        &verifier.claims("CU-1", Some("org-1"), &["rutafacil.drivers.list"]),
    );
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier))
            .configure(|cfg| router.configure(cfg)),
    )
    .await;

    for path in ["/signed-in", "/authorized"] {
        let request = actix_test::TestRequest::get()
            .uri(path)
            .insert_header(("Authorization", format!("Bearer {presented}")))
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body =
            String::from_utf8(actix_test::read_body(response).await.to_vec()).expect("utf-8");
        assert!(body.contains("CU-1"), "{path}: {body}");
        assert!(!body.contains(&presented), "{path} leaks the token: {body}");
    }
}

/// TEST_CHARTER
/// Requirement: the route table keeps its checks with signed-in routes in it: the same method
/// and path declared twice (signed-in and permission) is `DuplicateRoute`, and a permission
/// route with an undeclared permission is still `UnknownPermission`.
/// Oracle: the `RouteMapError` of `build`.
/// Risk edge: a signed-in declaration silently shadowing a permission route.
/// Layer: unit — the router alone.
/// Counterfactual: a table that skips signed-in entries when checking duplicates builds.
#[test]
fn the_table_still_refuses_duplicates_and_unknown_permissions() {
    let duplicate = PermissionRouter::new(Arc::new(manifest()))
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            list_drivers,
        )
        .signed_in(Method::GET, "/drivers", found_company)
        .build();
    assert!(
        matches!(
            duplicate,
            Err(RouteMapError::DuplicateRoute {
                path: "/drivers",
                ..
            })
        ),
        "a signed-in route over a permission route must be refused"
    );

    let unknown = PermissionRouter::new(Arc::new(manifest()))
        .signed_in(Method::POST, "/companies", found_company)
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.unknown",
            list_drivers,
        )
        .build();
    assert!(matches!(
        unknown,
        Err(RouteMapError::UnknownPermission {
            permission: "rutafacil.drivers.unknown",
            ..
        })
    ));
}

/// Requirement: the `testing` helpers accept signed-in routes: `assert_router_covers_manifest`
/// only counts permission routes (a signed-in route neither covers nor breaks coverage), and
/// `assert_no_unrouted_registrations` does not flag a `.signed_in(...)` declaration.
/// Oracle: the helpers pass on a router/source with signed-in routes, and still panic on an
/// uncovered permission.
#[test]
fn the_testing_helpers_support_signed_in_routes() {
    let manifest = manifest();
    let covering = PermissionRouter::new(Arc::new(manifest.clone()))
        .signed_in(Method::POST, "/companies", found_company)
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
            list_drivers,
        )
        .route(
            Method::POST,
            "/drivers/codes",
            "rutafacil.drivers.issueCode",
            list_drivers,
        )
        .route(Method::GET, "/fleet", "rutafacil.fleet.read", list_drivers)
        .build()
        .expect("router");
    assert_router_covers_manifest(&covering, &manifest);

    let only_signed_in = PermissionRouter::new(Arc::new(manifest.clone()))
        .signed_in(Method::POST, "/companies", found_company)
        .build()
        .expect("router");
    let uncovered = catch_unwind(AssertUnwindSafe(|| {
        assert_router_covers_manifest(&only_signed_in, &manifest)
    }));
    assert!(uncovered.is_err(), "a signed-in route covers no permission");

    let dir = temp_dir("signed-in-src");
    std::fs::write(
        dir.join("routes.rs"),
        "pub fn router(m: Manifest) -> PermissionRouter {\n    PermissionRouter::new(m)\n        .signed_in(Method::POST, \"/companies\", found_company)\n        .signed_in(\n            Method::GET,\n            \"/me\",\n            me,\n        )\n}\n",
    )
    .expect("write source");
    let scan = catch_unwind(|| assert_no_unrouted_registrations(&dir));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        scan.is_ok(),
        "signed-in declarations are routed registrations"
    );
}

/// Requirement: `FakeVerifier` signs org-less person tokens that pass a signed-in route (the
/// test tokens a product writes for its own "create my company" route).
/// Oracle: `access_claims()`-shaped real token with no `org_id` passes the real verifier too.
#[actix_web::test]
async fn an_api_shaped_org_less_token_passes_the_real_verifier() {
    let document = jwks(&[TestKey::a().public_jwk()]);
    let server = common::FakeServer::start(move |req| match req.path() {
        JWKS_PATH => Reply::ok(document.clone()),
        _ => Reply::status(404, "{}"),
    })
    .await;
    let verifier = Arc::new(verifier_with(client_for(&server), &server));
    let mut claims = access_claims();
    let object = claims.as_object_mut().expect("claims object");
    object.remove("org_id");
    object.remove("org_ext");
    object.insert("permissions".into(), json!([]));
    let presented = TestKey::a().sign(&claims);

    let (status, body) = post_companies(verifier, &format!("Bearer {presented}")).await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["org"], Value::Null);
}
