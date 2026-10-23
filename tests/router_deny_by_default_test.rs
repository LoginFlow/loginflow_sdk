//! `PermissionRouter`: deny by default. A route outside the table is refused even for a token
//! that holds every permission, the table is checked against the manifest, and the `testing`
//! helpers catch an unrouted registration or an unrouted permission before deploy.

#![cfg(feature = "testing")]

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use actix_web::http::{Method, StatusCode};
use actix_web::test as actix_test;
use actix_web::{App, HttpResponse, web};
use common::{manifest, temp_dir};
use loginflow_sdk::actix::{Authorized, BuiltRouter, PermissionRouter, RouteMapError};
use loginflow_sdk::testing::{
    FakeVerifier, assert_no_unrouted_registrations, assert_router_covers_manifest,
    signed_test_token,
};
use serde_json::{Value, json};

const AUDIENCE: &str = "https://drivers.api.test";

const EVERY_PERMISSION: [&str; 4] = [
    "rutafacil.drivers.list",
    "rutafacil.drivers.create",
    "rutafacil.drivers.issueCode",
    "rutafacil.fleet.read",
];

async fn list_drivers(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "org": auth.org_id() }))
}

async fn raw_handler() -> HttpResponse {
    HttpResponse::Ok().json(json!({ "reached": true }))
}

async fn public_asking_for_a_caller(auth: Authorized) -> HttpResponse {
    HttpResponse::Ok().json(json!({ "sub": auth.sub() }))
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn router() -> BuiltRouter {
    PermissionRouter::new(Arc::new(manifest()))
        .public(Method::GET, "/health", health)
        .public(Method::GET, "/whoami", public_asking_for_a_caller)
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            list_drivers,
        )
        .build()
        .expect("router")
}

fn token_with_every_permission(verifier: &FakeVerifier) -> String {
    let claims = verifier.claims("CU-1", Some("org-1"), &EVERY_PERMISSION);
    signed_test_token(verifier, &claims).expect("token")
}

/// TEST_CHARTER
/// Requirement: a request whose route is not in the router's table — a raw `App::route`, a path
/// no one registered, or a mapped path with another method — is refused with
/// `403 permission_unmapped`, whatever the token grants.
/// Oracle: HTTP status and body `error` of each response; the raw handler's body never comes
/// back.
/// Risk edge: OWASP API5 — a route added without a permission is reachable by any signed-in
/// caller.
/// Layer: integration — a real actix `App` with the gate wrapping it, `FakeVerifier` tokens.
/// Counterfactual: letting an unmapped route through the gate returns the raw handler's `200`.
#[actix_web::test]
async fn a_route_outside_the_table_is_refused_even_with_every_permission() {
    let router = router();
    let verifier = Arc::new(FakeVerifier::new(AUDIENCE).expect("verifier"));
    let token = token_with_every_permission(&verifier);
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier.clone()))
            .configure(|cfg| router.configure(cfg))
            .route("/raw", web::get().to(raw_handler)),
    )
    .await;

    for (method, path) in [
        (Method::GET, "/raw"),
        (Method::GET, "/nowhere"),
        (Method::DELETE, "/drivers"),
    ] {
        let req = actix_test::TestRequest::default()
            .method(method.clone())
            .uri(path)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let response = actix_test::call_service(&app, req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
        let body: Value = actix_test::read_body_json(response).await;
        assert_eq!(
            body["error"],
            json!("permission_unmapped"),
            "{method} {path}"
        );
    }

    // Control: the mapped route with the same token is served.
    let req = actix_test::TestRequest::get()
        .uri("/drivers")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, req).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = actix_test::read_body_json(response).await;
    assert_eq!(body["org"], json!("org-1"));
}

/// A public route needs no token; a handler that asks for `Authorized` on one gets a `500`,
/// never an unverified caller.
#[actix_web::test]
async fn a_public_route_passes_without_a_token_and_never_yields_a_caller() {
    let router = router();
    let verifier = Arc::new(FakeVerifier::new(AUDIENCE).expect("verifier"));
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier))
            .configure(|cfg| router.configure(cfg)),
    )
    .await;

    let health = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri("/health").to_request(),
    )
    .await;
    assert_eq!(health.status(), StatusCode::OK);

    let whoami = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri("/whoami").to_request(),
    )
    .await;
    assert_eq!(whoami.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let unauthenticated = actix_test::call_service(
        &app,
        actix_test::TestRequest::get().uri("/drivers").to_request(),
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}

/// `FakeVerifier` holds its tokens to the same audience rule as `TokenVerifier`.
#[actix_web::test]
async fn the_fake_verifier_refuses_a_token_for_another_api() {
    let router = router();
    let verifier = Arc::new(FakeVerifier::new(AUDIENCE).expect("verifier"));
    let mut claims = verifier.claims("CU-1", Some("org-1"), &EVERY_PERMISSION);
    claims.aud = "https://billing.api.test".to_string();
    let token = signed_test_token(&verifier, &claims).expect("token");
    let app = actix_test::init_service(
        App::new()
            .wrap(router.gate(verifier.clone()))
            .configure(|cfg| router.configure(cfg)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/drivers")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(
        actix_test::call_service(&app, req).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn build_refuses_an_unknown_permission_a_duplicate_route_and_a_relative_path() {
    let manifest = Arc::new(manifest());
    let unknown = PermissionRouter::new(manifest.clone())
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.delete",
            list_drivers,
        )
        .build();
    assert!(matches!(
        unknown,
        Err(RouteMapError::UnknownPermission {
            permission: "rutafacil.drivers.delete",
            ..
        })
    ));

    let duplicate = PermissionRouter::new(manifest.clone())
        .route(
            Method::GET,
            "/drivers",
            "rutafacil.drivers.list",
            list_drivers,
        )
        .public(Method::GET, "/drivers", health)
        .build();
    assert!(matches!(
        duplicate,
        Err(RouteMapError::DuplicateRoute { .. })
    ));

    let relative = PermissionRouter::new(manifest)
        .public(Method::GET, "health", health)
        .build();
    assert!(matches!(relative, Err(RouteMapError::InvalidPath { .. })));
}

/// TEST_CHARTER
/// Requirement: `assert_no_unrouted_registrations` fails on a source tree that registers a
/// route outside the `PermissionRouter` (route macros, `web::resource`, `App::route("...")`)
/// and passes on one that only uses the router.
/// Oracle: whether the assertion panics, and the `file:line` it reports.
/// Risk edge: a raw route compiled into the product (refused at runtime, but shipped).
/// Layer: unit over real files in a temp directory.
/// Counterfactual: an empty pattern list makes the raw tree pass.
#[test]
fn unrouted_registrations_in_the_source_tree_fail_the_assertion() {
    let raw = temp_dir("raw-src");
    std::fs::create_dir_all(raw.join("handlers")).expect("dir");
    std::fs::write(
        raw.join("handlers/drivers.rs"),
        "#[get(\"/drivers\")]\nasync fn list() -> HttpResponse { todo() }\n",
    )
    .expect("write");
    std::fs::write(
        raw.join("main.rs"),
        "App::new()\n    .route(\n        \"/raw\",\n        handler,\n    );\n",
    )
    .expect("write");
    let panic = catch_unwind(|| assert_no_unrouted_registrations(&raw))
        .expect_err("raw registrations must fail");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("drivers.rs:1"), "{message}");
    assert!(message.contains("main.rs:2"), "{message}");
    let _ = std::fs::remove_dir_all(raw);

    let clean = temp_dir("clean-src");
    std::fs::write(
        clean.join("routes.rs"),
        "// web::resource( in a comment is fine\nPermissionRouter::new(m)\n    .route(Method::GET, \"/drivers\", \"rutafacil.drivers.list\", list)\n    .build()\n",
    )
    .expect("write");
    assert_no_unrouted_registrations(&clean);
    let _ = std::fs::remove_dir_all(clean);
}

/// TEST_CHARTER
/// Requirement: `assert_router_covers_manifest` fails while a permission of the manifest guards
/// no route, and passes once every one does.
/// Oracle: whether the assertion panics, naming the unrouted permissions.
/// Risk edge: a permission granted in the panel that protects nothing (or a route that forgot
/// it).
/// Layer: unit.
/// Counterfactual: comparing against the manifest itself instead of the routed set passes the
/// incomplete router.
#[test]
fn a_permission_no_route_requires_fails_the_coverage_assertion() {
    let manifest = manifest();
    let partial = router();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        assert_router_covers_manifest(&partial, &manifest)
    }))
    .expect_err("partial router must fail");
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("rutafacil.drivers.create"), "{message}");
    assert!(!message.contains("rutafacil.drivers.list"), "{message}");

    let full = PermissionRouter::new(Arc::new(manifest.clone()))
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
            "/drivers/{id}/code",
            "rutafacil.drivers.issueCode",
            list_drivers,
        )
        .route(Method::GET, "/fleet", "rutafacil.fleet.read", list_drivers)
        .build()
        .expect("router");
    assert_router_covers_manifest(&full, &manifest);
}
