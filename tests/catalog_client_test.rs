//! `CatalogClient`: the API's manifest synced to `PUT /v1/service/catalog` behind a
//! `loginflow.catalog.write` token, the contract body and report, the conflicts the server
//! answers, and a manifest refused before anything is sent.

mod common;

use common::{
    MANIFEST_YAML, Reply, TOKEN_PATH, api_requests, config_for, envelope, error_body, manifest,
    service_door_server as server, token_request_scope,
};
use loginflow_sdk::{
    CatalogClient, LoginFlowError, PermissionLevel, PermissionManifest, PermissionStatus,
};
use serde_json::json;

const CATALOG_PATH: &str = "/v1/service/catalog";

fn client(server: &common::FakeServer) -> CatalogClient {
    CatalogClient::new(config_for(server), "drivers-api", "secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: `sync` requests a `loginflow.catalog.write` token and PUTs the manifest as
/// `{app, resources, permissions}` — no application or API id (the server takes both from the
/// token) — and parses the report.
/// Oracle: the token request's scope, the recorded PUT (method, path, Bearer, JSON body) and the
/// returned `CatalogSyncReport`.
/// Risk edge: a body that names its own app/API would let a key sync another API's catalog.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: another scope fails the scope assertion; a body built differently from the
/// manifest fails the body assertion.
#[tokio::test]
async fn sync_puts_the_manifest_with_a_catalog_write_token_and_parses_the_report() {
    let server = server(|_| {
        Reply::ok(envelope(json!({
            "catalog_hash": "a".repeat(64),
            "added": ["rutafacil.drivers.issueCode"],
            "reactivated": ["rutafacil.fleet.read"],
            "obsoleted": ["rutafacil.drivers.delete"],
            "unchanged": 2,
        })))
    })
    .await;

    let report = client(&server).sync(&manifest()).await.expect("synced");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.catalog.read loginflow.catalog.write"
    );
    let put = server.last();
    assert_eq!(put.method, "PUT");
    assert_eq!(put.path(), CATALOG_PATH);
    assert_eq!(put.header("authorization"), Some("Bearer token-1"));
    let body = put.json();
    assert_eq!(
        body,
        serde_json::to_value(manifest().catalog_request()).expect("body")
    );
    assert!(body.get("application_id").is_none() && body.get("api_id").is_none());

    assert_eq!(report.catalog_hash, "a".repeat(64));
    assert_eq!(report.added, ["rutafacil.drivers.issueCode"]);
    assert_eq!(report.reactivated, ["rutafacil.fleet.read"]);
    assert_eq!(report.obsoleted, ["rutafacil.drivers.delete"]);
    assert_eq!(report.unchanged, 2);
}

#[tokio::test]
async fn get_reads_the_apis_catalog() {
    let server = server(|_| {
        Reply::ok(envelope(json!({
            "app": "rutafacil",
            "catalog_hash": "b".repeat(64),
            "synced_at": "2026-10-22T09:00:00",
            "permissions": [{
                "key": "rutafacil.drivers.list", "resource": "drivers", "level": "read",
                "description": "List the drivers", "sensitive": true, "status": "obsolete",
            }],
        })))
    })
    .await;

    let catalog = client(&server).get().await.expect("catalog");

    assert_eq!(server.last().method, "GET");
    assert_eq!(server.last().path(), CATALOG_PATH);
    assert_eq!(catalog.app.as_deref(), Some("rutafacil"));
    assert_eq!(catalog.permissions[0].level, PermissionLevel::Read);
    assert_eq!(catalog.permissions[0].status, PermissionStatus::Obsolete);
    assert!(catalog.permissions[0].sensitive);
}

/// TEST_CHARTER
/// Requirement: `get` reads the catalog of an API that has not synced yet — the server answers
/// `app`, `catalog_hash` and `synced_at` as `null` until the first sync.
/// Oracle: `get()` returns `Ok` with no app, no hash, no sync time and no permissions.
/// Risk edge: a valid server state turned into a `ParseError` for every API before its first sync.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: a required `app: String` fails to parse `null` and `get()` errs.
#[tokio::test]
async fn get_reads_the_catalog_of_an_api_that_never_synced() {
    let server = server(|_| {
        Reply::ok(envelope(json!({
            "app": null, "catalog_hash": null, "synced_at": null, "permissions": [],
        })))
    })
    .await;

    let catalog = client(&server).get().await.expect("catalog");

    assert_eq!(catalog.app, None);
    assert_eq!(catalog.catalog_hash, None);
    assert_eq!(catalog.synced_at, None);
    assert!(catalog.permissions.is_empty());
}

/// The server's `409` codes reach the caller, so a deploy can tell a gate-protected permission
/// apart from a resource another API owns.
#[tokio::test]
async fn sync_conflicts_carry_the_server_code() {
    for code in [
        "catalog_app_mismatch",
        "catalog_prefix_taken",
        "resource_owned_by_other_api",
        "permission_used_by_sign_in_gate",
    ] {
        let server = server(move |_| Reply::status(409, error_body(code, "conflict"))).await;
        let result = client(&server).sync(&manifest()).await;
        assert!(
            matches!(&result, Err(LoginFlowError::Conflict { code: Some(c), .. }) if c == code),
            "{code}: {result:?}"
        );
    }
}

/// A manifest built by hand that breaks the rules is refused locally: no token, no request.
#[tokio::test]
async fn an_invalid_manifest_is_refused_before_any_request() {
    let server = server(|_| Reply::ok(envelope(json!({})))).await;
    let mut invalid: PermissionManifest =
        serde_yaml_ng::from_str(MANIFEST_YAML).expect("parse without validation");
    invalid.app = "loginflow".to_string();

    let result = client(&server).sync(&invalid).await;

    assert!(
        matches!(result, Err(LoginFlowError::Validation { .. })),
        "{result:?}"
    );
    assert_eq!(server.hits(TOKEN_PATH), 0);
    assert!(api_requests(&server).is_empty());
}

/// TEST_CHARTER
/// Requirement: the key's token carries `loginflow.catalog.read` AND `loginflow.catalog.write`
/// (contract C1 of phase 2): `GET /v1/service/catalog` needs `.read`, the sync needs `.write`,
/// each checked exactly in the token `scope`.
/// Oracle: the decoded `scope` of the token request behind a `get`, and the GET.
/// Risk edge: a write-only token answered `403 permission_denied` when reading the catalog.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: requesting only `loginflow.catalog.write` fails the scope assertion.
#[tokio::test]
async fn a_read_is_sent_with_a_token_that_carries_the_read_and_write_permissions() {
    let server = server(|_| {
        Reply::ok(envelope(json!({
            "app": "rutafacil", "catalog_hash": null, "synced_at": null, "permissions": []
        })))
    })
    .await;

    let catalog = client(&server).get().await.expect("read");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.catalog.read loginflow.catalog.write"
    );
    let get = server.last();
    assert_eq!(get.method, "GET");
    assert_eq!(get.path(), CATALOG_PATH);
    assert_eq!(catalog.app.as_deref(), Some("rutafacil"));
}
