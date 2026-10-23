//! `OrganizationsClient`: `/v1/service/organizations` behind a `loginflow.organizations.write`
//! token — ensure by external id, get, find, list, root and delete.

mod common;

use common::{
    Reply, config_for, envelope, error_body, service_door_server as server, token_request_scope,
};
use loginflow_sdk::{LoginFlowError, OrganizationKind, OrganizationsClient, PageRequest};
use serde_json::{Value, json};

fn organization(id: &str, kind: &str, external_id: Option<&str>) -> Value {
    json!({
        "id": id, "kind": kind, "external_id": external_id, "name": format!("Org {id}"),
        "created_at": "2026-10-22T09:00:00",
    })
}

fn client(server: &common::FakeServer) -> OrganizationsClient {
    OrganizationsClient::new(config_for(server), "drivers-api", "secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: `ensure` PUTs `{name}` to `/v1/service/organizations/external/{external_id}`
/// (percent-encoded) with a `loginflow.organizations.write` token, and parses the organization
/// (`201` created or `200` renamed).
/// Oracle: the token scope, the recorded PUT and the returned `Organization`.
/// Risk edge: an unencoded external id (`client/7`) addressing another path.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: no encoding sends `/external/client/7`, which this server answers `404`.
#[tokio::test]
async fn ensure_puts_the_name_under_the_encoded_external_id() {
    let server = server(|req| match (req.method.as_str(), req.target.as_str()) {
        ("PUT", "/v1/service/organizations/external/client%2F7") => Reply::status(
            201,
            envelope(organization("org-7", "regular", Some("client/7"))),
        ),
        _ => Reply::status(404, error_body("NOT_FOUND", "no route")),
    })
    .await;

    let organization = client(&server)
        .ensure("client/7", "Transportes Ruiz")
        .await
        .expect("ensured");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.organizations.read loginflow.organizations.write"
    );
    assert_eq!(server.last().json(), json!({ "name": "Transportes Ruiz" }));
    assert_eq!(organization.id, "org-7");
    assert_eq!(organization.kind, OrganizationKind::Regular);
    assert_eq!(organization.external_id.as_deref(), Some("client/7"));
}

#[tokio::test]
async fn get_find_and_list_hit_the_contract_routes() {
    let server = server(|req| match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/v1/service/organizations/org-7") => {
            Reply::ok(envelope(organization("org-7", "regular", Some("client-7"))))
        }
        ("GET", "/v1/service/organizations?external_id=client-7") => Reply::ok(envelope(json!({
            "items": [organization("org-7", "regular", Some("client-7"))], "total": 1,
        }))),
        ("GET", "/v1/service/organizations?external_id=client-8") => {
            Reply::ok(envelope(json!({ "items": [], "total": 0 })))
        }
        ("GET", "/v1/service/organizations?limit=2&offset=4") => Reply::ok(envelope(json!({
            "items": [organization("org-1", "root", None)], "total": 5,
        }))),
        _ => Reply::status(404, error_body("NOT_FOUND", "Organization not found")),
    })
    .await;
    let organizations = client(&server);

    assert_eq!(organizations.get("org-7").await.expect("get").id, "org-7");
    assert!(matches!(
        organizations.get("org-9").await,
        Err(LoginFlowError::NotFound { .. })
    ));
    assert_eq!(
        organizations
            .find_by_external_id("client-7")
            .await
            .expect("find")
            .map(|o| o.id),
        Some("org-7".to_string())
    );
    assert_eq!(
        organizations
            .find_by_external_id("client-8")
            .await
            .expect("find"),
        None
    );
    let page = organizations
        .list(PageRequest {
            limit: Some(2),
            offset: Some(4),
        })
        .await
        .expect("list");
    assert_eq!(page.total, 5);
    assert_eq!(page.items[0].kind, OrganizationKind::Root);
    assert_eq!(page.items[0].external_id, None);
}

/// `root` pages through the listing until it finds the root, wherever the server lists it.
#[tokio::test]
async fn root_pages_until_it_finds_the_root() {
    let server = server(|req| match req.target.as_str() {
        "/v1/service/organizations?limit=100&offset=0" => Reply::ok(envelope(json!({
            "items": (0..100).map(|i| organization(&format!("org-{i}"), "regular", Some(&format!("c-{i}")))).collect::<Vec<_>>(),
            "total": 101,
        }))),
        "/v1/service/organizations?limit=100&offset=100" => Reply::ok(envelope(json!({
            "items": [organization("org-root", "root", None)], "total": 101,
        }))),
        _ => Reply::status(404, error_body("NOT_FOUND", "no route")),
    })
    .await;

    let root = client(&server).root().await.expect("root");

    assert_eq!(root.id, "org-root");
    assert_eq!(root.kind, OrganizationKind::Root);
}

#[tokio::test]
async fn delete_answers_no_content_and_the_root_is_a_conflict() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("DELETE", "/v1/service/organizations/org-7") => Reply::status(204, ""),
        ("DELETE", "/v1/service/organizations/org-root") => Reply::status(
            409,
            error_body(
                "root_organization",
                "The root organization cannot be deleted",
            ),
        ),
        _ => Reply::status(404, error_body("NOT_FOUND", "Organization not found")),
    })
    .await;
    let organizations = client(&server);

    organizations.delete("org-7").await.expect("deleted");
    assert_eq!(server.last().method, "DELETE");
    assert!(matches!(
        organizations.delete("org-root").await,
        Err(LoginFlowError::Conflict { code: Some(code), .. }) if code == "root_organization"
    ));
    assert!(matches!(
        organizations.delete("org-9").await,
        Err(LoginFlowError::NotFound { .. })
    ));
}

/// TEST_CHARTER
/// Requirement: the key's token carries `loginflow.organizations.read` AND
/// `loginflow.organizations.write` (contract C1 of phase 2): reads need `.read`, ensure and
/// delete need `.write`, each checked exactly in the token `scope`.
/// Oracle: the decoded `scope` of the token request behind a `get`, and the GET.
/// Risk edge: a write-only token answered `403 permission_denied` on every organizations read.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: requesting only `loginflow.organizations.write` fails the scope assertion.
#[tokio::test]
async fn a_read_is_sent_with_a_token_that_carries_the_read_and_write_permissions() {
    let server =
        server(|_| Reply::ok(envelope(organization("org-7", "regular", Some("client/7"))))).await;

    let organization = client(&server).get("org-7").await.expect("read");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.organizations.read loginflow.organizations.write"
    );
    let get = server.last();
    assert_eq!(get.method, "GET");
    assert_eq!(get.path(), "/v1/service/organizations/org-7");
    assert_eq!(organization.id, "org-7");
}
