//! `MembersClient`: `/v1/service/members` behind a `loginflow.assignments.write` token — the
//! key's grantable roles, grant to a person or an access-code subject, list by filter, revoke —
//! and the coded refusals of the delegation rules, exactly as `loginflow_api` answers them.

mod common;

use chrono::{TimeZone, Utc};
use common::{
    Reply, config_for, envelope, error_body, service_door_server as server, token_request_scope,
};
use loginflow_sdk::{GrantMember, LoginFlowError, MemberFilter, MembersClient, Principal};
use serde_json::{Value, json};

/// An `Assignment` as the API serializes it: `NaiveDateTime` instants without an offset, and a
/// subject principal that also carries its LoginFlow `id`.
fn assignment(id: &str, principal: Value) -> Value {
    json!({
        "id": id, "organization_id": "org-7", "role_key": "driver", "principal": principal,
        "granted_by": { "kind": "client", "id": "drivers-api" },
        "expires_at": null, "created_at": "2026-10-23T09:00:00",
    })
}

/// The API's coded refusal envelope: `{"error": {"code", "message", "details"?}, "meta"}`.
fn refusal(code: &str, details: Option<Value>) -> String {
    let mut error = json!({ "code": code, "message": "refused" });
    if let Some(details) = details {
        error["details"] = details;
    }
    json!({ "error": error, "meta": { "status": 403 } }).to_string()
}

fn client(server: &common::FakeServer) -> MembersClient {
    MembersClient::new(config_for(server), "drivers-api", "secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: `grant` POSTs `{organization_id, role_key, principal, expires_at?}` to
/// `/v1/service/members` with a `loginflow.assignments.write` token; the principal is
/// `{"kind":"company_user","id"}` or `{"kind":"access_subject","external_subject"}`; the
/// answer (with the subject's extra `id`) parses back into the same `Principal`.
/// Oracle: the token scope, the recorded path and JSON bodies, and the returned assignments.
/// Risk edge: a route the server no longer mounts (every grant `404`), or a principal
/// shape the server refuses (`deny_unknown_fields`: `400`).
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: pointing the client at any other collection path fails the path assertion;
/// an `expires_at` sent without an RFC 3339 offset fails the body assertion.
#[tokio::test]
async fn grant_posts_to_the_members_route_in_the_contract_shape() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("POST", "/v1/service/members") => {
            let principal = match req.json()["principal"].clone() {
                Value::Object(mut principal) if principal["kind"] == "access_subject" => {
                    principal.insert("id".into(), json!("AS-1"));
                    Value::Object(principal)
                }
                principal => principal,
            };
            Reply::status(201, envelope(assignment("as-1", principal)))
        }
        _ => Reply::status(404, error_body("NOT_FOUND", "No route")),
    })
    .await;
    let members = client(&server);

    let person = members
        .grant(&GrantMember {
            organization_id: "org-7".into(),
            role_key: "client_admin".into(),
            principal: Principal::CompanyUser("CU-1".into()),
            expires_at: Some(
                Utc.with_ymd_and_hms(2026, 12, 31, 0, 0, 0)
                    .single()
                    .expect("date"),
            ),
        })
        .await
        .expect("granted");
    assert_eq!(
        token_request_scope(&server),
        "loginflow.assignments.read loginflow.assignments.write"
    );
    let post = server.last();
    assert_eq!(post.method, "POST");
    assert_eq!(post.path(), "/v1/service/members");
    assert_eq!(
        post.json(),
        json!({
            "organization_id": "org-7",
            "role_key": "client_admin",
            "principal": { "kind": "company_user", "id": "CU-1" },
            "expires_at": "2026-12-31T00:00:00Z",
        })
    );
    assert_eq!(person.principal, Principal::CompanyUser("CU-1".into()));
    assert_eq!(person.granted_by.kind, "client");
    assert_eq!(person.created_at, "2026-10-23T09:00:00");

    let subject = members
        .grant(&GrantMember {
            organization_id: "org-7".into(),
            role_key: "driver".into(),
            principal: Principal::AccessSubject {
                external_subject: "driver:42".into(),
            },
            expires_at: None,
        })
        .await
        .expect("granted");
    assert_eq!(
        server.last().json(),
        json!({
            "organization_id": "org-7",
            "role_key": "driver",
            "principal": { "kind": "access_subject", "external_subject": "driver:42" },
        })
    );
    assert_eq!(
        subject.principal,
        Principal::AccessSubject {
            external_subject: "driver:42".into()
        }
    );
}

/// TEST_CHARTER
/// Requirement: `grantable_roles` reads `GET /v1/service/members/grantable-roles`, `list` sends
/// only the filters set to `GET /v1/service/members`, `revoke` deletes
/// `/v1/service/members/assignments/{id}` (`204`).
/// Oracle: the routes the fake API answers and the parsed values.
/// Risk edge: a revoke aimed at `/v1/service/members/{id}` (no such route: every revoke `404`).
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: dropping the `assignments/` segment of the revoke path makes it `NotFound`.
#[tokio::test]
async fn grantable_roles_list_and_revoke_hit_the_members_routes() {
    let server = server(|req| match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/v1/service/members/grantable-roles") => Reply::ok(envelope(json!([
            { "id": "role-1", "key": "driver", "name": "Conductor", "description": null },
        ]))),
        ("GET", "/v1/service/members?organization_id=org-7&external_subject=driver%3A42") => {
            Reply::ok(envelope(json!({
                "items": [assignment("as-1", json!({ "kind": "access_subject", "id": "AS-1", "external_subject": "driver:42" }))],
                "total": 1,
            })))
        }
        ("DELETE", "/v1/service/members/assignments/as-1") => Reply::status(204, ""),
        _ => Reply::status(404, refusal("assignment_not_found", None)),
    })
    .await;
    let members = client(&server);

    let roles = members.grantable_roles().await.expect("grantable roles");
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].key, "driver");
    assert_eq!(roles[0].description, None);

    let page = members
        .list(&MemberFilter {
            organization_id: Some("org-7".into()),
            external_subject: Some("driver:42".into()),
            ..MemberFilter::default()
        })
        .await
        .expect("list");
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].id, "as-1");

    members.revoke("as-1").await.expect("revoked");
    assert!(matches!(
        members.revoke("as-9").await,
        Err(LoginFlowError::NotFound { .. })
    ));
}

/// TEST_CHARTER
/// Requirement: every `403` refusal of the delegation rules reaches the caller as
/// `LoginFlowError::Authorization` with the server's `code`, so a product tells
/// `role_not_grantable` from `privilege_exceeds_grantor` without parsing text; the other
/// statuses keep their typed variants.
/// Oracle: the `code` of each returned error.
/// Risk edge: every refusal collapses into one untyped "forbidden".
/// Layer: integration against the in-process `FakeServer` (the API's envelope byte for byte).
/// Counterfactual: `from_status` dropping `error.code` for a `403`, `404`, `409` or `422` fails
/// that status's `code` assertion.
#[tokio::test]
async fn refusals_carry_the_servers_code() {
    let server = server(|req| {
        let role = req.json()["role_key"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        match role.as_str() {
            "member_not_found" => Reply::status(404, refusal("member_not_found", None)),
            "expires_at_in_past" => Reply::status(422, refusal("expires_at_in_past", None)),
            "system_application" => Reply::status(409, refusal("system_application", None)),
            "privilege_exceeds_grantor" => Reply::status(
                403,
                refusal(&role, Some(json!({ "dimension": "permissions" }))),
            ),
            _ => Reply::status(403, refusal(&role, None)),
        }
    })
    .await;
    let members = client(&server);
    let grant = |role_key: &str| GrantMember {
        organization_id: "org-7".into(),
        role_key: role_key.into(),
        principal: Principal::CompanyUser("CU-1".into()),
        expires_at: None,
    };

    for code in [
        "role_not_grantable",
        "organization_out_of_reach",
        "privilege_exceeds_grantor",
        "self_assignment_forbidden",
        "permission_denied",
    ] {
        let refused = members.grant(&grant(code)).await;
        assert!(
            matches!(&refused, Err(LoginFlowError::Authorization { code: Some(c), .. }) if c == code),
            "{code}: {refused:?}"
        );
    }
    let not_found = members.grant(&grant("member_not_found")).await;
    assert!(
        matches!(&not_found, Err(LoginFlowError::NotFound { code: Some(c), .. }) if c == "member_not_found"),
        "{not_found:?}"
    );
    let invalid = members.grant(&grant("expires_at_in_past")).await;
    assert!(
        matches!(&invalid, Err(LoginFlowError::Validation { code: Some(c), .. }) if c == "expires_at_in_past"),
        "{invalid:?}"
    );
    let conflict = members.grant(&grant("system_application")).await;
    assert!(
        matches!(&conflict, Err(LoginFlowError::Conflict { code: Some(c), .. }) if c == "system_application"),
        "{conflict:?}"
    );
}

/// TEST_CHARTER
/// Requirement: a grant's `expires_at` is an instant with an RFC 3339 offset — the API reads it
/// as `DateTime<Utc>` and refuses a naive date-time — so a naive value can be neither built nor
/// sent through the SDK.
/// Oracle: building a `GrantMember` from JSON with a naive `expires_at` is an error; with the
/// same instant in UTC (`Z`) it succeeds.
/// Risk edge: a product grants an expiring assignment and LoginFlow answers `400` for a value the
/// SDK accepted.
/// Layer: the public model's serde contract (the wire format itself is asserted over HTTP above).
/// Counterfactual: an `expires_at` that accepts any string (or a naive date-time) builds the naive
/// value and fails the first assertion.
#[test]
fn a_naive_expiry_cannot_be_built() {
    let body = |expires_at: &str| {
        json!({
            "organization_id": "org-7",
            "role_key": "driver",
            "principal": { "kind": "company_user", "id": "CU-1" },
            "expires_at": expires_at,
        })
    };

    let naive = serde_json::from_value::<GrantMember>(body("2026-12-31T00:00:00"));
    assert!(naive.is_err(), "a naive expiry was accepted: {naive:?}");

    let utc = serde_json::from_value::<GrantMember>(body("2026-12-31T00:00:00Z"))
        .expect("an RFC 3339 instant in UTC");
    assert_eq!(
        serde_json::to_value(&utc).expect("body"),
        body("2026-12-31T00:00:00Z")
    );
}

/// TEST_CHARTER
/// Requirement: the key's token carries `loginflow.assignments.read` AND
/// `loginflow.assignments.write` (contract C1 of phase 2): `GET /v1/service/members*` needs
/// `.read`, grant and revoke need `.write`, each checked exactly in the token `scope`.
/// Oracle: the decoded `scope` of the token request behind `grantable_roles`, and the GET.
/// Risk edge: a write-only token answered `403 permission_denied` on every members read.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: requesting only `loginflow.assignments.write` fails the scope assertion.
#[tokio::test]
async fn a_read_is_sent_with_a_token_that_carries_the_read_and_write_permissions() {
    let server = server(|_| {
        Reply::ok(envelope(json!([
            { "id": "role-1", "key": "driver", "name": "Driver", "description": null }
        ])))
    })
    .await;

    let roles = client(&server).grantable_roles().await.expect("read");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.assignments.read loginflow.assignments.write"
    );
    let get = server.last();
    assert_eq!(get.method, "GET");
    assert_eq!(get.path(), "/v1/service/members/grantable-roles");
    assert_eq!(roles.len(), 1);
}
