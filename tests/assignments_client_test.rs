//! `AssignmentsClient`: `/v1/service/assignments` behind a `loginflow.assignments.write` token —
//! grant to a person or an access-code subject, list by filter, revoke.

mod common;

use chrono::{TimeZone, Utc};
use common::{
    Reply, config_for, envelope, error_body, service_door_server as server, token_request_body,
};
use loginflow_sdk::{
    AssignmentFilter, AssignmentsClient, GrantAssignment, LoginFlowError, Principal,
};
use serde_json::{Value, json};

fn assignment(id: &str, principal: Value) -> Value {
    json!({
        "id": id, "organization_id": "org-7", "role_key": "driver", "principal": principal,
        "granted_by": { "kind": "client", "id": "drivers-api" },
        "expires_at": null, "created_at": "2026-10-22T09:00:00",
    })
}

fn client(server: &common::FakeServer) -> AssignmentsClient {
    AssignmentsClient::new(config_for(server), "drivers-api", "secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: `grant` POSTs `{organization_id, role_key, principal, expires_at?}` with a
/// `loginflow.assignments.write` token; the principal is `{"kind":"company_user","id"}` or
/// `{"kind":"access_subject","external_subject"}`; the answer parses back into the same
/// `Principal`.
/// Oracle: the token scope, the recorded JSON bodies and the returned `Assignment`s.
/// Risk edge: a principal shape the server does not accept (every grant `422`) or a
/// subject granted by the wrong id.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: serializing `Principal` externally tagged (`{"CompanyUser": ...}`) fails the
/// body assertions; an `expires_at` sent without an RFC 3339 offset (the API's
/// `DateTime<Utc>` refuses it, so every grant with an expiry is a `400`) fails the body assertion.
#[tokio::test]
async fn grant_sends_the_principal_in_the_contract_shape() {
    let server = server(|req| {
        let principal = req.json()["principal"].clone();
        Reply::status(201, envelope(assignment("as-1", principal)))
    })
    .await;
    let assignments = client(&server);

    let person = assignments
        .grant(GrantAssignment {
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
    let token_body = token_request_body(&server);
    assert!(
        token_body.contains("scope=loginflow.assignments.write"),
        "{token_body}"
    );
    let post = server.last();
    assert_eq!(post.method, "POST");
    assert_eq!(post.path(), "/v1/service/assignments");
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

    let subject = assignments
        .grant(GrantAssignment {
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

#[tokio::test]
async fn list_sends_only_the_filters_set_and_revoke_deletes() {
    let server = server(|req| match (req.method.as_str(), req.target.as_str()) {
        ("GET", "/v1/service/assignments?organization_id=org-7&external_subject=driver%3A42") => {
            Reply::ok(envelope(json!({
                "items": [assignment("as-1", json!({ "kind": "access_subject", "external_subject": "driver:42" }))],
                "total": 1,
            })))
        }
        ("DELETE", "/v1/service/assignments/as-1") => Reply::status(204, ""),
        _ => Reply::status(404, error_body("NOT_FOUND", "Assignment not found")),
    })
    .await;
    let assignments = client(&server);

    let page = assignments
        .list(AssignmentFilter {
            organization_id: Some("org-7".into()),
            external_subject: Some("driver:42".into()),
            ..AssignmentFilter::default()
        })
        .await
        .expect("list");
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].id, "as-1");

    assignments.revoke("as-1").await.expect("revoked");
    assert!(matches!(
        assignments.revoke("as-9").await,
        Err(LoginFlowError::NotFound(_))
    ));
}

/// A principal outside the tenant is `404`, a principal without a membership `422`: both reach
/// the caller typed.
#[tokio::test]
async fn grant_maps_not_found_and_validation() {
    let server = server(|req| {
        if req.json()["principal"]["id"] == json!("CU-other-tenant") {
            Reply::status(404, error_body("NOT_FOUND", "Principal not found"))
        } else {
            Reply::status(422, error_body("VALIDATION", "No active membership"))
        }
    })
    .await;
    let assignments = client(&server);
    let grant = |id: &str| GrantAssignment {
        organization_id: "org-7".into(),
        role_key: "driver".into(),
        principal: Principal::CompanyUser(id.into()),
        expires_at: None,
    };

    assert!(matches!(
        assignments.grant(grant("CU-other-tenant")).await,
        Err(LoginFlowError::NotFound(_))
    ));
    assert!(matches!(
        assignments.grant(grant("CU-no-membership")).await,
        Err(LoginFlowError::Validation(_))
    ));
}

/// TEST_CHARTER
/// Requirement: a grant's `expires_at` is an instant with an RFC 3339 offset — the API reads it
/// as `DateTime<Utc>` and refuses a naive date-time — so a naive value can be neither built nor
/// sent through the SDK.
/// Oracle: building a `GrantAssignment` from JSON with a naive `expires_at` is an error; with the
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

    let naive = serde_json::from_value::<GrantAssignment>(body("2026-12-31T00:00:00"));
    assert!(naive.is_err(), "a naive expiry was accepted: {naive:?}");

    let utc = serde_json::from_value::<GrantAssignment>(body("2026-12-31T00:00:00Z"))
        .expect("an RFC 3339 instant in UTC");
    assert_eq!(
        serde_json::to_value(&utc).expect("body"),
        body("2026-12-31T00:00:00Z")
    );
}
