//! `AccessCodesClient`: `/v1/service/access-codes` and `/v1/service/access-subjects/revoke`
//! behind a `client_credentials` token requested with scope `loginflow.accessCodes.issue`, envelope
//! parsing, `409 access_codes_disabled` -> `Conflict { code }`, `422` -> `Validation`, a `204`
//! with no body, and the shared single retry with a fresh token.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    FakeServer, Reply, TOKEN_PATH, api_requests, config_for, envelope, error_body,
    service_door_server as server, token_request_scope,
};
use loginflow_sdk::{
    ACCESS_CODES_DISABLED_CODE, AccessCodesClient, IssueAccessCodeRequest, LoginFlowError,
    SubjectKind,
};
use serde_json::{Value, json};

const CODES_PATH: &str = "/v1/service/access-codes";
const REVOKE_SUBJECT_PATH: &str = "/v1/service/access-subjects/revoke";
const CODE_ID: &str = "0b8f7f0e-6a51-4c55-9b0a-0f2b8f1d2c3e";

fn issued_code() -> Value {
    json!({
        "id": CODE_ID,
        "code": "K7QM-3XRT",
        // `NaiveDateTime` as the API serializes it: UTC, no offset.
        "expires_at": "2026-10-22T09:00:00",
        "subject_kind": "device",
        "external_subject": "kiosk:7",
        "profile": "Kiosk",
    })
}

fn code_info(id: &str, external_subject: &str) -> Value {
    json!({
        "id": id,
        "subject_kind": "person",
        "external_subject": external_subject,
        "profile": "Driver",
        "display_name": null,
        "issued_by": "rutafacil-backend",
        "issued_at": "2026-10-21T09:00:00.123456",
        "expires_at": "2026-10-22T09:00:00.123456",
    })
}

fn client(server: &FakeServer) -> AccessCodesClient {
    AccessCodesClient::new(config_for(server), "rutafacil-backend", "svc-secret").expect("client")
}

fn kiosk_request() -> IssueAccessCodeRequest {
    IssueAccessCodeRequest {
        subject_kind: SubjectKind::Device,
        external_subject: "kiosk:7".into(),
        profile: "Kiosk".into(),
        display_name: None,
        ttl_minutes: None,
        revoke_existing_sessions: None,
    }
}

/// TEST_CHARTER
/// Requirement: the token is requested with `grant_type=client_credentials` and scope
/// `loginflow.accessCodes.issue`; `issue` posts the contract body (absent optionals omitted, since the
/// server rejects unknown fields and must apply its own defaults) to `/v1/service/access-codes`
/// with that token and returns the `201` envelope's code, shown once.
/// Oracle: the token request's form body, the API request recorded by the fake server, and the
/// returned `IssuedAccessCode`.
/// Risk edge: a token without `loginflow.accessCodes.issue` is refused on every call; a `null`
/// `ttl_minutes` sent instead of omitted would not use the application default.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: requesting another scope fails the scope assertion; dropping
/// `skip_serializing_if` fails the body assertion.
#[tokio::test]
async fn issue_requests_an_access_codes_token_and_returns_the_code_once() {
    let server = server(|_| Reply::status(201, envelope(issued_code()))).await;

    let issued = client(&server)
        .issue(kiosk_request())
        .await
        .expect("issued");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke"
    );

    let issue = server.last();
    assert_eq!(issue.method, "POST");
    assert_eq!(issue.path(), CODES_PATH);
    assert_eq!(issue.header("authorization"), Some("Bearer token-1"));
    assert_eq!(
        issue.json(),
        json!({ "subject_kind": "device", "external_subject": "kiosk:7", "profile": "Kiosk" })
    );

    assert_eq!(issued.id, CODE_ID);
    assert_eq!(issued.code, "K7QM-3XRT");
    assert_eq!(issued.expires_at, "2026-10-22T09:00:00");
    assert_eq!(issued.subject_kind, SubjectKind::Device.to_string());
    assert_eq!(issued.external_subject, "kiosk:7");
    assert_eq!(issued.profile, "Kiosk");
}

#[tokio::test]
async fn issue_sends_the_optional_fields_when_set() {
    let server = server(|_| Reply::status(201, envelope(issued_code()))).await;

    client(&server)
        .issue(IssueAccessCodeRequest {
            subject_kind: SubjectKind::Person,
            external_subject: "driver:42".into(),
            profile: "Driver".into(),
            display_name: Some("Bus 12".into()),
            ttl_minutes: Some(420),
            revoke_existing_sessions: Some(true),
        })
        .await
        .expect("issued");

    assert_eq!(
        server.last().json(),
        json!({
            "subject_kind": "person",
            "external_subject": "driver:42",
            "profile": "Driver",
            "display_name": "Bus 12",
            "ttl_minutes": 420,
            "revoke_existing_sessions": true,
        })
    );
}

/// TEST_CHARTER
/// Requirement: `list`, `revoke` and `revoke_subject_sessions` hit the contract routes:
/// `GET /v1/service/access-codes` (with `external_subject` percent-encoded when given),
/// `DELETE /v1/service/access-codes/{id}` answered `204` with no body, and
/// `POST /v1/service/access-subjects/revoke {external_subject}`.
/// Oracle: the recorded requests and the parsed answers.
/// Risk edge: a `204` parsed as an envelope fails a successful revoke; an unencoded `:` or `&`
/// in an external subject changes the query.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: parsing the `204` through the envelope returns `Err`; dropping the encoding
/// fails the target assertion.
#[tokio::test]
async fn list_revoke_and_revoke_subject_hit_the_contract_routes() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("GET", CODES_PATH) => Reply::ok(envelope(json!([
            code_info("c-1", "driver:42"),
            code_info("c-2", "driver:43"),
        ]))),
        ("DELETE", path) if path == format!("{CODES_PATH}/{CODE_ID}") => Reply::status(204, ""),
        ("POST", REVOKE_SUBJECT_PATH) => Reply::ok(envelope(json!({ "revoked_sessions": 3 }))),
        _ => Reply::status(404, error_body("NOT_FOUND", "no route")),
    })
    .await;
    let codes = client(&server);

    let all = codes.list(None).await.expect("list");
    assert_eq!(server.last().target, CODES_PATH);
    assert_eq!(
        all.iter().map(|code| code.id.as_str()).collect::<Vec<_>>(),
        ["c-1", "c-2"]
    );
    assert_eq!(all[0].issued_by, "rutafacil-backend");
    assert_eq!(all[0].issued_at, "2026-10-21T09:00:00.123456");
    assert_eq!(all[0].display_name, None);

    codes
        .list(Some("driver:42&x"))
        .await
        .expect("filtered list");
    assert_eq!(
        server.last().target,
        format!("{CODES_PATH}?external_subject=driver%3A42%26x")
    );

    codes.revoke(CODE_ID).await.expect("revoked");
    let revoke = server.last();
    assert_eq!(revoke.method, "DELETE");
    assert_eq!(revoke.path(), format!("{CODES_PATH}/{CODE_ID}"));

    let revoked = codes
        .revoke_subject_sessions("driver:42")
        .await
        .expect("subject revoked");
    assert_eq!(revoked.revoked_sessions, 3);
    assert_eq!(
        server.last().json(),
        json!({ "external_subject": "driver:42" })
    );

    // One token served every call.
    assert_eq!(server.hits(TOKEN_PATH), 1);
}

/// TEST_CHARTER
/// Requirement: `409 access_codes_disabled` surfaces as `Conflict` carrying that code, so the
/// issuer can tell "the application has access codes off" apart from any other failure.
/// Oracle: the `Err` returned by `issue`.
/// Risk edge: the code being lost (a generic error) leaves the issuer unable to explain why.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: removing the `409` arm of `LoginFlowError::from_status` fails the match.
#[tokio::test]
async fn disabled_application_is_a_conflict_with_its_code() {
    let server = server(|_| {
        Reply::status(
            409,
            error_body(
                ACCESS_CODES_DISABLED_CODE,
                "Access codes are disabled for this application",
            ),
        )
    })
    .await;

    let result = client(&server).issue(kiosk_request()).await;

    match result {
        Err(LoginFlowError::Conflict { code, .. }) => {
            assert_eq!(code.as_deref(), Some(ACCESS_CODES_DISABLED_CODE));
        }
        other => panic!("expected a Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn out_of_range_ttl_is_a_validation_error() {
    let server = server(|_| {
        Reply::status(
            422,
            error_body("VALIDATION_ERROR", "ttl_minutes must be within 420..=7200"),
        )
    })
    .await;

    let mut request = kiosk_request();
    request.ttl_minutes = Some(60);
    let result = client(&server).issue(request).await;

    assert!(
        matches!(&result, Err(LoginFlowError::Validation(_))),
        "{result:?}"
    );
}

/// TEST_CHARTER
/// Requirement: the shared machine door retries exactly once with a fresh token when the API
/// rejects the cached one, also on a call answered with no body (`DELETE`, `204`).
/// Oracle: two `DELETE`s carrying `token-1` then `token-2`, and `Ok(())`.
/// Risk edge: a revoked or re-scoped token cached until its `expires_in` would fail every
/// revoke; the retry living only in the `data` path would leave `revoke` without it.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: without the retry the call returns `Err(Authentication)` after one hit.
#[tokio::test]
async fn rejected_token_is_replaced_and_a_revoke_retried_once() {
    let api_calls = Arc::new(AtomicUsize::new(0));
    let calls = api_calls.clone();
    let server = server(move |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::status(
                401,
                error_body("UNAUTHORIZED", "Authentication is required."),
            )
        } else {
            Reply::status(204, "")
        }
    })
    .await;

    client(&server)
        .revoke(CODE_ID)
        .await
        .expect("retried with a fresh token");

    let api = api_requests(&server);
    assert_eq!(api.len(), 2);
    assert_eq!(api[0].header("authorization"), Some("Bearer token-1"));
    assert_eq!(api[1].header("authorization"), Some("Bearer token-2"));
    assert_eq!(server.hits(TOKEN_PATH), 2);
}

/// TEST_CHARTER
/// Requirement: the key's token carries `loginflow.accessCodes.issue`, `.read` AND `.revoke`
/// (contract C1 of phase 2): issuing needs `.issue`, listing `.read`, and deleting a code or
/// revoking a subject `.revoke`, each checked exactly in the token `scope`.
/// Oracle: the decoded `scope` of the token request behind a `revoke`, and the DELETE.
/// Risk edge: an issue-only token answered `403 permission_denied` on every revoke and list.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: requesting only `loginflow.accessCodes.issue` fails the scope assertion.
#[tokio::test]
async fn a_revoke_is_sent_with_a_token_that_carries_the_issue_read_and_revoke_permissions() {
    let server = server(|_| Reply::status(204, "")).await;

    client(&server).revoke(CODE_ID).await.expect("revoked");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke"
    );
    let delete = server.last();
    assert_eq!(delete.method, "DELETE");
    assert_eq!(delete.path(), format!("{CODES_PATH}/{CODE_ID}"));
}
