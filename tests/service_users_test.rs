//! `ServiceUsersClient`: `/v1/service/users` behind a `client_credentials` token requested with
//! scope `loginflow.users.write`, envelope parsing, `409` -> `Conflict { code }`, and exactly one retry
//! with a fresh token when the API rejects the cached one.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{
    FakeServer, Reply, TOKEN_PATH, api_requests, config_for, envelope, error_body,
    service_door_server as server, token_request_scope,
};
use loginflow_sdk::{
    CreateServiceUserRequest, InvitationStatus, LoginFlowError, ServiceUsersClient,
};
use serde_json::{Value, json};

const USERS_PATH: &str = "/v1/service/users";

fn service_user(id: &str, email: &str) -> Value {
    json!({
        "id": id,
        "email": email,
        "first_name": "Ana",
        "last_name": null,
        "is_active": true,
        "email_verified": false,
        // `NaiveDateTime` as the API serializes it: UTC, no offset.
        "created_at": "2026-10-20T10:00:00.123456",
        "last_login_at": null,
    })
}

fn client(server: &FakeServer) -> ServiceUsersClient {
    ServiceUsersClient::new(config_for(server), "billing-service", "svc-secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: the token is requested with `grant_type=client_credentials`, scope
/// `loginflow.users.write` and `client_secret_basic`, and every API call carries it as a Bearer token;
/// `create` posts the contract body to `/v1/service/users` and parses the `{data, meta}`
/// envelope into a `ServiceUser`.
/// Oracle: the token request's form body / `Authorization`, the API request recorded by the
/// fake server, and the returned `ServiceUser`.
/// Risk edge: a token without `loginflow.users.write` is refused by the server on every call.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: requesting any other scope (the retired pre-0.11 one) fails the scope
/// assertion; serializing a `role` fails the body assertion.
#[tokio::test]
async fn create_requests_a_users_write_token_and_parses_the_envelope() {
    let server =
        server(|_| Reply::status(201, envelope(service_user("CU-1", "ana@example.com")))).await;

    let user = client(&server)
        .create(CreateServiceUserRequest {
            email: "ana@example.com".into(),
            first_name: Some("Ana".into()),
            last_name: None,
            send_invitation: false,
        })
        .await
        .expect("created");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.users.read loginflow.users.write"
    );

    let create = server.last();
    assert_eq!(create.method, "POST");
    assert_eq!(create.path(), USERS_PATH);
    assert_eq!(create.header("authorization"), Some("Bearer token-1"));
    assert_eq!(
        create.json(),
        json!({ "email": "ana@example.com", "first_name": "Ana" })
    );

    assert_eq!(user.id, "CU-1");
    assert_eq!(user.email, "ana@example.com");
    assert_eq!(user.first_name.as_deref(), Some("Ana"));
    assert_eq!(user.last_name, None);
    assert!(user.is_active);
    assert!(!user.email_verified);
    assert_eq!(user.created_at, "2026-10-20T10:00:00.123456");
    assert_eq!(user.last_login_at, None);
}

#[tokio::test]
async fn list_get_and_set_active_hit_the_contract_routes() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("GET", USERS_PATH) => Reply::ok(envelope(json!([
            service_user("CU-1", "ana@example.com"),
            service_user("CU-2", "bo@example.com"),
        ]))),
        ("GET", "/v1/service/users/CU-1") => {
            Reply::ok(envelope(service_user("CU-1", "ana@example.com")))
        }
        ("PATCH", "/v1/service/users/CU-1") => {
            let mut user = service_user("CU-1", "ana@example.com");
            user["is_active"] = json!(false);
            user["last_login_at"] = json!("2026-10-20T10:05:00");
            Reply::ok(envelope(user))
        }
        _ => Reply::status(404, error_body("NOT_FOUND", "no route")),
    })
    .await;
    let users = client(&server);

    let listed = users.list().await.expect("list");
    assert_eq!(
        listed
            .iter()
            .map(|user| user.id.as_str())
            .collect::<Vec<_>>(),
        ["CU-1", "CU-2"]
    );

    assert_eq!(users.get("CU-1").await.expect("get").id, "CU-1");

    let deactivated = users.set_active("CU-1", false).await.expect("set_active");
    assert!(!deactivated.is_active);
    assert_eq!(
        deactivated.last_login_at.as_deref(),
        Some("2026-10-20T10:05:00")
    );
    assert_eq!(server.last().json(), json!({ "is_active": false }));

    // One token served every call.
    assert_eq!(server.hits(TOKEN_PATH), 1);
}

/// TEST_CHARTER
/// Requirement: a `409` surfaces as `LoginFlowError::Conflict` carrying the envelope's
/// `error.code`, so a caller can tell one conflict apart from another.
/// Oracle: the `Err` returned by `delete`.
/// Risk edge: without a `409` arm the error degrades to `Network("HTTP 409 ...")` and the code
/// is lost.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: removing the `409` arm of `LoginFlowError::from_status` fails the match.
#[tokio::test]
async fn conflict_carries_the_server_error_code() {
    let server = server(|_| {
        Reply::status(
            409,
            error_body("CONFLICT", "Other data depends on this membership"),
        )
    })
    .await;

    let result = client(&server).delete("CU-1").await;

    match result {
        Err(LoginFlowError::Conflict { message, code }) => {
            assert_eq!(code.as_deref(), Some("CONFLICT"));
            assert_eq!(message, "Other data depends on this membership");
        }
        other => panic!("expected a Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn not_found_user_is_not_found() {
    let server = server(|_| Reply::status(404, error_body("NOT_FOUND", "User not found"))).await;

    let result = client(&server).get("CU-404").await;

    assert!(
        matches!(&result, Err(LoginFlowError::NotFound { .. })),
        "{result:?}"
    );
}

/// TEST_CHARTER
/// Requirement: when the API rejects the cached token (`401`, code `UNAUTHORIZED`), the client
/// drops it, fetches a fresh token and resends the request exactly once.
/// Oracle: the second API request carries `token-2`, the call succeeds, and the token endpoint
/// and the API were each hit exactly twice.
/// Risk edge: a revoked or re-scoped token cached for up to its `expires_in` would otherwise
/// fail every call until it expires.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: without the retry the call returns `Err(Authentication)` after one API hit;
/// without the invalidation the resend carries `token-1` again.
#[tokio::test]
async fn rejected_token_is_replaced_and_the_request_retried_once() {
    let api_calls = Arc::new(AtomicUsize::new(0));
    let calls = api_calls.clone();
    let server = server(move |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::status(
                401,
                error_body("UNAUTHORIZED", "Authentication is required."),
            )
        } else {
            Reply::ok(envelope(json!([])))
        }
    })
    .await;

    let listed = client(&server)
        .list()
        .await
        .expect("retried with a fresh token");

    assert!(listed.is_empty());
    let api = api_requests(&server);
    assert_eq!(api.len(), 2);
    assert_eq!(api[0].header("authorization"), Some("Bearer token-1"));
    assert_eq!(api[1].header("authorization"), Some("Bearer token-2"));
    assert_eq!(server.hits(TOKEN_PATH), 2);
}

/// Exactly once: a token rejected again after the refresh is an error, not a loop.
#[tokio::test]
async fn a_second_rejection_is_returned_without_another_retry() {
    let server = server(|_| {
        Reply::status(
            401,
            error_body("UNAUTHORIZED", "Authentication is required."),
        )
    })
    .await;

    let result = client(&server).list().await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication { .. })),
        "{result:?}"
    );
    assert_eq!(api_requests(&server).len(), 2);
    assert_eq!(server.hits(TOKEN_PATH), 2);
}

/// A `401` whose envelope code is not `UNAUTHORIZED` is about the request itself, not the token:
/// it is returned at once, never resent with a fresh token. `INVALID_CODE` (a code the user typed)
/// is a `Validation` error.
#[tokio::test]
async fn a_401_about_the_request_is_not_retried() {
    let server =
        server(|_| Reply::status(401, error_body("INVALID_CODE", "Invalid or expired code"))).await;

    let result = client(&server).list().await;

    assert!(
        matches!(&result, Err(LoginFlowError::Validation { message, code: Some(code) })
            if message == "Invalid or expired code" && code == "INVALID_CODE"),
        "{result:?}"
    );
    assert_eq!(api_requests(&server).len(), 1);
    assert_eq!(server.hits(TOKEN_PATH), 1);
}

#[tokio::test]
async fn invalidate_token_forces_a_new_token_fetch() {
    let server = server(|_| Reply::ok(envelope(json!([])))).await;
    let users = client(&server);

    users.list().await.expect("first");
    users.invalidate_token().await;
    users.list().await.expect("second");

    assert_eq!(server.hits(TOKEN_PATH), 2);
    assert_eq!(
        server.last().header("authorization"),
        Some("Bearer token-2")
    );
}

/// TEST_CHARTER
/// Requirement: `delete` sends `DELETE /v1/service/users/{id}` with the machine token and
/// parses `{id, profile_deleted}`; a `409` (something depends on the membership) is a
/// `Conflict` and an unknown id is `NotFound`
/// (loginflow_api `docs/api/v1/service/users/delete.md`).
/// Oracle: the request the fake server recorded and the value / error returned.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: without `delete` this does not compile; a wrong method or path answers 404.
#[tokio::test]
async fn delete_hits_the_contract_route_and_maps_conflict_and_not_found() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("DELETE", "/v1/service/users/CU-1") => Reply::ok(envelope(json!({
            "id": "CU-1",
            "profile_deleted": true,
        }))),
        ("DELETE", "/v1/service/users/CU-2") => Reply::status(
            409,
            error_body(
                "CONFLICT",
                "The account cannot be permanently deleted because other data depends on it",
            ),
        ),
        _ => Reply::status(404, error_body("NOT_FOUND", "User not found")),
    })
    .await;
    let users = client(&server);

    let deleted = users.delete("CU-1").await.expect("delete");
    assert_eq!(deleted.id, "CU-1");
    assert!(deleted.profile_deleted);
    assert_eq!(server.last().method, "DELETE");

    assert!(matches!(
        users.delete("CU-2").await,
        Err(LoginFlowError::Conflict { .. })
    ));
    assert!(matches!(
        users.delete("CU-9").await,
        Err(LoginFlowError::NotFound { .. })
    ));
}

/// TEST_CHARTER
/// Requirement: `create` with `send_invitation: true` asks the API for the invitation email
/// (`"send_invitation": true` in the body) and exposes the `invitation` outcome of the `201`;
/// with `false` the field is not sent at all (the body of older SDK versions).
/// Oracle: the API request body recorded by the fake server and the returned `ServiceUser`.
/// Counterfactual: a field never serialized, or always serialized, fails one of the two bodies.
#[tokio::test]
async fn create_sends_send_invitation_only_when_true_and_parses_the_outcome() {
    let server = server(|req| {
        let mut user = service_user("CU-1", "ana@example.com");
        if req.json()["send_invitation"] == json!(true) {
            user["invitation"] = json!("sent");
        }
        Reply::status(201, envelope(user))
    })
    .await;
    let users = client(&server);
    let request = |send_invitation| CreateServiceUserRequest {
        email: "ana@example.com".into(),
        first_name: None,
        last_name: None,
        send_invitation,
    };

    let invited = users.create(request(true)).await.expect("created");
    assert_eq!(
        server.last().json(),
        json!({ "email": "ana@example.com", "send_invitation": true })
    );
    assert_eq!(invited.invitation, Some(InvitationStatus::Sent));

    let quiet = users.create(request(false)).await.expect("created");
    assert_eq!(server.last().json(), json!({ "email": "ana@example.com" }));
    assert_eq!(quiet.invitation, None);
}

/// An invitation outcome this SDK does not know never fails the create's parsing.
#[tokio::test]
async fn an_unknown_invitation_outcome_is_unknown() {
    let server = server(|_| {
        let mut user = service_user("CU-1", "ana@example.com");
        user["invitation"] = json!("queued");
        Reply::status(201, envelope(user))
    })
    .await;

    let user = client(&server)
        .create(CreateServiceUserRequest {
            email: "ana@example.com".into(),
            first_name: None,
            last_name: None,
            send_invitation: true,
        })
        .await
        .expect("created");

    assert_eq!(user.invitation, Some(InvitationStatus::Unknown));
}

/// TEST_CHARTER
/// Requirement: `not_needed` (the person already had an account; LoginFlow's shared
/// `InvitationStatus` gained it with the members API) is a known outcome, not `Unknown`.
/// Oracle: the parsed outcome serializes back to the same wire value.
/// Risk edge: a product treats an existing person's invitation as a failure it does not
/// understand.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: without the variant, `#[serde(other)]` parses it as `Unknown`, which
/// serializes as `"unknown"` and fails the assertion.
#[tokio::test]
async fn a_not_needed_invitation_outcome_is_known() {
    let server = server(|_| {
        let mut user = service_user("CU-1", "ana@example.com");
        user["invitation"] = json!("not_needed");
        Reply::status(201, envelope(user))
    })
    .await;

    let user = client(&server)
        .create(CreateServiceUserRequest {
            email: "ana@example.com".into(),
            first_name: None,
            last_name: None,
            send_invitation: true,
        })
        .await
        .expect("created");

    assert_eq!(
        serde_json::to_value(user.invitation).expect("serialize"),
        json!("not_needed")
    );
}

/// TEST_CHARTER
/// Requirement: the key's token carries `loginflow.users.read` AND `loginflow.users.write`
/// (contract C1 of phase 2): the API checks each route's exact permission in the token `scope`,
/// so a read (`GET /v1/service/users/{id}`, how a product makes a person's local record) needs
/// `.read` and a write needs `.write`.
/// Oracle: the decoded `scope` of the token request behind a `get`, and the GET it authorizes.
/// Risk edge: a write-only token answered `403 permission_denied` on every read route.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: requesting only `loginflow.users.write` fails the scope assertion.
#[tokio::test]
async fn a_read_is_sent_with_a_token_that_carries_the_read_and_write_permissions() {
    let server = server(|_| Reply::ok(envelope(service_user("CU-1", "ana@example.com")))).await;

    let user = client(&server).get("CU-1").await.expect("read");

    assert_eq!(
        token_request_scope(&server),
        "loginflow.users.read loginflow.users.write"
    );
    let get = server.last();
    assert_eq!(get.method, "GET");
    assert_eq!(get.path(), format!("{USERS_PATH}/CU-1"));
    assert_eq!(user.id, "CU-1");
}
