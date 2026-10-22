//! `ServiceUsersClient`: `/v1/service/users` behind a `client_credentials` token requested with
//! scope `users:manage`, envelope parsing, `409` -> `Conflict { code }`, and exactly one retry
//! with a fresh token when the API rejects the cached one.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{FakeServer, RecordedRequest, Reply, config_for, envelope};
use loginflow_sdk::{
    CreateServiceUserRequest, InvitationStatus, LoginFlowError, ServiceUserRole,
    ServiceUsersClient, UpdateServiceUserRequest,
};
use serde_json::{Value, json};

const TOKEN_PATH: &str = "/oauth2/token";
const USERS_PATH: &str = "/v1/service/users";

fn service_user(id: &str, email: &str) -> Value {
    json!({
        "id": id,
        "email": email,
        "first_name": "Ana",
        "last_name": null,
        "role": "app_admin",
        "is_active": true,
        "email_verified": false,
        // `NaiveDateTime` as the API serializes it: UTC, no offset.
        "created_at": "2026-10-20T10:00:00.123456",
        "last_login_at": null,
    })
}

/// Token endpoint answer whose `access_token` is `token-<n>`, `n` counting from 1.
fn token_reply(issued: &AtomicUsize) -> Reply {
    let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
    Reply::ok(
        json!({ "access_token": format!("token-{n}"), "token_type": "Bearer", "expires_in": 900 })
            .to_string(),
    )
}

fn error_body(code: &str, message: &str) -> String {
    json!({
        "error": { "code": code, "message": message },
        "meta": { "status": 0, "timestamp": "2026-10-20T10:00:00Z", "request_id": "r", "path": "/" }
    })
    .to_string()
}

/// Fake LoginFlow: the token endpoint issues `token-1`, `token-2`, ...; every other request is
/// answered by `api`.
async fn server(api: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static) -> FakeServer {
    let issued = Arc::new(AtomicUsize::new(0));
    FakeServer::start(move |req| {
        if req.path() == TOKEN_PATH {
            token_reply(&issued)
        } else {
            api(req)
        }
    })
    .await
}

fn client(server: &FakeServer) -> ServiceUsersClient {
    ServiceUsersClient::new(config_for(server), "billing-service", "svc-secret").expect("client")
}

fn api_requests(server: &FakeServer) -> Vec<RecordedRequest> {
    server
        .requests()
        .into_iter()
        .filter(|req| req.path() != TOKEN_PATH)
        .collect()
}

/// TEST_CHARTER
/// Requirement: the token is requested with `grant_type=client_credentials`, scope
/// `users:manage` and `client_secret_basic`, and every API call carries it as a Bearer token;
/// `create` posts the contract body to `/v1/service/users` and parses the `{data, meta}`
/// envelope into a `ServiceUser`.
/// Oracle: the token request's form body / `Authorization`, the API request recorded by the
/// fake server, and the returned `ServiceUser`.
/// Risk edge: a token without `users:manage` is refused by the server on every call.
/// Layer: integration over loopback HTTP against the in-process `FakeServer`.
/// Counterfactual: dropping `.with_scope(USERS_MANAGE_SCOPE)` fails the scope assertion.
#[tokio::test]
async fn create_requests_a_users_manage_token_and_parses_the_envelope() {
    let server =
        server(|_| Reply::status(201, envelope(service_user("CU-1", "ana@example.com")))).await;

    let user = client(&server)
        .create(CreateServiceUserRequest {
            email: "ana@example.com".into(),
            first_name: Some("Ana".into()),
            last_name: None,
            role: ServiceUserRole::AppAdmin,
            send_invitation: false,
        })
        .await
        .expect("created");

    let token_request = server
        .requests()
        .into_iter()
        .find(|req| req.path() == TOKEN_PATH)
        .expect("token requested");
    assert!(
        token_request.body.contains("grant_type=client_credentials"),
        "{}",
        token_request.body
    );
    assert!(
        token_request.body.contains("scope=users%3Amanage"),
        "{}",
        token_request.body
    );
    assert!(
        token_request
            .header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
    );

    let create = server.last();
    assert_eq!(create.method, "POST");
    assert_eq!(create.path(), USERS_PATH);
    assert_eq!(create.header("authorization"), Some("Bearer token-1"));
    assert_eq!(
        create.json(),
        json!({ "email": "ana@example.com", "first_name": "Ana", "role": "app_admin" })
    );

    assert_eq!(user.id, "CU-1");
    assert_eq!(user.email, "ana@example.com");
    assert_eq!(user.first_name.as_deref(), Some("Ana"));
    assert_eq!(user.last_name, None);
    assert_eq!(user.role, ServiceUserRole::AppAdmin.to_string());
    assert!(user.is_active);
    assert!(!user.email_verified);
    assert_eq!(user.created_at, "2026-10-20T10:00:00.123456");
    assert_eq!(user.last_login_at, None);
}

#[tokio::test]
async fn list_get_set_active_and_email_change_hit_the_contract_routes() {
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
        ("POST", "/v1/service/users/CU-1/email-change") => Reply::status(
            202,
            envelope(json!({ "expires_at": "2026-10-20T10:15:00" })),
        ),
        ("POST", "/v1/service/users/CU-1/email-change/confirm") => {
            Reply::ok(envelope(service_user("CU-1", "ana.new@example.com")))
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

    let requested = users
        .request_email_change("CU-1", "ana.new@example.com")
        .await
        .expect("email change requested");
    assert_eq!(requested.expires_at, "2026-10-20T10:15:00");
    assert_eq!(
        server.last().json(),
        json!({ "new_email": "ana.new@example.com" })
    );

    let confirmed = users
        .confirm_email_change("CU-1", "123456")
        .await
        .expect("email change confirmed");
    assert_eq!(confirmed.email, "ana.new@example.com");
    assert_eq!(server.last().json(), json!({ "code": "123456" }));

    // One token served every call.
    assert_eq!(server.hits(TOKEN_PATH), 1);
}

/// TEST_CHARTER
/// Requirement: a `409` surfaces as `LoginFlowError::Conflict` carrying the envelope's
/// `error.code`, so a caller can tell `email_shared` apart from any other conflict.
/// Oracle: the `Err` returned by `confirm_email_change`.
/// Risk edge: without a `409` arm the error degrades to `Network("HTTP 409 ...")` and the code
/// is lost.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: removing the `409` arm of `LoginFlowError::from_status` fails the match.
#[tokio::test]
async fn conflict_carries_the_server_error_code() {
    let server = server(|_| {
        Reply::status(
            409,
            error_body("email_shared", "The profile belongs to other companies too"),
        )
    })
    .await;

    let result = client(&server).confirm_email_change("CU-1", "123456").await;

    match result {
        Err(LoginFlowError::Conflict { message, code }) => {
            assert_eq!(code.as_deref(), Some("email_shared"));
            assert_eq!(message, "The profile belongs to other companies too");
        }
        other => panic!("expected a Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn not_found_user_is_not_found() {
    let server = server(|_| Reply::status(404, error_body("NOT_FOUND", "User not found"))).await;

    let result = client(&server).get("CU-404").await;

    assert!(
        matches!(&result, Err(LoginFlowError::NotFound(_))),
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
        matches!(&result, Err(LoginFlowError::Authentication(_))),
        "{result:?}"
    );
    assert_eq!(api_requests(&server).len(), 2);
    assert_eq!(server.hits(TOKEN_PATH), 2);
}

/// A `401` about the request itself (a wrong email-change code, `INVALID_CODE`) is returned at
/// once: resending would burn one more attempt of the same wrong code.
#[tokio::test]
async fn invalid_code_is_not_retried() {
    let server =
        server(|_| Reply::status(401, error_body("INVALID_CODE", "Invalid or expired code"))).await;

    let result = client(&server).confirm_email_change("CU-1", "000000").await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication(message)) if message == "Invalid or expired code"),
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
/// Requirement: `delete` sends `DELETE /v1/service/users/{id}` with the `users:manage` token and
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
        Err(LoginFlowError::NotFound(_))
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
        role: ServiceUserRole::User,
        send_invitation,
    };

    let invited = users.create(request(true)).await.expect("created");
    assert_eq!(
        server.last().json(),
        json!({ "email": "ana@example.com", "role": "user", "send_invitation": true })
    );
    assert_eq!(invited.invitation, Some(InvitationStatus::Sent));

    let quiet = users.create(request(false)).await.expect("created");
    assert_eq!(
        server.last().json(),
        json!({ "email": "ana@example.com", "role": "user" })
    );
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
            role: ServiceUserRole::User,
            send_invitation: true,
        })
        .await
        .expect("created");

    assert_eq!(user.invitation, Some(InvitationStatus::Unknown));
}

/// TEST_CHARTER
/// Requirement: `set_role` PATCHes `{"role": ...}` (nothing else) to the user's route, and
/// `update` sends exactly the fields that are set.
/// Oracle: the method, path and JSON body recorded by the fake server; the returned role.
/// Counterfactual: a role never serialized sends `{}` (the server answers `422`).
#[tokio::test]
async fn set_role_and_update_patch_only_the_fields_set() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("PATCH", "/v1/service/users/CU-1") => {
            let mut user = service_user("CU-1", "ana@example.com");
            if let Some(role) = req.json().get("role") {
                user["role"] = role.clone();
            }
            Reply::ok(envelope(user))
        }
        _ => Reply::status(404, error_body("NOT_FOUND", "no route")),
    })
    .await;
    let users = client(&server);

    let demoted = users
        .set_role("CU-1", ServiceUserRole::User)
        .await
        .expect("set_role");
    assert_eq!(server.last().method, "PATCH");
    assert_eq!(server.last().json(), json!({ "role": "user" }));
    assert_eq!(demoted.role, "user");

    users
        .update(
            "CU-1",
            UpdateServiceUserRequest {
                is_active: Some(false),
                role: Some(ServiceUserRole::AppAdmin),
            },
        )
        .await
        .expect("update");
    assert_eq!(
        server.last().json(),
        json!({ "is_active": false, "role": "app_admin" })
    );
}
