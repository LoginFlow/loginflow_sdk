//! Every SDK call must hit a route the LoginFlow server mounts, with the body
//! the server's handler deserializes.

mod common;

use common::{DISCOVERY_PATH, FakeServer, Reply, client_for, discovery_document, envelope};
use loginflow_sdk::{AccountRecoveryRequest, ChangePasswordRequest, LoginFlowError};
use serde_json::json;

fn profile() -> serde_json::Value {
    json!({
        "id": "p-1", "email": "test@example.com", "first_name": null, "last_name": null,
        "created_at": null, "updated_at": null, "deleted_at": null, "is_deleted": false
    })
}

#[tokio::test]
async fn profile_search_uses_the_master_scope_and_encodes_the_email() {
    let server = FakeServer::start(|_| Reply::ok(envelope(profile()))).await;
    let client = client_for(&server);

    client
        .search_profile_by_email("master-token", "test@example.com")
        .await
        .expect("search");

    let req = server.last();
    assert_eq!(req.method, "GET");
    assert_eq!(
        req.target,
        "/v1/master/user-profiles/search?email=test%40example.com"
    );
    assert_eq!(req.header("authorization"), Some("Bearer master-token"));
}

#[tokio::test]
async fn account_lookup_uses_the_master_scope() {
    let account = json!({
        "id": "p-1", "email": "a@b.c", "first_name": null, "last_name": null,
        "user_id": "u-1", "company_id": "c-1", "application_id": "a-1", "auth_type": "password",
        "email_verified": true, "is_active": true, "failed_login_attempts": 0,
        "last_login_at": null, "last_successful_login": null, "last_failed_attempt": null,
        "lock_until": null, "lock_level": null, "created_at": null, "updated_at": null,
        "deleted_at": null, "is_deleted": false
    });
    let server = FakeServer::start(move |_| Reply::ok(envelope(account.clone()))).await;
    let client = client_for(&server);

    client
        .get_account("master-token", "acc-1")
        .await
        .expect("get account");

    assert_eq!(server.last().target, "/v1/master/user-accounts/acc-1");
}

/// SDK v0.6.0: the body carries only `new_password`.
#[tokio::test]
async fn change_password_sends_only_the_new_password() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "message": "Password updated. Sign in again." }),
        ))
    })
    .await;
    let client = client_for(&server);

    let response = client
        .change_password(
            "access-token",
            ChangePasswordRequest {
                new_password: "new-Passw0rd".into(),
            },
        )
        .await
        .expect("change password");

    assert_eq!(response.message, "Password updated. Sign in again.");
    let req = server.last();
    assert_eq!(req.target, "/v1/user/change-password");
    let body = req.json();
    let keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["new_password"]);
}

#[tokio::test]
async fn account_recovery_response_without_ticket_is_a_parse_error() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "success": true, "message": "sent", "support_contact": "support@example.com" }),
        ))
    })
    .await;
    let client = client_for(&server);

    let result = client
        .request_account_recovery(account_recovery_request())
        .await;

    assert!(
        matches!(result, Err(LoginFlowError::ParseError(_))),
        "{result:?}"
    );
}

fn account_recovery_request() -> AccountRecoveryRequest {
    AccountRecoveryRequest {
        application_id: "APP-CONSOLE".into(),
        old_email: "old@example.com".into(),
        new_email: "new@example.com".into(),
        reason: "lost mailbox".into(),
        full_name: None,
        phone: None,
        additional_info: None,
        language: None,
    }
}

#[tokio::test]
async fn account_recovery_returns_the_ticket() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "success": true, "message": "sent", "ticket_id": "t-1", "support_contact": "support@example.com" }),
        ))
    })
    .await;
    let client = client_for(&server);

    let response = client
        .request_account_recovery(account_recovery_request())
        .await
        .expect("account recovery");

    assert_eq!(response.ticket_id, "t-1");
    assert_eq!(response.support_contact, "support@example.com");
    let req = server.last();
    assert_eq!(req.path(), "/v1/public/auth/request-account-recovery");
    // The application is the one the caller names (the config names an API, not an app).
    assert_eq!(req.json()["application_id"], json!("APP-CONSOLE"));
    assert_eq!(req.json()["company_id"], json!(common::COMPANY_ID));
}

/// `GET /oauth2/userinfo` answers a plain JSON object (never the `{data, meta}` envelope), and
/// email only comes back because the server resolved it live for this call — never off a claim
/// the SDK cached from the access token itself.
#[tokio::test]
async fn userinfo_resolves_live_and_is_not_envelope_wrapped() {
    let server = FakeServer::start(|req| {
        if req.path() == DISCOVERY_PATH {
            // The fake server does not know its own base URL inside the responder closure, but
            // every request to it (including this one) carries it in `Host`.
            let base_url = format!("http://{}", req.header("host").expect("Host header"));
            return Reply::ok(discovery_document(&base_url));
        }
        Reply::ok(json!({ "sub": "cu-1", "user_id": "u-1", "email": "a@b.c" }).to_string())
    })
    .await;
    let client = client_for(&server);

    let info = client
        .userinfo("some-access-token")
        .await
        .expect("userinfo");

    assert_eq!(info.sub, "cu-1");
    assert_eq!(info.email, Some("a@b.c".to_string()));
    let req = server.last();
    assert_eq!(req.method, "GET");
    assert_eq!(req.path(), "/oauth2/userinfo");
    assert_eq!(
        req.header("authorization"),
        Some("Bearer some-access-token")
    );
}
