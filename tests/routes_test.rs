//! Every SDK call must hit a route the LoginFlow server mounts, with the body
//! the server's handler deserializes.

mod common;

use common::{APP_ID, COMPANY_ID, FakeServer, Reply, client_for, envelope};
use loginflow_sdk::{
    AccountRecoveryRequest, ChangePasswordRequest, LoginFlowError, LoginRequest, LoginResult,
    LogoutRequest, OtpLoginRequest, RegisterRequest, RequestEmailVerificationRequest,
    RequestOtpRequest, ValidateDelegatedTokenRequest, VerifyResetCodeRequest,
};
use serde_json::json;

fn profile() -> serde_json::Value {
    json!({
        "id": "p-1", "email": "test@example.com", "first_name": null, "last_name": null,
        "created_at": null, "updated_at": null, "deleted_at": null, "is_deleted": false
    })
}

fn session_payload(with_refresh_token: bool) -> serde_json::Value {
    let mut data = json!({
        "jwt": "access.jwt", "refresh_token": "refresh.jwt", "expires_in": 900,
        "user": { "id": "u-1", "email": "u@example.com", "first_name": "U", "last_name": "T", "role": "user", "company_id": "c-1" },
        "company": { "id": "c-1", "name": "C", "tax_id": null, "email": null },
        "session": { "id": "s-1", "device_info": null, "ip_address": null, "user_agent": null, "location": null,
                     "created_at": "2026-10-15T00:00:00", "expires_at": "2026-10-15T00:15:00",
                     "refresh_expires_at": "2026-10-22T00:00:00" },
        "application": { "id": "a-1", "name": "App", "app_url": null, "status": "active" }
    });
    if !with_refresh_token {
        data.as_object_mut()
            .expect("object")
            .remove("refresh_token");
    }
    data
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
        "role": "user", "email_verified": true, "is_active": true, "failed_login_attempts": 0,
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

#[tokio::test]
async fn register_sends_no_role_and_returns_the_server_ids() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "user_id": "u-1", "company_id": COMPANY_ID, "application_id": APP_ID }),
        ))
    })
    .await;
    let client = client_for(&server);

    let registered = client
        .register(RegisterRequest {
            email: "new@example.com".into(),
            first_name: "New".into(),
            last_name: "User".into(),
            password: "S3cure-password".into(),
        })
        .await
        .expect("register");

    assert_eq!(registered.user_id, "u-1");
    assert_eq!(registered.company_id, COMPANY_ID);
    assert_eq!(registered.application_id, APP_ID);
    let req = server.last();
    assert_eq!(req.target, "/v1/public/user-accounts");
    let body = req.json();
    for field in ["role", "status", "phone"] {
        assert!(
            body.get(field).is_none(),
            "register must not send `{field}`: {body}"
        );
    }
    assert_eq!(body["auth_type"], "password");
}

#[tokio::test]
async fn change_password_sends_only_the_passwords() {
    // The server answers `data` with a bare message string.
    let server =
        FakeServer::start(|_| Reply::ok(envelope(json!("Password updated, please sign in again"))))
            .await;
    let client = client_for(&server);

    let response = client
        .change_password(
            "access-token",
            ChangePasswordRequest {
                current_password: "old".into(),
                new_password: "new-Passw0rd".into(),
                confirm_password: "new-Passw0rd".into(),
            },
        )
        .await
        .expect("change password");

    assert_eq!(response.message, "Password updated, please sign in again");
    let req = server.last();
    assert_eq!(req.target, "/v1/user/change-password");
    let body = req.json();
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["confirm_password", "current_password", "new_password"]
    );
}

#[tokio::test]
async fn logout_without_a_target_is_rejected_before_any_request() {
    let server = FakeServer::start(|_| Reply::ok(envelope(json!({})))).await;
    let client = client_for(&server);

    let result = client
        .logout(
            "access-token",
            LogoutRequest {
                user_id: "u-1".into(),
                session_token: None,
                logout_all_devices: None,
            },
        )
        .await;

    assert!(
        matches!(result, Err(LoginFlowError::Validation(_))),
        "{result:?}"
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn logout_of_one_session_reaches_the_user_scope() {
    let server =
        FakeServer::start(|_| Reply::ok(envelope(json!({ "success": true, "message": "ok" }))))
            .await;
    let client = client_for(&server);

    client
        .logout(
            "access-token",
            LogoutRequest {
                user_id: "u-1".into(),
                session_token: Some("s-1".into()),
                logout_all_devices: None,
            },
        )
        .await
        .expect("logout");

    let req = server.last();
    assert_eq!(req.target, "/v1/user/logout");
    assert_eq!(req.json()["session_token"], "s-1");
}

#[tokio::test]
async fn email_verification_request_carries_no_skip_flag_and_expects_no_code() {
    let server =
        FakeServer::start(|_| Reply::ok(envelope(json!({ "success": true, "message": "sent" }))))
            .await;
    let client = client_for(&server);

    let response = client
        .request_email_verification(RequestEmailVerificationRequest {
            user_id: "u-1".into(),
            email: "u@example.com".into(),
            language: None,
        })
        .await
        .expect("request verification");

    assert!(response.success);
    assert_eq!(response.message, "sent");
    let body = server.last().json();
    assert!(body.get("skip_email").is_none(), "{body}");
}

#[tokio::test]
async fn otp_flow_uses_the_unified_endpoints() {
    let server = FakeServer::start(|req| {
        if req.path().ends_with("/request-otp-login") {
            Reply::ok(envelope(json!({
                "success": true, "message": "sent", "email_sent_to": "u***@example.com",
                "expires_at": "2026-10-15T00:30:00", "expires_in_minutes": 30
            })))
        } else {
            let mut data = session_payload(true);
            data["success"] = json!(true);
            data["message"] = json!("ok");
            Reply::ok(envelope(data))
        }
    })
    .await;
    let client = client_for(&server);

    client
        .request_otp_login(RequestOtpRequest {
            email: "u@example.com".into(),
            metadata: None,
            language: None,
        })
        .await
        .expect("request otp");
    let session = client
        .login_with_otp(OtpLoginRequest {
            email: "u@example.com".into(),
            code: "123456".into(),
        })
        .await
        .expect("otp login");

    let paths: Vec<String> = server
        .requests()
        .iter()
        .map(|r| r.path().to_string())
        .collect();
    assert_eq!(
        paths,
        ["/v1/public/request-otp-login", "/v1/public/login-with-otp"]
    );
    assert_eq!(session.refresh_token, "refresh.jwt");
}

#[tokio::test]
async fn login_response_without_refresh_token_is_a_parse_error() {
    let server = FakeServer::start(|_| Reply::ok(envelope(session_payload(false)))).await;
    let client = client_for(&server);

    let result = client
        .login(LoginRequest {
            email: "u@example.com".into(),
            password: "p".into(),
        })
        .await;

    assert!(
        matches!(result, Err(LoginFlowError::ParseError(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn login_response_with_refresh_token_parses() {
    let server = FakeServer::start(|_| Reply::ok(envelope(session_payload(true)))).await;
    let client = client_for(&server);

    let result = client
        .login(LoginRequest {
            email: "u@example.com".into(),
            password: "p".into(),
        })
        .await;

    match result {
        Ok(LoginResult::Success(response)) => assert_eq!(response.refresh_token, "refresh.jwt"),
        other => panic!("unexpected login result: {other:?}"),
    }
}

#[tokio::test]
async fn error_bodies_are_read_up_to_4_kib() {
    let huge = "e".repeat(100 * 1024);
    let server = FakeServer::start(move |_| Reply::status(400, huge.clone())).await;
    let client = client_for(&server);

    let result = client
        .login(LoginRequest {
            email: "u@example.com".into(),
            password: "p".into(),
        })
        .await;

    match result {
        Err(LoginFlowError::Validation(message)) => assert_eq!(message.len(), 4 * 1024),
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[tokio::test]
async fn structured_error_message_is_extracted() {
    let server = FakeServer::start(|_| {
        Reply::status(
            401,
            json!({ "error": { "code": "INVALID_CREDENTIALS", "message": "Wrong password" } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .login(LoginRequest {
            email: "u@example.com".into(),
            password: "p".into(),
        })
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication(m)) if m == "Wrong password"),
        "{result:?}"
    );
}

/// The server's wire body for every rejected one-time code (any `AppResponse::Unauthorized`).
fn unauthorized_body() -> String {
    json!({ "error": { "code": "UNAUTHORIZED", "message": "Authentication is required." } })
        .to_string()
}

#[tokio::test]
async fn otp_login_rejection_is_one_invalid_code_error() {
    let server = FakeServer::start(|_| Reply::status(401, unauthorized_body())).await;
    let client = client_for(&server);

    let result = client
        .login_with_otp(OtpLoginRequest {
            email: "u@example.com".into(),
            code: "000000".into(),
        })
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication(m)) if m == "The code is invalid or has expired"),
        "{result:?}"
    );
}

#[tokio::test]
async fn delegated_token_rejection_is_one_invalid_code_error() {
    let server = FakeServer::start(|_| Reply::status(401, unauthorized_body())).await;
    let client = client_for(&server);

    let result = client
        .validate_delegated_token(ValidateDelegatedTokenRequest {
            code: "7K3MZQ9P".into(),
            email: "creator@example.com".into(),
        })
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication(m)) if m == "The code is invalid or has expired"),
        "{result:?}"
    );
}

#[tokio::test]
async fn account_recovery_response_without_ticket_is_a_parse_error() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(json!({
            "success": true, "message": "sent", "support_contact": "support@example.com"
        })))
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
        Reply::ok(envelope(json!({
            "success": true, "message": "sent", "ticket_id": "t-1",
            "support_contact": "support@example.com"
        })))
    })
    .await;
    let client = client_for(&server);

    let response = client
        .request_account_recovery(account_recovery_request())
        .await
        .expect("account recovery");

    assert_eq!(response.ticket_id, "t-1");
    assert_eq!(response.support_contact, "support@example.com");
    assert_eq!(
        server.last().path(),
        "/v1/public/auth/request-account-recovery"
    );
}

#[tokio::test]
async fn delegated_token_validation_sends_the_creators_email() {
    let server = FakeServer::start(|_| {
        let mut data = session_payload(true);
        data["success"] = json!(true);
        data["message"] = json!("ok");
        Reply::ok(envelope(data))
    })
    .await;
    let client = client_for(&server);

    let session = client
        .validate_delegated_token(ValidateDelegatedTokenRequest {
            code: "7k3mzq9p".into(),
            email: "creator@example.com".into(),
        })
        .await
        .expect("validate delegated token");

    assert_eq!(session.refresh_token, "refresh.jwt");
    let req = server.last();
    assert_eq!(req.path(), "/v1/public/auth/validate-delegated-token");
    assert_eq!(
        req.json(),
        json!({
            "code": "7k3mzq9p", "email": "creator@example.com",
            "company_id": COMPANY_ID, "application_id": APP_ID
        })
    );
}

#[tokio::test]
async fn reset_code_with_a_leading_zero_is_sent_as_text() {
    let server =
        FakeServer::start(|_| Reply::ok(envelope(json!({ "reset_token": "reset.jwt" })))).await;
    let client = client_for(&server);

    client
        .verify_reset_code(VerifyResetCodeRequest {
            email: "u@example.com".into(),
            code: "01234567".into(),
        })
        .await
        .expect("verify reset code");

    assert_eq!(server.last().json()["reset_code"], "01234567");
}

#[tokio::test]
async fn reset_code_rejection_is_one_invalid_reset_code_error() {
    let server = FakeServer::start(|_| {
        Reply::status(
            422,
            json!({ "error": { "code": "VALIDATION_ERROR", "message": "Some fields are invalid." } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .verify_reset_code(VerifyResetCodeRequest {
            email: "u@example.com".into(),
            code: "01234567".into(),
        })
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::Authentication(m)) if m == "Invalid or expired reset code"),
        "{result:?}"
    );
}
