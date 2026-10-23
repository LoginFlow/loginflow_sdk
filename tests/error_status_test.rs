//! Rate limits (`429` + `Retry-After`) and an unavailable server (`503`) are
//! errors of their own, on every call, including the ones that answer `bool`.

mod common;

use common::{FakeServer, Reply, client_for};
use loginflow_sdk::{ChangePasswordRequest, LoginFlowError};
use serde_json::json;

fn rate_limited_body() -> String {
    json!({ "error": { "code": "RATE_LIMITED", "message": "Too many requests. Please try again later." } }).to_string()
}

fn change_password_request() -> ChangePasswordRequest {
    ChangePasswordRequest {
        new_password: "NewPassw0rd!".into(),
    }
}

#[tokio::test]
async fn rate_limited_change_password_is_an_error_not_a_rejection() {
    let server = FakeServer::start(|_| {
        Reply::status(429, rate_limited_body()).with_header("Retry-After", "600")
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    assert!(
        matches!(
            result,
            Err(LoginFlowError::RateLimit {
                retry_after_secs: Some(600),
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn unavailable_server_on_change_password_is_an_error_not_a_rejection() {
    let server = FakeServer::start(|_| {
        Reply::status(503, json!({ "error": { "code": "SERVICE_UNAVAILABLE", "message": "The server is busy, try again" } }).to_string())
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::ServiceUnavailable(m)) if m == "The server is busy, try again"),
        "{result:?}"
    );
}

#[tokio::test]
async fn rate_limit_carries_the_message_and_the_retry_after_header() {
    let server = FakeServer::start(|_| {
        Reply::status(429, rate_limited_body()).with_header("Retry-After", "42")
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    match result {
        Err(LoginFlowError::RateLimit {
            message,
            retry_after_secs,
        }) => {
            assert_eq!(message, "Too many requests. Please try again later.");
            assert_eq!(retry_after_secs, Some(42));
        }
        other => panic!("expected a rate limit, got {other:?}"),
    }
}

#[tokio::test]
async fn rate_limit_without_retry_after_has_no_wait() {
    let server = FakeServer::start(|_| Reply::status(429, rate_limited_body())).await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    assert!(
        matches!(
            result,
            Err(LoginFlowError::RateLimit {
                retry_after_secs: None,
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn service_unavailable_is_its_own_retryable_error() {
    let server = FakeServer::start(|_| {
        Reply::status(503, json!({ "error": { "code": "SERVICE_UNAVAILABLE", "message": "The server is busy, try again" } }).to_string())
    })
    .await;
    let client = client_for(&server);

    let error = client
        .change_password("token", change_password_request())
        .await
        .expect_err("503 must fail");

    assert!(
        matches!(&error, LoginFlowError::ServiceUnavailable(m) if m == "The server is busy, try again"),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

#[tokio::test]
async fn other_server_errors_stay_server_errors() {
    let server = FakeServer::start(|_| {
        Reply::status(
            500,
            json!({ "error": { "code": "DATABASE_ERROR", "message": "Internal error" } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    assert!(
        matches!(result, Err(LoginFlowError::ServerError(_))),
        "{result:?}"
    );
}

/// Core behaviour this cycle: RFC 9470 step-up is surfaced as its own typed error, distinct
/// from a plain `401`, with the `max_age` the server asked for.
#[tokio::test]
async fn insufficient_user_authentication_is_its_own_error_with_max_age() {
    let server = FakeServer::start(|_| {
        Reply::status(
            401,
            json!({ "error": { "code": "UNAUTHORIZED", "message": "step up" } }).to_string(),
        )
        .with_header(
            "WWW-Authenticate",
            "Bearer error=\"insufficient_user_authentication\", max_age=300",
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    assert!(
        matches!(
            result,
            Err(LoginFlowError::InsufficientUserAuthentication {
                max_age_secs: Some(300)
            })
        ),
        "{result:?}"
    );
}

/// TEST_CHARTER
/// Requirement: a `422 VALIDATION_ERROR` carries the generic `error.message` ("Some fields are
/// invalid.") and the specific reason in `error.details` (`loginflow_api`
/// `AppResponse::error_details`); the SDK surfaces that reason as the `Validation` message, with
/// the envelope's `code`.
/// Oracle: the `message` and `code` of the returned `LoginFlowError::Validation`.
/// Risk edge: every refused input reads "Some fields are invalid." and the caller cannot tell a
/// weak password from a breached one, or which catalog entry broke a sync.
/// Layer: integration against the in-process `FakeServer`, the API's envelope byte for byte.
/// Counterfactual: reading `error.message` only (ignoring `details`) fails the message assertion.
#[tokio::test]
async fn a_validation_error_carries_the_servers_reason_and_code() {
    let server = FakeServer::start(|_| {
        Reply::status(
            422,
            json!({ "error": {
                "code": "VALIDATION_ERROR",
                "message": "Some fields are invalid.",
                "details": "This password appears in a known data breach. Choose a different one.",
            }, "meta": { "status": 422 } })
            .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .change_password("token", change_password_request())
        .await;

    match result {
        Err(LoginFlowError::Validation { message, code }) => {
            assert_eq!(
                message,
                "This password appears in a known data breach. Choose a different one."
            );
            assert_eq!(code.as_deref(), Some("VALIDATION_ERROR"));
        }
        other => panic!("expected a validation error, got {other:?}"),
    }
}

/// TEST_CHARTER
/// Requirement: a wrong or locked-out TOTP code is `401 INVALID_CODE` (`loginflow_api`
/// `AppResponse::InvalidCode`): the access token is fine, the code typed is not. The SDK maps it
/// to `Validation { code: Some("INVALID_CODE") }`, which never asks to re-authenticate.
/// Oracle: the variant, `code` and message of the error, and `requires_reauthentication()`.
/// Risk edge: a typo in a 6-digit code is reported as a rejected credential, and a caller that
/// follows `requires_reauthentication()` signs the user out.
/// Layer: integration against the in-process `FakeServer`, the API's envelope byte for byte.
/// Counterfactual: mapping every `401` to `Authentication` fails the variant assertion and makes
/// `requires_reauthentication()` true.
#[tokio::test]
async fn a_wrong_totp_code_is_not_a_rejected_credential() {
    let server = FakeServer::start(|_| {
        Reply::status(
            401,
            json!({ "error": { "code": "INVALID_CODE", "message": "Invalid TOTP code" }, "meta": { "status": 401 } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let error = client
        .verify_totp_setup("token", "123456")
        .await
        .expect_err("a wrong code must fail");

    assert!(
        matches!(&error, LoginFlowError::Validation { message, code: Some(code) }
            if code == "INVALID_CODE" && message == "Invalid TOTP code"),
        "{error:?}"
    );
    assert!(!error.requires_reauthentication());
}

/// TEST_CHARTER
/// Requirement: a `404` keeps the envelope's `error.code` (`member_not_found`,
/// `organization_not_found`, ...), as `403` and `409` already do.
/// Oracle: the `code` of the returned `LoginFlowError::NotFound`; a `404` without an envelope has
/// none.
/// Risk edge: a product cannot tell "the person has no membership" from "the organization is
/// gone" and repairs the wrong thing.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: dropping `error.code` for a `404` fails the first assertion.
#[tokio::test]
async fn a_not_found_carries_the_servers_code() {
    let server = FakeServer::start(|req| {
        if req.path().ends_with("/status") {
            Reply::status(404, "")
        } else {
            Reply::status(
                404,
                json!({ "error": { "code": "NOT_FOUND", "message": "User account not found" } })
                    .to_string(),
            )
        }
    })
    .await;
    let client = client_for(&server);

    let coded = client.setup_totp("token", None).await;
    assert!(
        matches!(&coded, Err(LoginFlowError::NotFound { message, code: Some(code) })
            if code == "NOT_FOUND" && message == "User account not found"),
        "{coded:?}"
    );
    let bare = client.get_totp_status("token").await;
    assert!(
        matches!(&bare, Err(LoginFlowError::NotFound { code: None, .. })),
        "{bare:?}"
    );
}
