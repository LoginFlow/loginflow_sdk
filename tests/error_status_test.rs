//! Rate limits (`429` + `Retry-After`) and an unavailable server (`503`) are
//! errors of their own, on every call, including the ones that answer `bool`.

mod common;

use common::{FakeServer, Reply, client_for};
use loginflow_sdk::{LoginFlowError, LoginRequest, ResendVerificationRequest, VerifyEmailRequest};
use serde_json::json;

fn rate_limited_body() -> String {
    json!({ "error": { "code": "RATE_LIMITED", "message": "Too many requests. Please try again later." } })
        .to_string()
}

fn resend_request() -> ResendVerificationRequest {
    ResendVerificationRequest {
        user_id: "u-1".into(),
        email: "u@example.com".into(),
        language: None,
    }
}

#[tokio::test]
async fn rate_limited_resend_is_an_error_not_a_rejection() {
    let server = FakeServer::start(|_| {
        Reply::status(429, rate_limited_body()).with_header("Retry-After", "600")
    })
    .await;
    let client = client_for(&server);

    let result = client.resend_verification(resend_request()).await;

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
async fn unavailable_server_on_verify_email_is_an_error_not_a_rejection() {
    let server = FakeServer::start(|_| {
        Reply::status(
            503,
            json!({ "error": { "code": "SERVICE_UNAVAILABLE", "message": "The server is busy, try again" } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client
        .verify_email(VerifyEmailRequest {
            verification_code: "123456".into(),
            user_id: "u-1".into(),
            language: None,
        })
        .await;

    assert!(
        matches!(&result, Err(LoginFlowError::ServiceUnavailable(m)) if m == "The server is busy, try again"),
        "{result:?}"
    );
}

fn login_request() -> LoginRequest {
    LoginRequest {
        email: "u@example.com".into(),
        password: "p".into(),
    }
}

#[tokio::test]
async fn rate_limit_carries_the_message_and_the_retry_after_header() {
    let server = FakeServer::start(|_| {
        Reply::status(429, rate_limited_body()).with_header("Retry-After", "42")
    })
    .await;
    let client = client_for(&server);

    let result = client.login(login_request()).await;

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

    let result = client.login(login_request()).await;

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
        Reply::status(
            503,
            json!({ "error": { "code": "SERVICE_UNAVAILABLE", "message": "The server is busy, try again" } })
                .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let error = client
        .login(login_request())
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

    let result = client.login(login_request()).await;

    assert!(
        matches!(result, Err(LoginFlowError::ServerError(_))),
        "{result:?}"
    );
}
