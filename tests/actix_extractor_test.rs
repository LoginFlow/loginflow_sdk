//! Actix extractors must never trust a token they have not verified.

#![cfg(feature = "actix")]

mod common;

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::test::TestRequest;
use actix_web::{FromRequest, web};
use common::{FakeServer, Reply, TestKey, USER_ID, access_claims, client_for, jwks, jwks_server};
use loginflow_sdk::LoginFlowError;
use loginflow_sdk::actix::{AuthMiddleware, MasterAuth, OptionalAuth};

/// Unsigned token whose payload claims a master account. Any decoder that skips the
/// signature check would happily accept it.
const FORGED_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJqIiwidXNlcl9pZCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsImNvbXBhbnlfaWQiOiIyMjIyMjIyMi0yMjIyLTIyMjItMjIyMi0yMjIyMjIyMjIyMjIiLCJhcHBsaWNhdGlvbl9pZCI6IjMzMzMzMzMzLTMzMzMtMzMzMy0zMzMzLTMzMzMzMzMzMzMzMyIsImVtYWlsIjoiZm9yZ2VkQGV4YW1wbGUuY29tIiwicm9sZSI6Im1hc3RlciIsInN0YXR1cyI6ImFjdGl2ZSIsInRva2VuX3R5cGUiOiJhY2Nlc3MifQ.forged-signature";

#[actix_web::test]
async fn auth_without_registered_client_is_a_configuration_error() {
    let req = TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {FORGED_TOKEN}")))
        .to_http_request();

    let result = AuthMiddleware::from_request(&req, &mut Payload::None).await;

    let err = match result {
        Ok(auth) => panic!(
            "unverified token accepted for user {}",
            auth.company_user_id()
        ),
        Err(err) => err,
    };
    assert_eq!(
        err.as_response_error().status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[actix_web::test]
async fn optional_auth_without_registered_client_is_a_configuration_error() {
    let req = TestRequest::default()
        .insert_header(("Authorization", format!("Bearer {FORGED_TOKEN}")))
        .to_http_request();

    let result = OptionalAuth::from_request(&req, &mut Payload::None).await;

    let err = match result {
        Ok(auth) => panic!(
            "optional auth swallowed a misconfiguration (authenticated: {})",
            auth.is_authenticated()
        ),
        Err(err) => err,
    };
    assert_eq!(
        err.as_response_error().status_code(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

/// Request carrying `token`, with the client registered as the SDK documents.
async fn request_with(token: Option<&str>) -> (actix_web::HttpRequest, common::FakeServer) {
    let server = jwks_server(jwks(&[TestKey::a().public_jwk()])).await;
    let mut builder = TestRequest::default().app_data(web::Data::new(client_for(&server)));
    if let Some(token) = token {
        builder = builder.insert_header(("Authorization", format!("Bearer {token}")));
    }
    (builder.to_http_request(), server)
}

fn status_of<T>(result: Result<T, actix_web::Error>) -> StatusCode {
    match result {
        Ok(_) => StatusCode::OK,
        Err(err) => err.as_response_error().status_code(),
    }
}

#[actix_web::test]
async fn auth_without_header_is_unauthorized() {
    let (req, _server) = request_with(None).await;

    let result = AuthMiddleware::from_request(&req, &mut Payload::None).await;

    assert_eq!(status_of(result), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn auth_with_a_verified_access_token_exposes_the_user() {
    let token = TestKey::a().sign(&access_claims());
    let (req, _server) = request_with(Some(&token)).await;

    let auth = AuthMiddleware::from_request(&req, &mut Payload::None)
        .await
        .expect("authenticated");

    assert_eq!(auth.company_user_id(), USER_ID);
    assert_eq!(auth.token(), token);
}

#[actix_web::test]
async fn auth_with_a_forged_token_is_unauthorized() {
    let (req, _server) = request_with(Some(FORGED_TOKEN)).await;

    let result = AuthMiddleware::from_request(&req, &mut Payload::None).await;

    assert_eq!(status_of(result), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn auth_with_a_non_access_token_header_typ_is_unauthorized() {
    // A TOTP-challenge/password-reset token is never typed `at+jwt`; the header check alone must
    // reject it here too, same as `LoginFlowClient::verify_token` itself.
    let key = TestKey::a();
    let token = key.sign_with_typ(&access_claims(), Some("JWT"));
    let (req, _server) = request_with(Some(&token)).await;

    let result = AuthMiddleware::from_request(&req, &mut Payload::None).await;

    assert_eq!(status_of(result), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn master_auth_rejects_a_verified_user_role() {
    let token = TestKey::a().sign(&access_claims());
    let (req, _server) = request_with(Some(&token)).await;

    let result = MasterAuth::from_request(&req, &mut Payload::None).await;

    assert_eq!(status_of(result), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn optional_auth_without_header_is_anonymous() {
    let (req, _server) = request_with(None).await;

    let auth = OptionalAuth::from_request(&req, &mut Payload::None)
        .await
        .expect("optional auth must not fail");

    assert!(!auth.is_authenticated());
}

#[actix_web::test]
async fn optional_auth_with_a_forged_token_is_anonymous() {
    let (req, _server) = request_with(Some(FORGED_TOKEN)).await;

    let auth = OptionalAuth::from_request(&req, &mut Payload::None)
        .await
        .expect("optional auth must not fail");

    assert!(!auth.is_authenticated());
}

#[test]
fn bearer_token_is_extracted_from_the_header() {
    let req = TestRequest::default()
        .insert_header(("Authorization", "Bearer test-token"))
        .to_http_request();
    assert_eq!(
        loginflow_sdk::actix::extract_token_from_request(&req).expect("token"),
        "test-token"
    );
}

#[test]
fn non_bearer_header_is_rejected() {
    let req = TestRequest::default()
        .insert_header(("Authorization", "Basic xxx"))
        .to_http_request();
    assert!(loginflow_sdk::actix::extract_token_from_request(&req).is_err());
}

/// Request carrying a valid token while the JWKS endpoint answers 500.
async fn request_with_jwks_down() -> (actix_web::HttpRequest, FakeServer) {
    let server = FakeServer::start(|_| Reply::status(500, "{}")).await;
    let token = TestKey::a().sign(&access_claims());
    let req = TestRequest::default()
        .app_data(web::Data::new(client_for(&server)))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_http_request();
    (req, server)
}

#[actix_web::test]
async fn auth_with_jwks_unavailable_is_service_unavailable() {
    let (req, _server) = request_with_jwks_down().await;

    let result = AuthMiddleware::from_request(&req, &mut Payload::None).await;

    assert_eq!(status_of(result), StatusCode::SERVICE_UNAVAILABLE);
}

#[actix_web::test]
async fn optional_auth_with_jwks_unavailable_propagates_the_error() {
    let (req, _server) = request_with_jwks_down().await;

    let result = OptionalAuth::from_request(&req, &mut Payload::None).await;

    match result {
        Ok(auth) => panic!(
            "JWKS outage turned into an anonymous request (authenticated: {})",
            auth.is_authenticated()
        ),
        Err(err) => assert_eq!(
            err.as_response_error().status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        ),
    }
}

#[actix_web::test]
async fn upstream_error_body_is_a_fixed_message() {
    let detail = "request failed: error sending request for url (http://10.0.0.7:8080/oauth2/jwks)";
    let response =
        actix_web::ResponseError::error_response(&LoginFlowError::Jwks(detail.to_string()));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("body");
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("10.0.0.7") && !body.contains("request failed"),
        "{body}"
    );

    let network =
        actix_web::ResponseError::error_response(&LoginFlowError::Network(detail.to_string()));
    let body = actix_web::body::to_bytes(network.into_body())
        .await
        .expect("body");
    assert!(!String::from_utf8_lossy(&body).contains("10.0.0.7"));
}

#[test]
fn rate_limit_response_forwards_retry_after() {
    let error = LoginFlowError::RateLimit {
        message: "Too many requests. Please try again later.".into(),
        retry_after_secs: Some(42),
    };

    let response = actix_web::ResponseError::error_response(&error);

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("42")
    );
}

#[test]
fn rate_limit_response_without_wait_has_no_retry_after() {
    let error = LoginFlowError::RateLimit {
        message: "Too many requests. Please try again later.".into(),
        retry_after_secs: None,
    };

    let response = actix_web::ResponseError::error_response(&error);

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response
            .headers()
            .get(actix_web::http::header::RETRY_AFTER)
            .is_none()
    );
}

/// TEST_CHARTER
/// Requirement: a backend built on this SDK that calls `JwtClaims::require_recent_auth` (or
/// gets `LoginFlowError::InsufficientUserAuthentication` from a LoginFlow API call) and returns
/// it as an Actix response presents the *same* RFC 9470 `WWW-Authenticate` challenge LoginFlow's
/// own server sends — not just a 401 with no header, which leaves the caller unable to tell a
/// step-up apart from any other rejection.
/// Oracle: the `WWW-Authenticate` response header.
/// Risk edge: the header's `error=`/`max_age=` shape must match exactly what
/// `loginflow_api::shared::helper::recent_auth::recent_auth_required` sends, since a client
/// (this SDK's own HTTP layer, or another LoginFlow SDK) parses it looking for that literal
/// string.
/// Layer: unit against `ResponseError::error_response`.
/// Counterfactual: the header insertion block removed makes both assertions below fail (the
/// header would be absent).
#[test]
fn insufficient_user_authentication_response_carries_the_rfc9470_challenge() {
    let error = LoginFlowError::InsufficientUserAuthentication {
        max_age_secs: Some(300),
    };

    let response = actix_web::ResponseError::error_response(&error);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer error=\"insufficient_user_authentication\", max_age=300")
    );
}

/// Without a `max_age` (the SDK itself never sends one when it has none to report), the
/// challenge omits `max_age` entirely rather than inventing a value.
#[test]
fn insufficient_user_authentication_without_max_age_omits_it_from_the_challenge() {
    let error = LoginFlowError::InsufficientUserAuthentication { max_age_secs: None };

    let response = actix_web::ResponseError::error_response(&error);

    assert_eq!(
        response
            .headers()
            .get(actix_web::http::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer error=\"insufficient_user_authentication\"")
    );
}
