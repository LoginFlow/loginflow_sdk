//! Multi-tenant calls share the client's HTTP configuration and the unified OTP flow.

#![cfg(feature = "multi-tenant")]

mod common;

use common::{FakeServer, Reply, config_for, envelope};
use loginflow_sdk::multi_tenant::{
    MultiTenantExt, MultiTenantLoginRequest, MultiTenantOAuthLoginRequest,
    MultiTenantRequestOtpRequest,
};
use loginflow_sdk::{LoginFlowClient, LoginResult, OAuthLoginRequest};
use serde_json::json;

#[tokio::test]
async fn multi_tenant_requests_use_the_configured_client() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "requires_2fa": true, "totp_token": "t", "expires_in": 300 }),
        ))
    })
    .await;
    let mut config = config_for(&server);
    config.user_agent = Some("TenantApp/1.0".into());
    let client = LoginFlowClient::new(config).expect("client");

    client
        .login_with_company(MultiTenantLoginRequest {
            email: "u@example.com".into(),
            password: "p".into(),
            company_id: "company-b".into(),
        })
        .await
        .expect("login");

    let req = server.last();
    assert_eq!(req.target, "/v1/public/login-password");
    assert_eq!(req.header("user-agent"), Some("TenantApp/1.0"));
    assert_eq!(req.json()["company_id"], "company-b");
}

#[tokio::test]
async fn multi_tenant_otp_request_uses_the_unified_endpoint() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(json!({
            "success": true, "message": "sent", "email_sent_to": "u***@example.com",
            "expires_at": "2026-10-15T00:30:00", "expires_in_minutes": 30
        })))
    })
    .await;
    let client = common::client_for(&server);

    client
        .request_otp_login_with_company(MultiTenantRequestOtpRequest {
            email: "u@example.com".into(),
            company_id: "company-b".into(),
            metadata: None,
            language: None,
        })
        .await
        .expect("otp request");

    let req = server.last();
    assert_eq!(req.target, "/v1/public/request-otp-login");
    assert_eq!(req.json()["company_id"], "company-b");
}

#[tokio::test]
async fn oauth_body_is_the_same_for_single_and_multi_tenant_except_the_company() {
    let server = FakeServer::start(|_| {
        Reply::ok(envelope(
            json!({ "requires_2fa": true, "totp_token": "t", "expires_in": 300 }),
        ))
    })
    .await;
    let client = common::client_for(&server);

    let single = client
        .login_with_oauth(OAuthLoginRequest {
            provider: "google".into(),
            id_token: "id-token".into(),
        })
        .await
        .expect("single-tenant oauth");
    let single_body = server.last().json();
    let multi = client
        .login_with_oauth_with_company(MultiTenantOAuthLoginRequest {
            provider: "google".into(),
            id_token: "id-token".into(),
            company_id: "company-b".into(),
        })
        .await
        .expect("multi-tenant oauth");
    let multi_body = server.last().json();

    assert!(
        matches!(single, LoginResult::TotpRequired(_))
            && matches!(multi, LoginResult::TotpRequired(_))
    );
    assert_eq!(single_body["company_id"], common::COMPANY_ID);
    assert_eq!(multi_body["company_id"], "company-b");
    let mut expected = single_body.clone();
    expected["company_id"] = json!("company-b");
    assert_eq!(multi_body, expected);
    assert_eq!(server.last().target, "/v1/public/oauth-login");
}
