//! `request_account_recovery` against LoginFlow 0.22: an application with account recovery
//! switched off refuses the request with `403 account_recovery_disabled`, and the caller tells
//! that refusal apart by its code.

mod common;

use common::{FakeServer, Reply, client_for};
use loginflow_sdk::{AccountRecoveryRequest, LoginFlowError};
use serde_json::json;

fn recovery_request() -> AccountRecoveryRequest {
    AccountRecoveryRequest {
        application_id: "APP-TEST".into(),
        old_email: "old@example.com".into(),
        new_email: "new@example.com".into(),
        reason: "Lost access to the old mailbox".into(),
        full_name: None,
        phone: None,
        additional_info: None,
        language: None,
    }
}

#[tokio::test]
async fn recovery_switched_off_is_an_authorization_error_with_its_code() {
    let server = FakeServer::start(|_| {
        Reply::status(
            403,
            json!({
                "error": {
                    "code": "account_recovery_disabled",
                    "message": "Account recovery is not available for this application"
                },
                "meta": { "status": 403 }
            })
            .to_string(),
        )
    })
    .await;
    let client = client_for(&server);

    let result = client.request_account_recovery(recovery_request()).await;

    assert!(
        matches!(
            &result,
            Err(LoginFlowError::Authorization { code: Some(code), .. }) if code == "account_recovery_disabled"
        ),
        "{result:?}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].target,
        "/v1/public/auth/request-account-recovery"
    );
}
