# 05. OTP login (email code)

LoginFlow has a single email-code login. Older SDKs exposed a separate "passwordless" flow; it was merged into this one. Whether an email without an account gets one on step 2 is a per-application server setting (self sign-up). Step 1 answers the same way whether the account exists or not.

## SDK methods
- `request_otp_login(RequestOtpRequest) -> RequestOtpResponse`
- `login_with_otp(OtpLoginRequest) -> OtpLoginResponse`

## Step 1: `POST /v1/public/request-otp-login`

`RequestOtpRequest { email, metadata, language }`

`RequestOtpResponse { success, message, email_sent_to, expires_at, expires_in_minutes }`

## Step 2: `POST /v1/public/login-with-otp`

`OtpLoginRequest { email, code }`

`OtpLoginResponse { success, message, jwt, refresh_token, expires_in, user, company, session, application, metadata }`. `refresh_token` is always present.

## Example

```rust
use loginflow_sdk::{LoginFlowClient, OtpLoginRequest, RequestOtpRequest};

async fn otp_login(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    client.request_otp_login(RequestOtpRequest {
        email: "user@example.com".into(),
        metadata: None,
        language: None,
    }).await?;

    let session = client.login_with_otp(OtpLoginRequest {
        email: "user@example.com".into(),
        code: "123456".into(),
    }).await?;

    println!("access token: {}", session.jwt);
    Ok(())
}
```

Multi-tenant variants: `request_otp_login_with_company`, `login_with_otp_with_company` ([12-multi-tenant.md](12-multi-tenant.md)).
