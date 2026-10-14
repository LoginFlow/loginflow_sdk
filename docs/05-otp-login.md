# 05. OTP login (email code)

LoginFlow has a single email-code login. Older SDKs exposed a separate "passwordless" flow; it was merged into this one and its server routes no longer exist. Whether an email without an account gets one on step 2 is a per-application server setting (`allow_self_signup`, set through the master applications API). Accounts created that way have `auth_type: "otp"`.

## SDK methods
- `request_otp_login(RequestOtpRequest) -> RequestOtpResponse`
- `login_with_otp(OtpLoginRequest) -> OtpLoginResponse`

## Step 1: `POST /v1/public/request-otp-login`

`RequestOtpRequest { email, metadata, language }`

`RequestOtpResponse { success, message, email_sent_to, expires_at, expires_in_minutes }`

Always `200` with the same body (only a malformed email is an error): `email_sent_to` is the requested address, masked. It does not confirm that a code was sent or that the account exists.

## Step 2: `POST /v1/public/login-with-otp`

`OtpLoginRequest { email, code }`

`OtpLoginResponse { success, message, jwt, refresh_token, expires_in, user, company, session, application, metadata }`. `refresh_token` is always present.

The 6-digit code is single-use and burned after 5 failed attempts. Every rejected code (wrong, expired, burned, reused, issued to another email) is `LoginFlowError::Authentication(INVALID_CODE_MESSAGE)` (`"The code is invalid or has expired"`).

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
