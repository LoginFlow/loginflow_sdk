# 12. Multi-tenant

Requires the `multi-tenant` feature.

## Trait
`MultiTenantExt` adds methods that take `company_id` per request:
- `login_with_company`
- `register_with_company`
- `verify_email_with_company`
- `request_password_reset_with_company`
- `verify_reset_code_with_company`
- `complete_password_reset_with_company`
- `complete_password_reset_with_token_with_company` (`MultiTenantCompleteResetWithTokenRequest { email, reset_token, new_password, confirm_password, company_id }`, with the `reset_token` returned by `verify_reset_code_with_company`)
- `login_with_oauth_with_company`
- `request_otp_login_with_company`
- `login_with_otp_with_company`

All of them use the client's shared HTTP client (same connection pool, timeout and User-Agent).

## Use case
A single application serves several tenants and the `company_id` changes per user or request.

## OTP example

```rust
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::multi_tenant::{MultiTenantExt, MultiTenantOtpLoginRequest, MultiTenantRequestOtpRequest};

async fn otp_login_multi_tenant(
    client: &LoginFlowClient,
    company_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.request_otp_login_with_company(MultiTenantRequestOtpRequest {
        email: "user@example.com".into(),
        company_id: company_id.into(),
        metadata: None,
        language: None,
    }).await?;

    let session = client.login_with_otp_with_company(MultiTenantOtpLoginRequest {
        email: "user@example.com".into(),
        code: "123456".into(),
        company_id: company_id.into(),
    }).await?;

    println!("access token: {}", session.jwt);
    Ok(())
}
```
