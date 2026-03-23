# 12. Multi-tenant

Requiere feature `multi-tenant`.

## Trait
`MultiTenantExt` agrega métodos con `company_id` dinámico:
- `login_with_company`
- `register_with_company`
- `verify_email_with_company`
- `request_password_reset_with_company`
- `verify_reset_code_with_company`
- `complete_password_reset_with_company`
- `complete_password_reset_with_token_with_company`
- `login_with_oauth_with_company`
- `request_passwordless_code_with_company`
- `authenticate_passwordless_with_company`

## Caso de uso
Cuando una sola aplicación integra múltiples tenants y el `company_id` cambia por usuario/request.

## Ejemplo passwordless

```rust
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::multi_tenant::{
    MultiTenantExt,
    MultiTenantPasswordlessAuthRequest,
    MultiTenantRequestPasswordlessCodeRequest,
};

async fn passwordless_login_multi_tenant(
    client: &LoginFlowClient,
    company_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.request_passwordless_code_with_company(
        MultiTenantRequestPasswordlessCodeRequest {
            email: "user@example.com".into(),
            company_id: company_id.into(),
            metadata: None,
        }
    ).await?;

    let response = client.authenticate_passwordless_with_company(
        MultiTenantPasswordlessAuthRequest {
            email: "user@example.com".into(),
            code: "123456".into(),
            company_id: company_id.into(),
        }
    ).await?;

    println!("JWT: {}", response.jwt);
    Ok(())
}
```
