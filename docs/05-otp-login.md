# 05. OTP login

## Métodos SDK
- `request_otp_login(RequestOtpRequest) -> RequestOtpResponse`
- `login_with_otp(OtpLoginRequest) -> OtpLoginResponse`
- `request_passwordless_code(RequestPasswordlessCodeRequest) -> RequestPasswordlessCodeResponse`
- `authenticate_passwordless(PasswordlessAuthRequest) -> PasswordlessAuthResponse`

## Paso 1
`RequestOtpRequest { email, metadata }`

`RequestOtpResponse`:
- `success`
- `message`
- `email_sent_to`
- `expires_at`
- `expires_in_minutes`

## Paso 2
`OtpLoginRequest { email, code }`

`OtpLoginResponse`:
- `jwt`, `refresh_token?`, `expires_in`
- `user`, `company`, `session`, `application`
- `metadata`

Para obtener siempre el token utilizable para refresh:
`response.effective_refresh_token()`

## Passwordless por email

El SDK también soporta el flujo dedicado `passwordless`, separado del OTP login existente.

### Paso 1
`RequestPasswordlessCodeRequest { email, metadata }`

`RequestPasswordlessCodeResponse`:
- `success`
- `message`
- `email_sent_to`
- `expires_at`
- `expires_in_minutes`

### Paso 2
`PasswordlessAuthRequest { email, code }`

`PasswordlessAuthResponse`:
- `jwt`, `refresh_token?`, `expires_in`
- `user`, `company`, `session`, `application`
- `metadata`

### Ejemplo

```rust
use loginflow_sdk::{
    LoginFlowClient,
    PasswordlessAuthRequest,
    RequestPasswordlessCodeRequest,
};

async fn passwordless_login(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    client.request_passwordless_code(
        RequestPasswordlessCodeRequest {
            email: "user@example.com".into(),
            metadata: None,
        }
    ).await?;

    let response = client.authenticate_passwordless(
        PasswordlessAuthRequest {
            email: "user@example.com".into(),
            code: "123456".into(),
        }
    ).await?;

    println!("JWT: {}", response.jwt);
    Ok(())
}
```
