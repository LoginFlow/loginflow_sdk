# LoginFlow SDK (Rust)

SDK async y type-safe para integrar autenticación con LoginFlow.

Este README está orientado a implementación real en backend Rust (Actix, Axum, etc.) y está alineado con el código actual del SDK (`src/client.rs`) y el backend (`login_flow`).

## 1. Instalación

```toml
[dependencies]
# Recomendado: fijar tag
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk", tag = "v0.1.0" }

# Alternativa: última versión en main
# loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk" }
```

### Feature flags

```toml
# Default: incluye actix
loginflow_sdk = { git = "..." }

# Sin actix
loginflow_sdk = { git = "...", default-features = false }

# Multi-tenant (+ default features)
loginflow_sdk = { git = "...", features = ["multi-tenant"] }
```

- `actix` (default): extractores y middleware para Actix.
- `multi-tenant`: permite enviar `company_id` dinámico por request.

## 2. Configuración

### Variables requeridas

- `LOGIN_FLOW_URL` (o `LOGIN_URL`)
- `LOGIN_FLOW_COMPANY` (o `COMPANY`)
- `LOGIN_FLOW_APPLICATION` (o `APPLICATION`)

### Variables opcionales

- `LOGIN_FLOW_VERSION` (default `1`)
- `LOGIN_FLOW_TIMEOUT` (default `30` segundos)
- `LOGINFLOW_USER_AGENT`
- `LOGINFLOW_SIGNING_SECRET` (habilita validación local de firma JWT)

### Ejemplo `.env`

```env
LOGIN_FLOW_URL=https://auth.example.com
LOGIN_FLOW_COMPANY=550e8400-e29b-41d4-a716-446655440000
LOGIN_FLOW_APPLICATION=6ba7b810-9dad-11d1-80b4-00c04fd430c8

LOGIN_FLOW_VERSION=1
LOGIN_FLOW_TIMEOUT=30
LOGINFLOW_SIGNING_SECRET=your-per-app-signing-secret
```

## 3. Quick Start

```rust
use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let client = LoginFlowClient::from_env()?;

    let result = client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "SecurePass123!".into(),
    }).await?;

    match result {
        LoginResult::Success(resp) => {
            println!("JWT: {}", resp.jwt);
            println!("Refresh efectivo: {}", resp.effective_refresh_token());
            println!("User: {:?}", resp.user.email);
        }
        LoginResult::TotpRequired(challenge) => {
            println!("2FA requerido, totp_token={}", challenge.totp_token);
        }
    }

    Ok(())
}
```

## Tokens JWT (Access + Refresh)

Todos los endpoints de login devuelven **dos tokens JWT separados**:
- `jwt` (access token): expiración corta (default 1 día, configurable via `JWT_EXPIRATION_MINUTES` en el backend).
- `refresh_token`: expiración larga (default 7 días, configurable via `JWT_REFRESH_DAYS` en el backend).

El `refresh_token` se usa con `client.refresh_token(request)` para obtener un nuevo access token sin re-autenticar.

## 4. Features soportadas por el SDK

### Core auth
- Registro de usuario (`register`)
- Login password (`login`) con resultado unificado (`LoginResult`)
- Refresh token (`refresh_token`)
- Logout autenticado (`logout(access_token, request)`)

### Recuperación / verificación
- Password reset 3 pasos (`request_password_reset`, `verify_reset_code`, `complete_password_reset`)
- Email verification (`verify_email`, `resend_verification`)

### Passwordless / 2FA / OAuth
- OTP login (`request_otp_login`, `login_with_otp`)
- Passwordless email code (`request_passwordless_code`, `authenticate_passwordless`)
- TOTP 2FA (`setup_totp`, `verify_totp_setup`, `get_totp_status`, `disable_totp`, `verify_totp_login`)
- OAuth (`login_with_oauth`)

### Delegated Auth
- Crear código delegado (`create_delegated_token`) — requiere JWT válido
- Validar código delegado (`validate_delegated_token`) — endpoint público

### Account Recovery / Email Verification
- Solicitar recuperación de cuenta (`request_account_recovery`)
- Solicitar verificación de email (`request_email_verification`)

### Gestión de usuarios (admin)
- User accounts (`get_account`, `update_account`, `soft_delete_account`, `restore_account`, `hard_delete_account`)
- User profiles (`get_profile`, `search_profile_by_email`, `update_profile`, `delete_profile`)

### Seguridad local
- Decodificar JWT (`decode_jwt_claims`)
- Verificar firma JWT local (`verify_jwt_claims`, `LoginFlowClient::verify_token`)

### Integración web
- `actix::AuthMiddleware` — extractor de JWT obligatorio
- `actix::OptionalAuth` — extractor de JWT opcional
- `actix::AdminAuth` — extractor que valida rol admin
- `actix::MasterAuth` — extractor que valida rol master

### Multi-tenant (feature)
- Trait `MultiTenantExt` con variantes `*_with_company`

## 5. Contrato de respuestas esperado

El SDK espera el formato estándar del backend:

```json
{
  "data": { "...": "..." },
  "meta": {
    "status": 200,
    "timestamp": "2026-02-26T...",
    "request_id": "...",
    "path": "/v1/..."
  }
}
```

Errores esperados:

```json
{
  "error": {
    "code": "...",
    "message": "...",
    "details": "..."
  },
  "meta": { "status": 4xx/5xx, "...": "..." }
}
```

El SDK mapea por status HTTP a `LoginFlowError` (`Validation`, `Authentication`, `Authorization`, etc.) y extrae `error.message` cuando existe.

Para `401`, el SDK trata el error como autenticación inválida y expone `requires_reauthentication()` para forzar relogin en cliente.

## 6. Mapa rápido SDK -> API

### Alineados
- `register` -> `POST /v1/public/user-accounts`
- `login` -> `POST /v1/public/login-password`
- `refresh_token` -> `POST /v1/public/refresh-token`
- `logout` -> `POST /v1/user/logout`
- `request_otp_login` -> `POST /v1/public/request-otp-login`
- `login_with_otp` -> `POST /v1/public/login-with-otp`
- `request_passwordless_code` -> `POST /v1/public/request-passwordless-code`
- `authenticate_passwordless` -> `POST /v1/public/authenticate-passwordless`
- `verify_totp_login` -> `POST /v1/public/verify-totp`
- `setup_totp` -> `POST /v1/user/totp/setup`
- `verify_totp_setup` -> `POST /v1/user/totp/verify-setup`
- `get_totp_status` -> `GET /v1/user/totp/status`
- `disable_totp` -> `POST /v1/user/totp/disable`
- `login_with_oauth` -> `POST /v1/public/oauth-login`
- `request_password_reset` -> `POST /v1/public/reset-password`
- `verify_reset_code` -> `POST /v1/public/reset-password/verify`
- `complete_password_reset` -> `POST /v1/public/reset-password/complete`
- `change_password` -> `POST /v1/user/change-password`
- `verify_email` -> `POST /v1/public/verify-email`
- `resend_verification` -> `POST /v1/public/resend-verification`
- `get_account/update_account/...` -> `*/v1/master/user-accounts/...`
- `get_profile/update_profile/...` -> `*/v1/master/user-profiles/...`
- `create_delegated_token` -> `POST /v1/user/auth/create-delegated-token`
- `validate_delegated_token` -> `POST /v1/public/auth/validate-delegated-token`
- `request_account_recovery` -> `POST /v1/public/auth/request-account-recovery`
- `request_email_verification` -> `POST /v1/public/request-email-verification`

## 7. Flujo passwordless

Este flujo permite autenticar solo con email y código, sin password.

### Paso 1: solicitar código

```rust
use loginflow_sdk::{LoginFlowClient, RequestPasswordlessCodeRequest};

async fn request_code(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.request_passwordless_code(
        RequestPasswordlessCodeRequest {
            email: "user@example.com".into(),
            metadata: None,
        }
    ).await?;

    println!("Enviado a: {}", response.email_sent_to);
    println!("Expira en {} minutos", response.expires_in_minutes);
    Ok(())
}
```

### Paso 2: autenticar con el código

```rust
use loginflow_sdk::{LoginFlowClient, PasswordlessAuthRequest};

async fn authenticate(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    let response = client.authenticate_passwordless(
        PasswordlessAuthRequest {
            email: "user@example.com".into(),
            code: "123456".into(),
        }
    ).await?;

    println!("JWT: {}", response.jwt);
    println!("User: {}", response.user.email);
    Ok(())
}
```

Comportamiento esperado del backend:
- si la cuenta existe, hace login
- si la cuenta no existe, crea la cuenta passwordless y luego autentica

## 8. Passwordless multi-tenant

Con feature `multi-tenant`, el `company_id` se envía por request.

```rust
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::multi_tenant::{
    MultiTenantExt,
    MultiTenantPasswordlessAuthRequest,
    MultiTenantRequestPasswordlessCodeRequest,
};

async fn passwordless_multi_tenant(
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

## 9. Manejo de errores recomendado

```rust
use loginflow_sdk::LoginFlowError;

match client.login(req).await {
    Ok(result) => { /* manejar success / totp */ }
    Err(err) => match err {
        LoginFlowError::Authentication(msg) => {
            // credenciales inválidas, token inválido, sesión revocada/inactiva, etc.
            eprintln!("401: {}", msg);
            if err.requires_reauthentication() {
                // limpiar sesión local y redirigir a login
            }
        }
        LoginFlowError::Validation(msg) => {
            // payload inválido, reglas de negocio
            eprintln!("422/400: {}", msg);
        }
        e if e.is_retryable() => {
            // network/timeout/429/5xx
            eprintln!("retryable: {}", e);
        }
        _ => eprintln!("fatal: {}", err),
    }
}
```

## 10. Validación local de JWT

Si configuras `LOGINFLOW_SIGNING_SECRET`, el SDK valida firma HMAC-SHA256 y expiración localmente.

```rust
let claims = client.verify_token(jwt_token)?;
println!("user_id={}", claims.user_id);
```

Si no hay secret, `extract_user_from_token` hace decode sin verificar firma.

## 11. Integración Actix (feature `actix`)

```rust
use actix_web::{get, HttpResponse};
use loginflow_sdk::actix::AuthMiddleware;

#[get("/me")]
async fn me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role(),
    }))
}
```

## 10. Referencia detallada

- `TUTORIAL.md`
- `docs/01-configuration.md`
- `docs/02-auth-password.md`
- `docs/03-password-reset.md`
- `docs/04-email-verification.md`
- `docs/05-otp-login.md`
- `docs/06-totp-2fa.md`
- `docs/07-oauth-login.md`
- `docs/08-session-refresh-logout.md`
- `docs/09-user-accounts-profiles.md`
- `docs/10-jwt-local-verification.md`
- `docs/11-actix-integration.md`
- `docs/12-multi-tenant.md`
- `docs/13-error-handling.md`
- `docs/14-sdk-api-traceability.md`
