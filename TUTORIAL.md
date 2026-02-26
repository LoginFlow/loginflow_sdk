# Tutorial de implementación: LoginFlow SDK

Guía práctica de integración para un servicio Rust.

## 1. Preparación

### 1.1 Dependencia

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk", tag = "v0.1.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
dotenv = "0.15"
```

### 1.2 Variables de entorno

```env
LOGINFLOW_URL=https://auth.example.com
LOGINFLOW_COMPANY=<company_uuid>
LOGINFLOW_APPLICATION=<application_uuid>
LOGINFLOW_TIMEOUT=30
```

### 1.3 Cliente

```rust
use loginflow_sdk::LoginFlowClient;

fn build_client() -> Result<LoginFlowClient, Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    Ok(LoginFlowClient::from_env()?)
}
```

## 2. Flujo base: register -> login -> refresh -> logout

```rust
use loginflow_sdk::{
    LoginFlowClient, RegisterRequest, LoginRequest, LoginResult,
    RefreshTokenRequest, LogoutRequest,
};

async fn base_flow(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    // Register
    let reg = client.register(RegisterRequest {
        email: "user@example.com".into(),
        first_name: "Jane".into(),
        last_name: "Doe".into(),
        password: "SecurePass123!".into(),
        phone: None,
    }).await?;

    // Login
    let login = client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "SecurePass123!".into(),
    }).await?;

    let login = match login {
        LoginResult::Success(resp) => *resp,
        LoginResult::TotpRequired(challenge) => {
            eprintln!("2FA requerido: {}", challenge.totp_token);
            return Ok(());
        }
    };

    // Refresh (en backend actual, usa refresh_token + session_id)
    let refreshed = client.refresh_token(RefreshTokenRequest {
        refresh_token: login.jwt.clone(), // JWT actual (refresh token en tu implementación puede variar)
        session_id: login.session.id.clone(),
    }).await;

    // Logout (endpoint protegido: requiere Bearer token)
    let _ = client.logout(&login.jwt, LogoutRequest {
        user_id: reg.user_id,
        session_token: Some(login.session.id.clone()),
        logout_all_devices: Some(false),
    }).await;

    println!("refresh result: {:?}", refreshed);
    Ok(())
}
```

## 3. OTP login (passwordless)

```rust
use loginflow_sdk::{RequestOtpRequest, OtpLoginRequest};

async fn otp_flow(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    let step1 = client.request_otp_login(RequestOtpRequest {
        email: "user@example.com".into(),
        metadata: None,
    }).await?;

    println!("OTP enviado a {}", step1.email_sent_to);

    let step2 = client.login_with_otp(OtpLoginRequest {
        email: "user@example.com".into(),
        code: "123456".into(),
    }).await?;

    println!("JWT={}", step2.jwt);
    Ok(())
}
```

## 4. TOTP 2FA

### 4.1 Setup (usuario autenticado)

```rust
let setup = client.setup_totp(jwt).await?;
println!("otpauth uri: {}", setup.otp_auth_uri);

let status = client.verify_totp_setup(jwt, "123456").await?;
println!("enabled={}", status.enabled);
```

### 4.2 Login con challenge

```rust
use loginflow_sdk::{LoginRequest, LoginResult, VerifyTotpLoginRequest};

let result = client.login(LoginRequest {
    email: "user@example.com".into(),
    password: "SecurePass123!".into(),
}).await?;

let login_response = match result {
    LoginResult::Success(resp) => *resp,
    LoginResult::TotpRequired(challenge) => {
        client.verify_totp_login(VerifyTotpLoginRequest {
            totp_token: challenge.totp_token,
            code: "123456".into(),
        }).await?
    }
};

println!("JWT={}", login_response.jwt);
```

## 5. OAuth login

```rust
use loginflow_sdk::{OAuthLoginRequest, LoginResult};

let result = client.login_with_oauth(OAuthLoginRequest {
    provider: "google".into(),
    id_token: "<google-id-token>".into(),
}).await?;

match result {
    LoginResult::Success(resp) => println!("jwt={}", resp.jwt),
    LoginResult::TotpRequired(ch) => println!("2FA token={}", ch.totp_token),
}
```

## 6. Password reset (3 pasos)

```rust
use loginflow_sdk::{VerifyResetCodeRequest, CompleteResetRequest};

client.request_password_reset("user@example.com").await?;

let verify = client.verify_reset_code(VerifyResetCodeRequest {
    email: "user@example.com".into(),
    code: "123456".into(),
}).await?;

println!("reset_token={}", verify.reset_token);

client.complete_password_reset(CompleteResetRequest {
    email: "user@example.com".into(),
    code: "123456".into(),
    new_password: "NewSecurePass123!".into(),
    confirm_password: "NewSecurePass123!".into(),
}).await?;
```

## 7. Verificación de email

```rust
use loginflow_sdk::{VerifyEmailRequest, ResendVerificationRequest};

let ok = client.verify_email(VerifyEmailRequest {
    verification_code: "123456".into(),
    user_id: "<user_uuid>".into(),
}).await?;

println!("verified={ok}");

let resent = client.resend_verification(ResendVerificationRequest {
    user_id: "<user_uuid>".into(),
    email: "user@example.com".into(),
}).await?;

println!("resent={resent}");
```

## 8. JWT local (sin llamada al servidor)

```rust
let claims = client.verify_token(jwt)?;
println!("user_id={}", claims.user_id);
```

## 9. Integración Actix

```rust
use actix_web::{web, App, HttpServer, HttpResponse, get};
use loginflow_sdk::{LoginFlowClient};
use loginflow_sdk::actix::AuthMiddleware;

#[get("/me")]
async fn me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "id": auth.user_id().to_string(),
        "email": auth.email(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let client = LoginFlowClient::from_env().expect("client init");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .service(me)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

## 10. Notas críticas de compatibilidad

- `register()` actualmente apunta a `/v1/public/users`, pero el backend actual expone `/v1/public/user-accounts`.
- `change_password()` actualmente apunta a `/v1/public/change-password`, pero el backend actual expone `/v1/user/change-password`.

Antes de producción, valida estas dos rutas en tu entorno objetivo.
