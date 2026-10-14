# Implementation tutorial: LoginFlow SDK

A practical integration guide for a Rust service (SDK 0.5.0).

## 1. Setup

### 1.1 Dependency

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.5.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

### 1.2 Environment

```env
LOGIN_FLOW_URL=https://api.loginflow.dev
LOGIN_FLOW_COMPANY=<company_uuid>
LOGIN_FLOW_APPLICATION=<application_uuid>
LOGINFLOW_ISSUER=https://api.loginflow.dev
```

### 1.3 Client

Build the client once and share it (clones share the connection pool and the JWKS cache).

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowResult};

fn build_client() -> LoginFlowResult<LoginFlowClient> {
    LoginFlowClient::from_env()
}
```

## 2. Base flow: register, login, refresh, logout

```rust
use loginflow_sdk::{
    LoginFlowClient, LoginRequest, LoginResult, LogoutRequest, RefreshTokenRequest, RegisterRequest,
};

async fn base_flow(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    // Register: always creates a `user`. Returns { user_id, company_id, application_id }.
    let registered = client.register(RegisterRequest {
        email: "user@example.com".into(),
        first_name: "Jane".into(),
        last_name: "Doe".into(),
        password: "SecurePass123!".into(),
    }).await?;

    // Login
    let login = match client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "SecurePass123!".into(),
    }).await? {
        LoginResult::Success(resp) => *resp,
        LoginResult::TotpRequired(challenge) => {
            eprintln!("2FA required: {}", challenge.totp_token);
            return Ok(());
        }
    };

    // Refresh: refresh token + session ID. The refresh token rotates; keep the new one.
    let refreshed = client.refresh_token(RefreshTokenRequest {
        refresh_token: login.refresh_token.clone(),
        session_id: login.session.id.clone(),
    }).await?;

    // Logout: name the session (or set logout_all_devices: Some(true)).
    client.logout(&refreshed.access_token, LogoutRequest {
        user_id: registered.user_id,
        session_token: Some(login.session.id.clone()),
        logout_all_devices: None,
    }).await?;

    Ok(())
}
```

## 3. OTP login (email code)

There is a single email-code flow. Whether an unknown email gets an account on step 2 is a per-application setting on the server; the step 1 response looks the same either way.

```rust
use loginflow_sdk::{LoginFlowClient, OtpLoginRequest, RequestOtpRequest};

async fn otp_flow(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    let step1 = client.request_otp_login(RequestOtpRequest {
        email: "user@example.com".into(),
        metadata: None,
        language: Some("en".into()),
    }).await?;
    println!("code sent to {}", step1.email_sent_to);

    let session = client.login_with_otp(OtpLoginRequest {
        email: "user@example.com".into(),
        code: "123456".into(),
    }).await?;
    println!("access={} refresh={}", session.jwt, session.refresh_token);
    Ok(())
}
```

## 4. TOTP 2FA

### 4.1 Enrollment (authenticated user)

```rust
let setup = client.setup_totp(&access_token, Some("Acme Back Office")).await?;
println!("otpauth uri: {}", setup.otpauth_uri); // render as a QR code

client.verify_totp_setup(&access_token, "123456").await?; // activates TOTP
let status = client.get_totp_status(&access_token).await?;
println!("enabled={}", status.enabled);
```

### 4.2 Login with a TOTP challenge

```rust
use loginflow_sdk::{LoginRequest, LoginResult, VerifyTotpLoginRequest};

let login = match client.login(LoginRequest {
    email: "user@example.com".into(),
    password: "SecurePass123!".into(),
}).await? {
    LoginResult::Success(resp) => *resp,
    LoginResult::TotpRequired(challenge) => {
        client.verify_totp_login(VerifyTotpLoginRequest {
            totp_token: challenge.totp_token,
            code: "123456".into(),
        }).await?
    }
};
```

The `totp_token` is a `token_type = "totp_challenge"` token: `verify_token` and the Actix extractors reject it.

## 5. OAuth login

```rust
use loginflow_sdk::{LoginResult, OAuthLoginRequest};

match client.login_with_oauth(OAuthLoginRequest {
    provider: "google".into(),
    id_token: "<google-id-token>".into(),
}).await? {
    LoginResult::Success(resp) => println!("access={}", resp.jwt),
    LoginResult::TotpRequired(challenge) => println!("2FA token={}", challenge.totp_token),
}
```

## 6. Password reset (3 steps) and change

```rust
use loginflow_sdk::{ChangePasswordRequest, CompleteResetRequest};

client.request_password_reset("user@example.com", Some("en")).await?;

// complete_password_reset verifies the code (step 2) and sets the new password (step 3).
client.complete_password_reset(CompleteResetRequest {
    email: "user@example.com".into(),
    code: "12345678".into(),
    new_password: "NewSecurePass123!".into(),
    confirm_password: "NewSecurePass123!".into(),
}).await?;

// Authenticated change: identity comes from the access token.
client.change_password(&access_token, ChangePasswordRequest {
    current_password: "NewSecurePass123!".into(),
    new_password: "AnotherPass123!".into(),
    confirm_password: "AnotherPass123!".into(),
}).await?;
```

## 7. Email verification

```rust
use loginflow_sdk::{RequestEmailVerificationRequest, ResendVerificationRequest, VerifyEmailRequest};

// The code is emailed; it is never returned by the API.
client.request_email_verification(RequestEmailVerificationRequest {
    user_id: "<user_uuid>".into(),
    email: "user@example.com".into(),
    language: None,
}).await?;

let verified = client.verify_email(VerifyEmailRequest {
    verification_code: "123456".into(),
    user_id: "<user_uuid>".into(),
    language: None,
}).await?;

let resent = client.resend_verification(ResendVerificationRequest {
    user_id: "<user_uuid>".into(),
    email: "user@example.com".into(),
    language: None,
}).await?;
```

## 8. Verifying access tokens in your API

```rust
let claims = client.verify_token(&access_token).await?;
println!("user_id={} role={}", claims.user_id, claims.role);
```

The SDK downloads the issuer's JWKS (`{LOGIN_FLOW_URL}/oauth2/jwks`), picks the key by `kid`, checks the ES256 signature, `iss`, `aud`, `exp`, `token_type == "access"` and `status == "active"`.

## 9. Actix integration

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer};
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::actix::AuthMiddleware;

#[get("/me")]
async fn me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "id": auth.user_id().to_string(), "email": auth.email() }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = LoginFlowClient::from_env().map_err(std::io::Error::other)?;
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone())) // required
            .service(me)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

If the client is not registered, the extractors answer HTTP 500 (configuration error) instead of trusting the token.
