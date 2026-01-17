# LoginFlow SDK

A Rust SDK for integrating with the LoginFlow authentication service. Provides a clean, type-safe API for authentication, password management, and Actix-web integration.

## Features

- **Authentication**: Register, login, logout users
- **Password Management**: Reset password (3-step flow), change password
- **Email Verification**: Verify user email with verification code
- **JWT Handling**: Decode and extract user information from JWT tokens
- **Actix-web Integration**: Ready-to-use middleware and extractors

## Installation

### Git Dependency

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk", tag = "v0.1.0" }

# Or use main branch for latest
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk" }
```

### Feature Flags

```toml
[dependencies]
# With Actix-web support (default)
loginflow_sdk = { git = "...", tag = "v0.1.0" }

# Without Actix-web support
loginflow_sdk = { git = "...", tag = "v0.1.0", default-features = false }
```

## Quick Start

### 1. Set Environment Variables

```env
# Required
LOGINFLOW_URL=https://your-loginflow-server.com    # Or LOGIN_URL
LOGINFLOW_COMPANY=your-company-uuid        # Or COMPANY
LOGINFLOW_APPLICATION=your-app-uuid        # Or APPLICATION

# Optional
LOGINFLOW_VERSION=1                        # Default: 1
LOGINFLOW_TIMEOUT=30                       # Default: 30 seconds
```

### 2. Create Client

```rust
use loginflow_sdk::LoginFlowClient;

// From environment variables
let client = LoginFlowClient::from_env()?;

// Or with explicit configuration
use loginflow_sdk::LoginFlowConfig;

let client = LoginFlowClient::new(LoginFlowConfig {
    base_url: "https://your-loginflow-server.com".into(),
    api_version: 1,
    company_id: "your-company-uuid".into(),
    application_id: "your-app-uuid".into(),
    timeout_secs: 30,
    user_agent: None,
})?;
```

### 3. Use Authentication Methods

```rust
use loginflow_sdk::{LoginFlowClient, LoginRequest, RegisterRequest};

async fn example(client: &LoginFlowClient) {
    // Register a new user
    let register_response = client.register(RegisterRequest {
        email: "user@example.com".into(),
        first_name: "John".into(),
        last_name: "Doe".into(),
        password: "secure_password".into(),
        phone: Some("+1234567890".into()),
    }).await?;

    // Login
    let login_response = client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "secure_password".into(),
    }).await?;

    println!("JWT: {}", login_response.jwt);
    println!("User ID: {}", login_response.user.id);
}
```

## Actix-web Integration

The SDK provides ready-to-use middleware for protecting endpoints:

```rust
use actix_web::{web, App, HttpServer, HttpResponse, post, get};
use loginflow_sdk::{LoginFlowClient, LoginRequest};
use loginflow_sdk::actix::{AuthMiddleware, OptionalAuth};

// Protected endpoint - requires authentication
#[post("/protected")]
async fn protected_endpoint(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role()
    }))
}

// Optional authentication - works with or without token
#[get("/profile")]
async fn profile_endpoint(auth: OptionalAuth) -> HttpResponse {
    if let Some(user) = auth.user() {
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "user_id": user.user_id.to_string()
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": false
        }))
    }
}

// Login endpoint using the client
#[post("/login")]
async fn login(
    client: web::Data<LoginFlowClient>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    match client.login(body.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = LoginFlowClient::from_env().expect("LoginFlow config");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .service(login)
            .service(protected_endpoint)
            .service(profile_endpoint)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

## Password Reset Flow

The SDK supports the 3-step password reset flow:

```rust
use loginflow_sdk::{LoginFlowClient, CompleteResetRequest};

async fn reset_password_flow(client: &LoginFlowClient, email: &str) {
    // Step 1: Request reset (sends code to email)
    client.request_password_reset(email).await?;

    // Step 2 & 3: Complete reset with code and new password
    // (SDK internally verifies code to get reset_token)
    client.complete_password_reset(CompleteResetRequest {
        email: email.into(),
        code: "123456".into(),  // Code from email
        new_password: "new_secure_password".into(),
        confirm_password: "new_secure_password".into(),
    }).await?;
}
```

## Change Password (Authenticated)

```rust
use loginflow_sdk::{LoginFlowClient, ChangePasswordRequest};

async fn change_password(
    client: &LoginFlowClient,
    token: &str,
    user_id: &str,
    company_id: &str,
) {
    client.change_password(
        token,
        user_id,
        company_id,
        ChangePasswordRequest {
            current_password: "old_password".into(),
            new_password: "new_password".into(),
            confirm_password: "new_password".into(),
        },
    ).await?;
}
```

## Error Handling

The SDK provides detailed error types:

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowError, LoginRequest};

async fn handle_login(client: &LoginFlowClient) {
    match client.login(LoginRequest { .. }).await {
        Ok(response) => println!("Success: {}", response.jwt),
        Err(LoginFlowError::Authentication(msg)) => {
            println!("Invalid credentials: {}", msg);
        }
        Err(LoginFlowError::Network(msg)) => {
            println!("Network error: {}", msg);
        }
        Err(LoginFlowError::Validation(msg)) => {
            println!("Invalid input: {}", msg);
        }
        Err(e) => println!("Other error: {}", e),
    }
}
```

## JWT Handling

Extract user information from JWT tokens:

```rust
use loginflow_sdk::{LoginFlowClient, decode_jwt_claims};

// Using the client
let user = client.extract_user_from_token("eyJ...")?;
println!("User ID: {}", user.user_id);

// Or directly decode claims
let claims = decode_jwt_claims("eyJ...")?;
if claims.is_expired() {
    println!("Token expired!");
}
```

## AuthMiddleware API

The `AuthMiddleware` extractor provides these methods:

```rust
auth.user_id()       // -> Uuid
auth.email()         // -> &str
auth.role()          // -> &str
auth.company_id()    // -> Uuid
auth.application_id() // -> Uuid
auth.user()          // -> &AuthenticatedUser
auth.token()         // -> &str (raw JWT for forwarding)
auth.is_admin()      // -> bool
auth.is_master()     // -> bool
```

## API Reference

### LoginFlowClient Methods

| Method | Description |
|--------|-------------|
| `register(req)` | Register a new user |
| `login(req)` | Login with email/password |
| `logout(req)` | Logout user session |
| `verify_email(req)` | Verify email with code |
| `request_password_reset(email)` | Send reset code to email |
| `verify_reset_code(req)` | Verify reset code, get token |
| `complete_password_reset(req)` | Complete password reset |
| `change_password(token, user_id, company_id, req)` | Change password (authenticated) |
| `extract_user_from_token(token)` | Decode JWT to AuthenticatedUser |

## Migration from TurnoQR API

If migrating from the existing auth module in TurnoQR API:

1. Add the SDK dependency
2. Replace `AuthRepository` calls with `LoginFlowClient` methods
3. Replace `AuthMiddleware` import to use SDK version
4. Update error handling to use `LoginFlowError`

```rust
// Before
use crate::modules::auth::model::loginflow_models::*;
use crate::utils::auth_middleware::AuthMiddleware;

// After
use loginflow_sdk::prelude::*;
```

## License

MIT
