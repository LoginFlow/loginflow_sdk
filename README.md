# LoginFlow SDK (Rust)

Async, type-safe SDK for integrating a Rust backend (Actix, Axum, ...) with the LoginFlow authentication service.

Version 0.5.0 verifies access tokens locally with **ES256 against the issuer's JWKS**. There is no shared signing secret anymore. Upgrading from 0.4.x? Read [CHANGELOG.md](CHANGELOG.md) first.

## 1. Installation

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.5.0" }
```

### Feature flags

```toml
# Default: includes the Actix extractors
loginflow_sdk = { git = "...", tag = "v0.5.0" }

# Without Actix
loginflow_sdk = { git = "...", tag = "v0.5.0", default-features = false }

# Multi-tenant (+ default features)
loginflow_sdk = { git = "...", tag = "v0.5.0", features = ["multi-tenant"] }
```

- `actix` (default): `AuthMiddleware`, `OptionalAuth`, `AdminAuth`, `MasterAuth` extractors.
- `multi-tenant`: send a different `company_id` per request.

## 2. Configuration

### Required variables

| Variable | Alternative | Description |
|---|---|---|
| `LOGIN_FLOW_URL` | `LOGIN_URL` | Base URL without version, e.g. `https://api.loginflow.dev` |
| `LOGIN_FLOW_COMPANY` | `COMPANY` | Company UUID |
| `LOGIN_FLOW_APPLICATION` | `APPLICATION` | Application UUID. Access tokens are accepted only when `aud` equals it |
| `LOGINFLOW_ISSUER` | - | Expected `iss` of every token: `https://api.loginflow.dev` (dev: `https://api-dev.loginflow.dev`) |

### Optional variables

| Variable | Default | Description |
|---|---|---|
| `LOGIN_FLOW_VERSION` / `LOGIN_VERSION` | `1` | API version |
| `LOGIN_FLOW_TIMEOUT` | `30` | Request timeout, seconds |
| `LOGINFLOW_USER_AGENT` | - | Custom User-Agent |
| `LOGINFLOW_JWKS_URL` | `{LOGIN_FLOW_URL}/oauth2/jwks` | JWKS endpoint |
| `LOGINFLOW_JWKS_CACHE_TTL_SECS` | `600` | How long a downloaded JWKS stays fresh |

`LOGINFLOW_SIGNING_SECRET` no longer exists. Remove it from your deployments.

### Example `.env`

```env
LOGIN_FLOW_URL=https://api.loginflow.dev
LOGIN_FLOW_COMPANY=550e8400-e29b-41d4-a716-446655440000
LOGIN_FLOW_APPLICATION=6ba7b810-9dad-11d1-80b4-00c04fd430c8
LOGINFLOW_ISSUER=https://api.loginflow.dev
```

## 3. Quick start

```rust
use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = LoginFlowClient::from_env()?;

    let result = client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "SecurePass123!".into(),
    }).await?;

    match result {
        LoginResult::Success(resp) => {
            println!("access token: {}", resp.jwt);
            println!("refresh token: {}", resp.refresh_token);
            println!("session: {}", resp.session.id);
        }
        LoginResult::TotpRequired(challenge) => {
            println!("2FA required, totp_token={}", challenge.totp_token);
        }
    }
    Ok(())
}
```

## 4. Tokens

Every login returns two separate tokens:

- `jwt`: the **access token**. Short lived. Send it as `Authorization: Bearer <jwt>`.
- `refresh_token`: always present. Use it with `client.refresh_token(RefreshTokenRequest { refresh_token, session_id })`. It is rotated on every refresh; store the new one. Presenting a rotated token again (more than 2 s later) revokes the session, so `refresh_token` is single-flight: concurrent calls with the same session and token share one request.

All tokens are ES256 JWTs with a `kid` header. The public keys are published at `GET {base_url}/oauth2/jwks`, and discovery is at `{base_url}/.well-known/openid-configuration`.

Claims: `jti`, `iss`, `sub` (= user ID), `aud`, `exp`, `iat`, `user_id`, `company_id`, `application_id`, `email`, `role`, `status`, `token_type`, `created_at`, `expires_in`.
`token_type` is one of `access`, `refresh`, `totp_challenge` and `password_reset`. Consumers accept only `access`.

## 5. Verifying access tokens

```rust
let claims = client.verify_token(&access_token).await?;   // JwtClaims
let user = client.extract_user_from_token(&access_token).await?; // AuthenticatedUser
```

`verify_token` rejects (`LoginFlowError::Authentication`) any token that:

- is not `alg: ES256` or has no `kid`;
- is signed with a key that is not in the issuer's JWKS;
- has `iss` different from `LOGINFLOW_ISSUER`, `aud` different from `LOGIN_FLOW_APPLICATION`, or is past `exp` (30 s leeway);
- lacks `exp`, `iss`, `aud` or `sub`;
- has no `token_type`, a `token_type` other than `access`, or `status` other than `active`.

**JWKS cache.** The key set is downloaded on first use and kept for `LOGINFLOW_JWKS_CACHE_TTL_SECS`; if a later refresh fails, the cached keys keep being served. A token with an unknown `kid` triggers a refresh at most once every 30 s, which is how key rotation is picked up. Concurrent refreshes share one request. The response is capped at 64 KiB, and only `kty=EC`, `crv=P-256`, `alg=ES256` keys are used. If the keys cannot be obtained, the error is `LoginFlowError::Jwks` (HTTP 503 in the Actix extractors).

## 6. Actix integration (feature `actix`)

Register the client in `app_data`. **Without it every extractor fails with a configuration error (HTTP 500)**: tokens are never decoded without verification.

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer};
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::actix::AuthMiddleware;

#[get("/me")]
async fn me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role(),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = LoginFlowClient::from_env().map_err(std::io::Error::other)?;
    HttpServer::new(move || App::new().app_data(web::Data::new(client.clone())).service(me))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
```

| Extractor | Missing/invalid token | Wrong role | No client registered | JWKS unavailable |
|---|---|---|---|---|
| `AuthMiddleware` | 401 | - | 500 | 503 |
| `AdminAuth` (`app_admin` or `master`) | 401 | 403 | 500 | 503 |
| `MasterAuth` (`master`) | 401 | 403 | 500 | 503 |
| `OptionalAuth` | anonymous (`None`) | - | 500 | 503 |

## 7. Features

- **Core auth:** `register`, `login` (`LoginResult`: success or TOTP challenge), `refresh_token`, `logout`
- **OTP login (single flow):** `request_otp_login`, `login_with_otp`. Whether an unknown email gets an account is a per-application server setting.
- **TOTP 2FA:** `setup_totp`, `verify_totp_setup`, `verify_totp_code`, `get_totp_status`, `disable_totp`, `verify_totp_login`
- **OAuth:** `login_with_oauth` (Google / Microsoft ID token)
- **Password:** `request_password_reset`, `verify_reset_code`, `complete_password_reset`, `change_password`
- **Email verification:** `request_email_verification`, `verify_email`, `resend_verification`
- **Delegated auth:** `create_delegated_token` (8-character token, valid 15 minutes), `validate_delegated_token` (token + the creator's email)
- **Account recovery:** `request_account_recovery` (always returns a `ticket_id`)
- **User administration (master token):** `get_account`, `update_account`, `soft_delete_account`, `restore_account`, `hard_delete_account`, `get_profile`, `search_profile_by_email`, `update_profile`, `delete_profile`
- **Token verification:** `verify_token`, `extract_user_from_token`, `JwksCache`
- **Multi-tenant (feature):** `MultiTenantExt` with `*_with_company` variants

## 8. Server contract

Success responses:

```json
{ "data": { "...": "..." }, "meta": { "status": 200, "timestamp": "...", "request_id": "...", "path": "/v1/..." } }
```

Errors:

```json
{ "error": { "code": "...", "message": "...", "details": "..." }, "meta": { "...": "..." } }
```

The SDK maps the HTTP status to `LoginFlowError` (`Validation`, `Authentication`, `Authorization`, `NotFound`, `RateLimit`, `ServiceUnavailable`, `ServerError`, ...) and extracts `error.message`. Error bodies are read up to 4 KiB.

A `429` is `RateLimit { message, retry_after_secs }`, where `retry_after_secs` is the `Retry-After` header (`None` when absent). A `503` is `ServiceUnavailable` (the server is busy; try again later). Both are retryable, and both are errors on the calls that answer `bool` (`verify_email`, `resend_verification`), which return `false` only when the server rejects the request.

The public flows never reveal whether an account exists: `request_otp_login`, `request_password_reset`, `request_email_verification` and `resend_verification` succeed the same way whether or not a code was sent, `register` answers an existing email with the same shape (random `user_id`), and `request_account_recovery` always returns a ticket. A rejected OTP code or delegated token is `Authentication("The code is invalid or has expired")`; a rejected reset code is `Authentication("Invalid or expired reset code")`. See [docs/14-sdk-api-traceability.md](docs/14-sdk-api-traceability.md).

## 9. SDK to API map

| SDK method | Route |
|---|---|
| `register` | `POST /v1/public/user-accounts` |
| `login` | `POST /v1/public/login-password` |
| `refresh_token` | `POST /v1/public/refresh-token` |
| `logout` | `POST /v1/user/logout` |
| `request_otp_login` | `POST /v1/public/request-otp-login` |
| `login_with_otp` | `POST /v1/public/login-with-otp` |
| `verify_totp_login` | `POST /v1/public/verify-totp` |
| `setup_totp` | `POST /v1/user/totp/setup` |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` |
| `verify_totp_code` | `POST /v1/user/totp/verify-code` |
| `get_totp_status` | `GET /v1/user/totp/status` |
| `disable_totp` | `POST /v1/user/totp/disable` |
| `login_with_oauth` | `POST /v1/public/oauth-login` |
| `request_password_reset` | `POST /v1/public/reset-password` |
| `verify_reset_code` | `POST /v1/public/reset-password/verify` |
| `complete_password_reset` | `POST /v1/public/reset-password/complete` |
| `change_password` | `POST /v1/user/change-password` |
| `request_email_verification` | `POST /v1/public/request-email-verification` |
| `verify_email` | `POST /v1/public/verify-email` |
| `resend_verification` | `POST /v1/public/resend-verification` |
| `create_delegated_token` | `POST /v1/user/auth/create-delegated-token` |
| `validate_delegated_token` | `POST /v1/public/auth/validate-delegated-token` |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` |
| `get_account` / `update_account` / `hard_delete_account` | `GET` / `PATCH` / `DELETE /v1/master/user-accounts/{id}` |
| `soft_delete_account` / `restore_account` | `POST /v1/master/user-accounts/{id}/soft-delete` / `restore` |
| `get_profile` / `update_profile` / `delete_profile` | `GET` / `PATCH` / `DELETE /v1/master/user-profiles/{id}` |
| `search_profile_by_email` | `GET /v1/master/user-profiles/search?email=` |
| JWKS (internal) | `GET /oauth2/jwks` |

## 10. Error handling

```rust
use loginflow_sdk::LoginFlowError;

match client.login(req).await {
    Ok(result) => { /* success or TOTP challenge */ }
    Err(err) if err.requires_reauthentication() => { /* clear the local session, go to login */ }
    Err(LoginFlowError::Validation(msg)) => eprintln!("invalid input: {msg}"),
    Err(err) if err.is_retryable() => eprintln!("retry later: {err}"),
    Err(err) => eprintln!("fatal: {err}"),
}
```

## 11. Reference

- [TUTORIAL.md](TUTORIAL.md)
- [CHANGELOG.md](CHANGELOG.md): 0.4.x to 0.5.0 migration guide
- `docs/01-configuration.md` to `docs/14-sdk-api-traceability.md`
