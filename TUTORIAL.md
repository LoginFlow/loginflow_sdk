# Implementation tutorial: LoginFlow SDK

A practical integration guide for a Rust service (SDK 0.6.0).

This SDK is for a **backend resource server**: it verifies access tokens, resolves a user's
email on demand, enrolls TOTP, administers accounts/profiles with a master token, and talks
`client_credentials`/introspection to the OIDC provider. It does not log a user in — login
(password, OTP, TOTP, OAuth, Native SSO) goes through the first-party OIDC challenge or the
hosted login page, outside this SDK (see `loginflow_auth`, the Flutter client library, or the
server's `docs/architecture/oidc-provider.md`).

## 1. Setup

### 1.1 Dependency

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.7.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

### 1.2 Environment

```env
LOGINFLOW_URL=https://api.loginflow.dev
LOGINFLOW_COMPANY=<company_id, CP-...>
LOGINFLOW_APPLICATION=<application_id, APP-...>
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

## 2. Verifying an access token

This is the core of what this SDK does: a request arrives at your service with
`Authorization: Bearer <token>`, and you need to know who it is before doing anything else.

```rust
let claims = client.verify_token(&access_token).await?; // JwtClaims
println!("company_user_id={} role={} scope={}", claims.sub, claims.role, claims.scope);
```

`verify_token` checks header `typ: at+jwt` (rejects an ID token or any other LoginFlow JWT reused
as an access token), `alg: ES256` with a `kid` in the issuer's JWKS, `iss`, `aud` and `exp` (30 s
leeway). **The access token carries no PII**: no email, no profile `user_id`, no account status.
If you need the user's email, use `userinfo` (§4) instead of looking for it on a claim.

For the common "give me a typed user" shape:

```rust
let user = client.extract_user_from_token(&access_token).await?; // AuthenticatedUser
println!("{} is {}", user.company_user_id, user.role);
```

## 3. Actix integration

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer};
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::actix::AuthMiddleware;

#[get("/me")]
async fn me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "company_user_id": auth.company_user_id().to_string(),
        "role": auth.role(),
    }))
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

If the client is not registered, the extractors answer HTTP 500 (configuration error) instead of
trusting the token. `AdminAuth`/`MasterAuth` add a role check (403 otherwise); `OptionalAuth`
yields `None` instead of a 401 when the header is missing or the token is rejected.

## 4. Resolving an email (`userinfo`)

```rust
let info = client.userinfo(&access_token).await?; // UserInfoResponse
if let Some(email) = info.email {
    println!("{email}");
}
```

The server resolves `email`/`role`/`user_id` live, gated by the token's scope (`email`,
`profile`) — nothing here is ever cached on the access token.

## 5. TOTP enrollment (authenticated user)

```rust
let setup = client.setup_totp(&access_token, Some("Acme Back Office")).await?;
println!("otpauth uri: {}", setup.otpauth_uri); // render as a QR code

client.verify_totp_setup(&access_token, "123456").await?; // activates TOTP
let status = client.get_totp_status(&access_token).await?;
println!("enabled={}", status.enabled);

client.disable_totp(&access_token, "123456").await?;
```

TOTP as a login second factor is the challenge's own `next: totp` step, not an SDK call — this
is only the enrollment/management API.

## 6. Changing a password

```rust
use loginflow_sdk::ChangePasswordRequest;

match client.change_password(&access_token, ChangePasswordRequest {
    new_password: "AnotherPass123!".into(),
}).await {
    Ok(resp) => println!("{}", resp.message),
    Err(loginflow_sdk::LoginFlowError::InsufficientUserAuthentication { max_age_secs }) => {
        // RFC 9470: the session is too old for this operation. Send the user through a
        // fresh login step-up, then retry.
        eprintln!("needs recent auth within {max_age_secs:?}s");
    }
    Err(err) => eprintln!("{err}"),
}
```

## 7. Account recovery

```rust
use loginflow_sdk::AccountRecoveryRequest;

let recovery = client.request_account_recovery(AccountRecoveryRequest {
    old_email: "lost@example.com".into(),
    new_email: "found@example.com".into(),
    reason: "lost access to the old mailbox".into(),
    full_name: None,
    phone: None,
    additional_info: None,
    language: Some("en".into()),
}).await?;
println!("ticket={} support={}", recovery.ticket_id, recovery.support_contact);
```

Always returns a ticket, whether or not `old_email` has an account — this is an
anti-enumeration guarantee, not a bug.

## 8. Account/profile administration (master token)

```rust
use loginflow_sdk::UpdateUserAccountRequest;

let account = client.get_account(&master_token, &account_id).await?; // FullUserAccountResponse

client.update_account(&master_token, &account_id, UpdateUserAccountRequest {
    role: Some("app_admin".into()),
    auth_type: None,
    is_active: None,
}).await?;

client.soft_delete_account(&master_token, &account_id).await?;
client.restore_account(&master_token, &account_id).await?;
client.hard_delete_account(&master_token, &account_id).await?; // permanent

let profile = client.search_profile_by_email(&master_token, "user@example.com").await?;
```

## 9. Service-to-service: `client_credentials` and introspection

A confidential client calling another backend needs no `LoginFlowConfig` — just the token
endpoint URL and its own credentials:

```rust
use loginflow_sdk::{ClientCredentialsClient, IntrospectionClient};
use reqwest::Client;

let cc = ClientCredentialsClient::new(
    Client::new(),
    "https://api.loginflow.dev/oauth2/token",
    "my-service-client",
    std::env::var("MY_SERVICE_CLIENT_SECRET")?,
).with_scope("internal");

let token = cc.access_token().await?; // cached, refreshed shortly before expiry, single-flight

let introspection = IntrospectionClient::new(
    Client::new(),
    "https://api.loginflow.dev/oauth2/introspect",
    "my-service-client",
    std::env::var("MY_SERVICE_CLIENT_SECRET")?,
);

// For a sensitive operation: a live revocation check, cached per token for ≤30 s.
if introspection.introspect_cached(&some_token).await?.active {
    // proceed
}

// Revoking one of your own tokens early (RFC 7009) needs the same client authentication.
use loginflow_sdk::RevocationClient;
let revoke = RevocationClient::new(
    Client::new(),
    "https://api.loginflow.dev/oauth2/revoke",
    "my-service-client",
    std::env::var("MY_SERVICE_CLIENT_SECRET")?,
);
revoke.revoke(&some_token).await?;
```

None of the three need the endpoint hardcoded — build them with `from_discovery` from
`client.discovery().await?` instead of `new`, once you already have a `LoginFlowClient` for
these three endpoints' tenant.

## 10. Back-channel logout, DPoP and step-up (advanced)

If your service registers a `backchannel_logout_uri`, verify what it receives:

```rust
let logout_claims = client.verify_logout_token(&logout_token).await?;
// Track `logout_claims.jti` yourself to reject a replay — this SDK holds no storage.
```

If your service is a resource server behind a client that uses DPoP (RFC 9449), validate the
proof against the token's `cnf.jkt`:

```rust
use loginflow_sdk::dpop::verify_proof_matches_cnf;

let claims = client.verify_token(&access_token).await?;
if let Some(cnf) = &claims.cnf {
    let dpop_header = /* the request's `DPoP` header */ "...";
    verify_proof_matches_cnf(dpop_header, "POST", "https://my-service.example/resource", &access_token, &cnf.jkt)?;
}
```

Gating your own sensitive endpoint on a recent login (RFC 9470) — the same shape
`change_password` already enforces:

```rust
let claims = client.verify_token(&access_token).await?;
claims.require_recent_auth(300)?; // Err(InsufficientUserAuthentication) if `auth_time` is stale

// Authorization decisions that care how strong the login was:
if claims.is_phishing_resistant() {
    // a passkey (WebAuthn L3) authenticated this session
} else if !claims.has_mfa() {
    // single factor: maybe require a step-up before a sensitive action
}
```

## 11. Versioning and LTS

This SDK follows the same LTS discipline as the server: every minor (`0.x`) is its own LTS line,
there is no `1.0.0`. `0.6.x` only ever gets fixes and small, non-breaking additions; a breaking
change to a method signature or a claim's meaning ships as `0.7.0`. See README.md §13 for the
full policy.
