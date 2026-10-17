# LoginFlow SDK (Rust)

Async, type-safe SDK for integrating a Rust backend (Actix, Axum, ...) with the LoginFlow OIDC provider.

Sign-in, registration, password reset, email verification and logout go through LoginFlow's
first-party OIDC challenge / hosted login, outside this SDK. This SDK covers what a backend
resource server needs: RFC 9068 access-token verification, a `client_credentials` client,
RFC 7662 introspection, and the account/profile APIs. Upgrading from 0.5.x? Read
[CHANGELOG.md](CHANGELOG.md) first.

## 1. Installation

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.6.0" }
```

### Feature flags

```toml
# Default: includes the Actix extractors
loginflow_sdk = { git = "...", tag = "v0.6.0" }

# Without Actix
loginflow_sdk = { git = "...", tag = "v0.6.0", default-features = false }
```

- `actix` (default): `AuthMiddleware`, `OptionalAuth`, `AdminAuth`, `MasterAuth` extractors.

## 2. Configuration

### Required variables

| Variable | Description |
|---|---|
| `LOGINFLOW_URL` | Base URL without version, e.g. `https://api.loginflow.dev` |
| `LOGINFLOW_COMPANY` | Company UUID |
| `LOGINFLOW_APPLICATION` | Application UUID. Access tokens are accepted only when `aud` equals it |
| `LOGINFLOW_ISSUER` | Expected `iss` of every token: `https://api.loginflow.dev` (dev: `https://api-dev.loginflow.dev`) |

### Optional variables

| Variable | Default | Description |
|---|---|---|
| `LOGINFLOW_VERSION` | `1` | API version |
| `LOGINFLOW_TIMEOUT` | `30` | Request timeout, seconds |
| `LOGINFLOW_USER_AGENT` | - | Custom User-Agent |
| `LOGINFLOW_JWKS_URL` | `{LOGINFLOW_URL}/oauth2/jwks` | JWKS endpoint |
| `LOGINFLOW_JWKS_CACHE_TTL_SECS` | `600` | How long a downloaded JWKS stays fresh |

### Example `.env`

```env
LOGINFLOW_URL=https://api.loginflow.dev
LOGINFLOW_COMPANY=550e8400-e29b-41d4-a716-446655440000
LOGINFLOW_APPLICATION=6ba7b810-9dad-11d1-80b4-00c04fd430c8
LOGINFLOW_ISSUER=https://api.loginflow.dev
```

## 3. Quick start: verifying an access token

```rust
use loginflow_sdk::LoginFlowClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = LoginFlowClient::from_env()?;

    let claims = client.verify_token("Bearer-token-from-a-request").await?;
    println!("company_user_id={} client_id={} scope={}", claims.sub, claims.client_id, claims.scope);
    Ok(())
}
```

Issuing tokens (password, OTP, TOTP, OAuth, Native SSO) is the hosted/native OIDC challenge's
job, not this SDK's — see the `loginflow_auth` Flutter library or the server's
`docs/architecture/oidc-provider.md` for that side.

## 4. Tokens

Access tokens are RFC 9068 JWTs: header `typ: at+jwt`, `alg: ES256`, a `kid`. The public keys are
published at `GET {base_url}/oauth2/jwks`, and discovery is at
`{base_url}/.well-known/openid-configuration`.

Claims: `jti`, `iss`, `sub` (= `company_users.id`), `aud`, `exp`, `iat`, `client_id`, `scope`,
`sid` (optional — absent for `client_credentials` tokens), `auth_time`, `amr`, `acr` (optional),
`company_id`, `application_id`, `role`, and `cnf` (optional — present only for a DPoP-bound
token, RFC 9449 §6). **The access token carries no PII**: no email, no profile `user_id`, no
account status. Resolve an email, when actually needed, through
[`LoginFlowClient::userinfo`](#5-verifying-access-tokens) (scope `email`/`profile`) — never off a
cached claim.

`JwtClaims` has accessors: `company_user_id()` (= `sub`), `scopes()`, `has_scope(s)`,
`has_amr(m)`, `is_dpop_bound()` — `sid`, `client_id`, `scope` and `auth_time` are plain public
fields.

**`acr`/MFA helpers**, for an authorization decision that needs to know how strong the login
was, not just that it happened:

```rust
if claims.is_phishing_resistant() {
    // a hardware or software passkey (WebAuthn L3) authenticated this session
}
if claims.has_mfa() {
    // a passkey, or two independent factors (password + TOTP/email OTP/recovery code)
}

// RFC 9470 step-up gate for your own sensitive endpoint (change email, delete account, a
// payout — the same shape LoginFlow's own `change_password` already enforces):
claims.require_recent_auth(300)?; // Err(InsufficientUserAuthentication { max_age_secs: Some(300) })
```

A `LoginFlowError::InsufficientUserAuthentication` returned from your own handler (via the
`actix` feature's `ResponseError`) sends the same `401` + `WWW-Authenticate: Bearer
error="insufficient_user_authentication", max_age=<n>` challenge LoginFlow's server sends, so a
client that already knows how to step up for `change_password` handles your endpoint the same
way.

Refresh tokens are opaque (`lfrt_...`) and never seen by this SDK directly: a backend resource
server only ever sees access tokens in the `Authorization` header.

## 5. Verifying access tokens

```rust
let claims = client.verify_token(&access_token).await?;   // JwtClaims
let user = client.extract_user_from_token(&access_token).await?; // AuthenticatedUser
```

`verify_token` rejects (`LoginFlowError::Authentication`) any token that:

- does not have header `typ: at+jwt` (rejects token-type confusion: an ID token, or any other
  valid JWT, reused as an access token);
- is not `alg: ES256` or has no `kid`;
- is signed with a key that is not in the issuer's JWKS;
- has `iss` different from `LOGINFLOW_ISSUER`, `aud` different from `LOGINFLOW_APPLICATION`, or is past `exp` (30 s leeway);
- lacks `exp`, `iss`, `aud` or `sub`.

**JWKS cache.** The key set is downloaded on first use and kept for `LOGINFLOW_JWKS_CACHE_TTL_SECS`; if a later refresh fails, the cached keys keep being served. A token with an unknown `kid` triggers a refresh at most once every 30 s, which is how key rotation is picked up. Concurrent refreshes share one request. The response is capped at 64 KiB, and only `kty=EC`, `crv=P-256`, `alg=ES256` keys are used. If the keys cannot be obtained, the error is `LoginFlowError::Jwks` (HTTP 503 in the Actix extractors).

## 6. `client_credentials` and introspection

For service-to-service calls (a confidential client calling another backend) and for a resource
server that wants the issuer to vouch for a token it did not verify itself:

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
).introspect(&some_token).await?;

if introspection.active {
    println!("token belongs to {:?}", introspection.sub);
}
```

Both clients build their own `reqwest::Client`/endpoint URL and do not need a
`LoginFlowConfig` — a confidential service client usually has no tenant of its own to configure.

For a sensitive operation (money movement, destructive action, privilege change) that wants a
live revocation check without paying a network round trip on every call, use
`introspect_cached` instead of `introspect`: same RFC 7662 answer, cached per token for at most
`INTROSPECTION_CACHE_TTL` (30 s). An `active: false` answer is never cached.

To revoke one of your own confidential client's tokens early (RFC 7009 — the server now requires
`client_secret_basic`, the same authentication `ClientCredentialsClient`/`IntrospectionClient`
use):

```rust
use loginflow_sdk::RevocationClient;

let revoke = RevocationClient::new(
    Client::new(),
    "https://api.loginflow.dev/oauth2/revoke",
    "my-service-client",
    std::env::var("MY_SERVICE_CLIENT_SECRET")?,
);
revoke.revoke(&token).await?;
```

None of the three need a hardcoded endpoint either: build them with `from_discovery` from a
[`DiscoveryDocument`](#9-server-contract) instead of `new`:

```rust
let discovery = client.discovery().await?;
let cc = ClientCredentialsClient::from_discovery(Client::new(), discovery, "my-service-client", secret.clone());
let introspection = IntrospectionClient::from_discovery(Client::new(), discovery, "my-service-client", secret.clone());
let revoke = RevocationClient::from_discovery(Client::new(), discovery, "my-service-client", secret);
```

## 6b. Userinfo, back-channel logout and DPoP

```rust
// The one sanctioned way to read a user's email — never off an access token claim.
let info = client.userinfo(&access_token).await?; // UserInfoResponse { sub, user_id, role, email }

// Verifying a logout token delivered to this RP's own `backchannel_logout_uri`
// (OIDC Back-Channel Logout 1.0 §2.6).
let logout_claims = client.verify_logout_token(&logout_token).await?;
// Single-use `jti` enforcement against replay is the caller's own job: this SDK holds no storage.
```

A resource server that receives DPoP-bound requests (RFC 9449) validates the presented proof
against the access token's `cnf.jkt` with the `dpop` module:

```rust
use loginflow_sdk::dpop::verify_proof_matches_cnf;

let claims = client.verify_token(&access_token).await?;
if let Some(cnf) = &claims.cnf {
    let dpop_header = /* the request's `DPoP` header */ "...";
    verify_proof_matches_cnf(dpop_header, "POST", "https://my-service.example/resource", &access_token, &cnf.jkt)?;
}
```

## 7. Actix integration (feature `actix`)

Register the client in `app_data`. **Without it every extractor fails with a configuration error (HTTP 500)**: tokens are never decoded without verification.

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

## 8. Features

- **Token verification:** `verify_token`, `extract_user_from_token`, `JwksCache`
- **Userinfo:** `userinfo` — the one sanctioned way to resolve an email live
- **Back-channel logout:** `verify_logout_token` (OIDC Back-Channel Logout 1.0 §2.6)
- **DPoP (RFC 9449):** `dpop::verify_proof_matches_cnf`, for a resource server
- **`client_credentials` / introspection:** `ClientCredentialsClient`, `IntrospectionClient` (plus `introspect_cached`, a ≤30 s cache for sensitive operations)
- **TOTP enrollment (account API, unaffected by the login cutover):** `setup_totp`, `verify_totp_setup`, `get_totp_status`, `disable_totp`
- **Password:** `change_password` (reshaped to `{new_password}`, RFC 9470 step-up)
- **Account recovery:** `request_account_recovery` (always returns a `ticket_id`)
- **User administration (master token):** `get_account`, `update_account`, `soft_delete_account`, `restore_account`, `hard_delete_account`, `get_profile`, `search_profile_by_email`, `update_profile`, `delete_profile`

Password login, registration, OTP login, TOTP login, OAuth login, password reset and email
verification are not part of this SDK: they go through the OIDC challenge / hosted login.

## 9. Server contract

Success responses:

```json
{ "data": { "...": "..." }, "meta": { "status": 200, "timestamp": "...", "request_id": "...", "path": "/v1/..." } }
```

Errors:

```json
{ "error": { "code": "...", "message": "...", "details": "..." }, "meta": { "...": "..." } }
```

The SDK maps the HTTP status to `LoginFlowError` (`Validation`, `Authentication`, `Authorization`, `NotFound`, `RateLimit`, `ServiceUnavailable`, `ServerError`, `InsufficientUserAuthentication`, ...) and extracts `error.message`. Error bodies are read up to 4 KiB.

A `429` is `RateLimit { message, retry_after_secs }`, where `retry_after_secs` is the `Retry-After` header (`None` when absent). A `503` is `ServiceUnavailable` (the server is busy; try again later). A `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470) is `InsufficientUserAuthentication { max_age_secs }`, not a plain `Authentication` error: the credential is fine, the session is just too old for this operation (e.g. `change_password`), and the caller should have the user re-authenticate and retry.

The `/oauth2/token`, `/oauth2/introspect` and `/.well-known/*` endpoints sit outside this envelope (plain RFC 6749/7662/8414 bodies); `ClientCredentialsClient`/`IntrospectionClient` parse those directly.

## 10. SDK to API map

| SDK method | Route |
|---|---|
| `setup_totp` | `POST /v1/user/totp/setup` |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` |
| `get_totp_status` | `GET /v1/user/totp/status` |
| `disable_totp` | `POST /v1/user/totp/disable` |
| `change_password` | `POST /v1/user/change-password` |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` |
| `get_account` / `update_account` / `hard_delete_account` | `GET` / `PATCH` / `DELETE /v1/master/user-accounts/{id}` |
| `soft_delete_account` / `restore_account` | `POST /v1/master/user-accounts/{id}/soft-delete` / `restore` |
| `get_profile` / `update_profile` / `delete_profile` | `GET` / `PATCH` / `DELETE /v1/master/user-profiles/{id}` |
| `search_profile_by_email` | `GET /v1/master/user-profiles/search?email=` |
| `userinfo` | `GET /oauth2/userinfo` (resolved from discovery) |
| JWKS (internal) | `GET /oauth2/jwks` (default convention; `discovery().jwks_uri` is the same URL) |
| `discovery` | `GET /.well-known/openid-configuration` |
| `ClientCredentialsClient::access_token` | `POST /oauth2/token` (`grant_type=client_credentials`) |
| `IntrospectionClient::introspect` / `introspect_cached` | `POST /oauth2/introspect` |
| `RevocationClient::revoke` | `POST /oauth2/revoke` |
| `verify_logout_token` / `dpop::verify_proof_matches_cnf` / `JwtClaims::require_recent_auth` | local verification, no HTTP call |

## 11. Error handling

```rust
use loginflow_sdk::LoginFlowError;

match client.change_password(&access_token, req).await {
    Ok(_) => { /* success */ }
    Err(LoginFlowError::InsufficientUserAuthentication { max_age_secs }) => {
        /* send the user through a fresh login step-up, then retry */
    }
    Err(err) if err.requires_reauthentication() => { /* clear the local session, go to login */ }
    Err(LoginFlowError::Validation(msg)) => eprintln!("invalid input: {msg}"),
    Err(err) if err.is_retryable() => eprintln!("retry later: {err}"),
    Err(err) => eprintln!("fatal: {err}"),
}
```

## 12. Reference

- [TUTORIAL.md](TUTORIAL.md)
- [CHANGELOG.md](CHANGELOG.md): 0.5.x to 0.6.0 migration guide
- `docs/01-configuration.md`, `docs/06-totp-2fa.md`, `docs/09-user-accounts-profiles.md`,
  `docs/10-jwt-local-verification.md`, `docs/11-actix-integration.md`, `docs/13-error-handling.md`,
  `docs/14-sdk-api-traceability.md` (the numbering has gaps on purpose: the login-REST docs
  — password, OTP, OAuth, password reset, email verification, refresh/logout, multi-tenant —
  were deleted with the methods they documented)

## 13. Versioning and LTS

Every minor version (`0.x`) is its own LTS line — there will be no `1.0.0`.

- **0.6** is the LTS line this release establishes (API, SDK and `loginflow_auth` aligned on
  `0.6.0`). `0.6.1`, `0.6.2`, … carry fixes, bug corrections and small, simple additions without
  breaking the 0.6 contract (an added field, a new optional helper — nothing that changes an
  existing method's signature or a claim's meaning).
- **0.7** arrives when a genuinely new capability lands (SMS, SAML, push, …) and becomes the new
  LTS; 0.6.x keeps receiving fixes in the meantime.
- A line is declared LTS once every feature in it is proven: exercised in `dev`, on real devices
  where applicable, with consumers migrated and a stable run in production.

A breaking change to this SDK's public surface — removing/renaming a method, changing a claim's
type, tightening a check that used to pass — only ever ships in a new minor, never as a `0.6.x`
patch, mirroring the server's own versioning discipline (see `loginflow_api`'s
`docs/operations/signing-cutover.md`).
