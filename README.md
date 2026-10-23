# LoginFlow SDK (Rust)

Async, type-safe SDK for integrating a Rust backend (Actix, Axum, ...) with the LoginFlow OIDC provider.

Sign-in, registration, password reset, email verification and logout go through LoginFlow's
first-party OIDC challenge / hosted login, outside this SDK. This SDK is how a product's API
consumes LoginFlow: its permission manifest and catalog sync, organizations and role
assignments, the verification of every request (RFC 9068 access tokens for this API and this
company, DPoP, permissions), a `client_credentials` client, RFC 7662 introspection,
machine-to-machine user management, access codes for subjects that live in your own database,
and a few account calls made with a person's own token (TOTP enrollment, password change,
userinfo). Upgrading from an earlier release? Read [CHANGELOG.md](CHANGELOG.md) first.

**New to it? Follow [TUTORIAL.md](TUTORIAL.md)**: the step-by-step integration of a Rust backend,
on RutaFácil's `apps/server`. This README is the reference.

What stays in the product is only what is specific to it: `permissions.yaml`, the route table of
its `PermissionRouter`, and its ownership checks (filtering by the token's organization).

## 1. Installation

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.14.0" }

[dev-dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.14.0", features = ["testing"] }
```

### Feature flags

- `actix` (default): `PermissionRouter`, its gate and the `Authorized` extractor.
- `testing`: helpers for a product's own tests (`assert_router_covers_manifest`,
  `assert_no_unrouted_registrations`, `signed_test_token`, `FakeVerifier`). Dev-dependencies only.

Without Actix: `default-features = false`; `TokenVerifier::verify_presented` is framework-agnostic.

## 2. Configuration

Each API of a product has its own audience and its own machine key.

### Required variables

| Variable | Description |
|---|---|
| `LOGINFLOW_URL` | Base URL without version, e.g. `https://api.loginflow.dev` |
| `LOGINFLOW_COMPANY` | Company ID (`CP-...`). Access tokens are accepted only when `company_id` equals it |
| `LOGINFLOW_API` | Audience of this API. Access tokens are accepted only when `aud` equals it (never the issuer) |
| `LOGINFLOW_ISSUER` | Expected `iss` of every token: `https://api.loginflow.dev` (dev: `https://api-dev.loginflow.dev`) |
| `LOGINFLOW_CLIENT_ID` / `LOGINFLOW_CLIENT_SECRET` | The API's machine key: catalog sync, organizations, members, users, access codes and overage introspection (read by your code and passed to the clients; not part of `LoginFlowConfig`) |

### Optional variables

| Variable | Default | Description |
|---|---|---|
| `LOGINFLOW_VERSION` | `1` | API version |
| `LOGINFLOW_TIMEOUT` | `30` | Request timeout, seconds |
| `LOGINFLOW_USER_AGENT` | - | Custom User-Agent |
| `LOGINFLOW_JWKS_URL` | `{LOGINFLOW_URL}/oauth2/jwks` | JWKS endpoint |
| `LOGINFLOW_JWKS_CACHE_TTL_SECS` | `600` | How long a downloaded JWKS stays fresh |
| `LOGINFLOW_RESOURCE_BASE_URL` | derived from the request | Public base URL of this resource server, used as the base of a DPoP proof's expected `htu` (set it behind a reverse proxy) |

### Example `.env`

```env
LOGINFLOW_URL=https://api.loginflow.dev
LOGINFLOW_COMPANY=CP-01JABCDEF
# An API created before APIs existed keeps the application id as its audience.
LOGINFLOW_API=APP-01JABCDEF
LOGINFLOW_ISSUER=https://api.loginflow.dev
LOGINFLOW_CLIENT_ID=rutafacil-api
LOGINFLOW_CLIENT_SECRET=...
```

## 3. Permissions

### 3.1 The manifest (`permissions.yaml`)

```yaml
app: rutafacil                 # the application's permission prefix (`loginflow` is reserved)
resources:
  drivers:
    description: Drivers of the client company
    sensitive: true            # left out of the panel's "Support" template
    read:
      - { action: list, description: List the drivers }
    write:
      - { action: create, description: Register a driver }
    special:
      - { action: issueCode, description: Issue a driver's access code }
```

Every permission is `{app}.{resource}.{action}` (`rutafacil.drivers.create`). `PermissionManifest::load`
refuses what the LoginFlow catalog would refuse: a bad prefix, `loginflow`, names outside
`[a-z][a-zA-Z0-9_]*`, a resource key over 60 or a permission key over 150 characters, a duplicate
action, a description empty or over 500 characters, more than 200 resources, 0 or more than 500
permissions, an unknown field.

### 3.2 Sync at start-up

```rust
use std::path::Path;
use loginflow_sdk::{CatalogClient, LoginFlowConfig, PermissionManifest};

let manifest = PermissionManifest::load(Path::new("permissions.yaml"))?;
let catalog = CatalogClient::new(LoginFlowConfig::from_env()?, client_id, client_secret)?;
let report = catalog.sync(&manifest).await?; // scope loginflow.catalog.read loginflow.catalog.write
// report.added / reactivated / obsoleted / unchanged; the same manifest again changes nothing.
```

The server takes the application and the API from the key's token: a sync touches the
catalog of THAT API only. `409` codes: `catalog_app_mismatch`, `catalog_prefix_taken`,
`resource_owned_by_other_api`, `permission_used_by_sign_in_gate`, `system_catalog`; `403`
`catalog_writer_not_allowed` when the key is not the key of an API of the application's owner
company; `422` with the server's reason as the `Validation` message.

### 3.3 Organizations and members

```rust
use loginflow_sdk::{GrantMember, MembersClient, OrganizationsClient, Principal};

let organizations = OrganizationsClient::new(config.clone(), &client_id, &client_secret)?;
let org = organizations.ensure("client-7", "Transportes Ruiz").await?; // PUT, 201 or 200
let root = organizations.root().await?;                                // the whole application

let members = MembersClient::new(config, &client_id, &client_secret)?;
let roles = members.grantable_roles().await?; // the roles THIS key may grant; empty for a new key
members
    .grant(&GrantMember {
        organization_id: org.id.clone(),
        role_key: "driver".into(),
        principal: Principal::AccessSubject { external_subject: "driver:42".into() },
        expires_at: None, // or Some(DateTime<Utc>): sent as RFC 3339 with its offset (`...Z`)
    })
    .await?; // scope loginflow.assignments.read loginflow.assignments.write
```

Roles themselves (which permissions each one holds), and which roles a key may grant, are
edited in the LoginFlow panel by the application's owner; the key grants and revokes only the
roles in its list (`403` `Authorization { code: Some("role_not_grantable") }` otherwise; the
other refusals are `NotFound` `organization_not_found` / `role_not_found` / `member_not_found`,
`Validation` `expires_at_in_past` / `role_not_assignable_here`, `Conflict`
`system_application`). The
key is for provisioning the system starts itself (drivers by access code). A grant a PERSON
starts (an owner inviting a client admin) goes through `/v1/app/members` with that person's own
token, from the product's frontend (`loginflow_auth`): never through the backend's key.

## 4. Protecting the API (feature `actix`)

```rust
use std::sync::Arc;
use actix_web::http::Method;
use actix_web::{App, HttpResponse, HttpServer};
use loginflow_sdk::actix::{Authorized, PermissionRouter};
use loginflow_sdk::{InMemoryJtiReplayCache, IntrospectionClient, LoginFlowClient, TokenVerifier};

async fn list_drivers(auth: Authorized) -> HttpResponse {
    // Scope every query by the token's organization — never by an id from the body or path.
    HttpResponse::Ok().json(repository::drivers_of(auth.org_id()))
}

let client = LoginFlowClient::from_env()?;
let discovery = client.discovery().await?.clone();
let introspection = IntrospectionClient::from_discovery(reqwest::Client::new(), &discovery, &client_id, &client_secret);
let verifier = Arc::new(TokenVerifier::new(client, Arc::new(InMemoryJtiReplayCache::new()), introspection));

let router = PermissionRouter::new(Arc::new(manifest))
    .public(Method::GET, "/health", health)
    .route(Method::GET, "/drivers", "rutafacil.drivers.list", list_drivers)
    .route(Method::POST, "/drivers", "rutafacil.drivers.create", create_driver)
    .build()?; // refuses a permission the manifest does not declare, a duplicate, a relative path

HttpServer::new(move || {
    App::new()
        .wrap(router.gate(verifier.clone())) // wrap the whole App
        .configure(|cfg| router.configure(cfg))
})
```

Register the router at the root of the `App` with full paths. For every request the gate decides
(a `401` carries `WWW-Authenticate: Bearer error="invalid_token"`, or `DPoP error="invalid_token",
algs="ES256"` when the request used the `DPoP` scheme):

| Case | Answer |
|---|---|
| Route (method + pattern) not in the table — a raw `App::route`, a path nobody registered | `403 {"error":"permission_unmapped"}` |
| Public route | the handler runs, no token needed |
| Token missing, malformed, other scheme; `alg` not ES256; `typ` not `at+jwt`; unknown `kid`; bad signature; `iss` not `LOGINFLOW_ISSUER`; `aud` not `LOGINFLOW_API`; `company_id` not `LOGINFLOW_COMPANY`; expired (30 s leeway) | `401 {"error":"invalid_token"}` (the reason is logged, never sent) |
| DPoP: a `cnf`-bound token not under `DPoP`, a plain token under `DPoP`, no/two proofs, a proof for another method or URL, from another key, not binding this token (`ath`), stale, already used (`jti`), or whose `jwk` carries a private key | `401 invalid_token` |
| Keys (JWKS) cannot be obtained; overage permissions cannot be read | `503 {"error":"authorization_unavailable"}` (fails closed) |
| Token without an active organization | `403 {"error":"organization_required"}` |
| Token without the route's permission | `403 {"error":"permission_denied"}` |

The handler reads `Authorized`: `sub()`, `org_id()`, `org_external_id()`, `company_id()`,
`permissions()`, `has(p)`, `require(p)` (a finer check inside the handler), `subject()` (an
access-code subject's `ext_sub`/`subject_kind`/`ext_profile`), `dpop_jkt()`, `claims()`.
Asking for `Authorized` on a public route answers `500`: there is never an unverified caller.

**Overage.** A token whose permissions did not fit (`permissions_overage: true`) is decided by
the live set from `POST /oauth2/introspect`, authenticated as this API's key (cached ≤ 30 s per
token).

**DPoP replay.** `InMemoryJtiReplayCache` covers one process; with several instances, implement
`JtiReplayCache` on a shared store (e.g. Redis `SET NX EX`). A full in-memory cache refuses new
proofs rather than evicting live ones.

### 4.1 Tests in the product (feature `testing`)

```rust
use loginflow_sdk::testing::{assert_no_unrouted_registrations, assert_router_covers_manifest, signed_test_token, FakeVerifier};

#[test]
fn every_route_is_mapped() {
    assert_router_covers_manifest(&routes::router(), &manifest()); // every permission guards a route
    assert_no_unrouted_registrations(Path::new("src"));             // no #[get], web::resource, App::route("...")
}

#[actix_web::test]
async fn drivers_are_scoped_to_the_token_organization() {
    // The audience and company the real verifier is configured with (LOGINFLOW_API,
    // LOGINFLOW_COMPANY); without `with_company` it accepts `FAKE_COMPANY_ID` (`CP-TEST`).
    let verifier = Arc::new(FakeVerifier::new("https://drivers.api.test")?.with_company("CP-01JABCDEF"));
    let token = signed_test_token(&verifier, &verifier.claims("CU-1", Some("org-1"), &["rutafacil.drivers.list"]))?;
    // App::new().wrap(router.gate(verifier.clone())).configure(...) and call it with `Bearer {token}`
}
```

`FakeVerifier` applies every check of `TokenVerifier` but the JWKS download and introspection
(an overage token is a `503`).

## 5. Tokens

Access tokens are RFC 9068 JWTs for ONE API: header `typ: at+jwt`, `alg: ES256`, a `kid`. The
public keys are published at `GET {base_url}/oauth2/jwks`, and discovery is at
`{base_url}/.well-known/openid-configuration`.

`AccessClaims`: `jti`, `iss`, `sub` (= `company_users.id`, an access-code subject id, or the
client_id of a `client_credentials` token), `aud` (the API), `exp`, `iat`, `client_id`, `scope`,
`sid`, `auth_time`, `amr`, `acr`, `company_id`, `app` (the application), `org_id` / `org_ext`
(the active organization), `permissions` (`TokenPermissions::Listed(set)` or `Overage`, from the
`permissions` and `permissions_overage` claims), `cnf` (DPoP-bound tokens), `auth_cid`
(federations), `access_subject`. **The access token carries no PII**: resolve an email, when
actually needed, through `LoginFlowClient::userinfo` (scope `email`).

**`acr`/MFA helpers**, for an authorization decision that needs to know how strong the login
was (`auth.claims()` in a handler):

```rust
if claims.is_phishing_resistant() { /* a passkey authenticated this session */ }
if claims.has_mfa() { /* a passkey, or two independent factors */ }
claims.require_recent_auth(300)?; // RFC 9470 step-up: Err(InsufficientUserAuthentication { .. })
```

A `LoginFlowError::InsufficientUserAuthentication` returned from your own handler sends the same
`401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=<n>`
challenge LoginFlow's server sends.

**JWKS cache.** The key set is downloaded on first use and kept for
`LOGINFLOW_JWKS_CACHE_TTL_SECS`; if a later refresh fails, the cached keys keep being served. A
token with an unknown `kid` triggers a refresh at most once every 30 s (key rotation).
Concurrent refreshes share one request. The response is capped at 64 KiB, and only `kty=EC`,
`crv=P-256`, `alg=ES256` keys are used.

Refresh tokens are opaque (`lfrt_...`) and never seen by this SDK.

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
[`DiscoveryDocument`](#8-server-contract) instead of `new`:

```rust
let discovery = client.discovery().await?;
let cc = ClientCredentialsClient::from_discovery(Client::new(), discovery, "my-service-client", secret.clone());
let introspection = IntrospectionClient::from_discovery(Client::new(), discovery, "my-service-client", secret.clone());
let revoke = RevocationClient::from_discovery(Client::new(), discovery, "my-service-client", secret);
```

## 6a. Managing users from a backend: `ServiceUsersClient`

A confidential OAuth client with the `client_credentials` grant and the `loginflow.users.read`
and `loginflow.users.write` permissions (granted in the LoginFlow panel) manages the users of its
own company and application. What a user may do is not part of the account: grant roles with
`MembersClient`. The company and application come only
from the token: the client cannot reach another tenant's users.

```rust
use loginflow_sdk::{CreateServiceUserRequest, LoginFlowConfig, ServiceUsersClient};

let users = ServiceUsersClient::new(
    LoginFlowConfig::from_env()?,
    "billing-service",                         // client_id
    std::env::var("BILLING_CLIENT_SECRET")?,   // shown once by the dashboard
)?;
// or ServiceUsersClient::from_discovery(config, client.discovery().await?, client_id, secret)?

let user = users
    .create(CreateServiceUserRequest {
        email: "ana@example.com".into(),
        first_name: Some("Ana".into()),
        last_name: None,
        send_invitation: true, // email the application's invitation (default false)
    })
    .await?; // 409 Conflict when the email is already registered in this application
// The account is active: the user signs in with an email OTP, then sets a password.
// `user.invitation`: Some(Sent | Failed | RateLimited) — a failed invitation never fails the
// create. The email is the editable `account_invitation` template ("Templates & send"), with the
// application's sign-in and Android/iOS/desktop links set in the dashboard.
// `user.id` is the `company_users` id, the same value as the `sub` of that person's tokens.

let all = users.list().await?;
let one = users.get(&user.id).await?;            // NotFound outside this company/application
users.set_active(&user.id, false).await?;        // deactivating revokes the user's sessions;
                                                 // 403 principal_outranks_client for a person
                                                 // holding a role the key may not grant
let gone = users.delete(&user.id).await?;         // permanent; 409 Conflict if data depends on it
println!("profile deleted too: {}", gone.profile_deleted);
```

A user's email is not changed from here: the person changes their own from the app
(`loginflow_auth`'s `startEmailChange` / `confirmEmailChange`, `/v1/app/email-change`), and an
operator corrects one from the LoginFlow panel.

The token is cached and shared by clones. When the API rejects it (`401`, e.g. revoked or
re-scoped before it expired) the client fetches a fresh one and resends the request exactly
once; `invalidate_token()` drops it on demand. A `401` with any other envelope code is about the
request itself, and is never resent.

## 6b. Userinfo and back-channel logout

```rust
// The one sanctioned way to read a user's email — never off an access token claim. The token
// must carry `openid` and be a plain Bearer token: a DPoP-bound one needs the person's device
// key, which a backend never holds (the same holds for the TOTP and password calls).
let info = client.userinfo(&access_token).await?; // UserInfoResponse { sub, user_id, email }

// Verifying a logout token delivered to this RP's own `backchannel_logout_uri`
// (OIDC Back-Channel Logout 1.0 §2.6). LoginFlow addresses it to the RP's client_id.
let logout_claims = client.verify_logout_token(&logout_token, "console").await?;
// Single use of its `jti`: record it (a `JtiReplayCache` does) and reject a repeat.
```

## 6c. Access codes for your own subjects: `AccessCodesClient`

For people or devices that live in YOUR database, not in LoginFlow (a driver, a student, a
kiosk): your backend issues a one-time code, the person or device types it in the app
(`loginflow_auth`, native challenge `method=access_code`, DPoP required) and gets a LoginFlow
session bound to that device. Code once, then passkey: right after the code the app may enroll a
passkey for the subject (`loginflow_auth` `enrollPasskey`), and every later sign-in on that phone
is the passkey alone (`signInWithPasskey()`), with the same subject tokens. LoginFlow keeps no PII
for them, only a minimal subject record.

Needs a confidential OAuth client with the `client_credentials` grant and the
`loginflow.accessCodes.issue`, `loginflow.accessCodes.read` and `loginflow.accessCodes.revoke`
permissions, and access codes enabled for the application (dashboard,
application settings). The app's sign-in client lists the `access_code` login method (with
`passkey` for the passkey after the code). The company and application come only from the
token.

```rust
use loginflow_sdk::{
    ACCESS_CODES_DISABLED_CODE, AccessCodesClient, IssueAccessCodeRequest, LoginFlowConfig,
    LoginFlowError, SubjectKind,
};

let codes = AccessCodesClient::new(
    LoginFlowConfig::from_env()?,
    "rutafacil-backend",                         // client_id
    std::env::var("RUTAFACIL_CLIENT_SECRET")?,   // shown once by the dashboard
)?;

match codes
    .issue(IssueAccessCodeRequest {
        subject_kind: SubjectKind::Person,       // or Device
        external_subject: "driver:42".into(),    // your id: <=128 chars of [A-Za-z0-9:._-]
        profile: "Driver".into(),                // yours, <=40 chars
        display_name: None,                      // optional, <=80 chars, no PII needed
        ttl_minutes: None,                       // 420..=7200; None = the application default
        revoke_existing_sessions: None,          // Some(true) also ends its sessions and deletes its passkeys
    })
    .await
{
    // `issued.code` is `XXXX-XXXX` and is returned ONLY here. A new code for the same
    // `external_subject` replaces the previous live one. `Debug` redacts it.
    Ok(issued) => show_to_driver(&issued.code, &issued.expires_at),
    Err(LoginFlowError::Conflict { code, .. }) if code.as_deref() == Some(ACCESS_CODES_DISABLED_CODE) => {
        // access codes are off for this application
    }
    Err(err) => return Err(err.into()), // 422 Validation: bad subject/profile, ttl out of range
}

let live = codes.list(Some("driver:42")).await?;      // AccessCodeInfo, never the code
codes.revoke(&live[0].id).await?;                     // DELETE, 204
let ended = codes.revoke_subject_sessions("driver:42").await?; // sessions, passkeys and live code
println!("{} sessions ended", ended.revoked_sessions);
```

The token handling is the same as `ServiceUsersClient` (cached, one retry on a rejected token).

On your resource server, a token minted for such a subject has `sub` = the LoginFlow subject id
(`AS-...`) and the extra claims `ext_sub` (your `external_subject`), `subject_kind` and
`ext_profile` (your `profile` label; named apart from the registered OIDC `profile` claim, a
URL). A session the subject opened with its passkey carries the same claims, with `amr`
`hwk`/`swk` and the phishing-resistant `acr` (`claims.is_phishing_resistant()`); one opened with
the code has `amr` `otp`. Grant the subject its role with `MembersClient`
(`Principal::AccessSubject`), and map the token back to your own record in the handler:

```rust
if let Some(subject) = auth.subject() {
    let driver_id = &subject.ext_sub;                     // "driver:42"
    let kind = subject.kind();                            // Some(SubjectKind::Person)
}
```

## 7. Features

- **Permissions:** `PermissionManifest`, `CatalogClient` (`sync`, `get`; scope `loginflow.catalog.read loginflow.catalog.write`), `OrganizationsClient` (`ensure`, `get`, `find_by_external_id`, `list`, `root`, `delete`; scope `loginflow.organizations.read loginflow.organizations.write`), `MembersClient` (`grantable_roles`, `grant`, `revoke`, `list`; scope `loginflow.assignments.read loginflow.assignments.write`)
- **Request verification:** `TokenVerifier` (JWKS, ES256 allow-list, `iss`/`aud`/`exp`/`typ`, DPoP with `JtiReplayCache`, overage through introspection), `PermissionRouter` + gate + `Authorized` (feature `actix`), `testing` helpers
- **Userinfo:** `userinfo` — the one sanctioned way to resolve an email live
- **Back-channel logout:** `verify_logout_token` (OIDC Back-Channel Logout 1.0 §2.6)
- **`client_credentials` / introspection:** `ClientCredentialsClient` (plus `invalidate`), `IntrospectionClient` (plus `introspect_cached`, a ≤30 s cache for sensitive operations)
- **Machine-to-machine user management:** `ServiceUsersClient` (`create` with an optional invitation, `list`, `get`, `set_active`, `delete`; scope `loginflow.users.read loginflow.users.write`)
- **Access codes:** `AccessCodesClient` (`issue`, `list`, `revoke`, `revoke_subject_sessions`; scope `loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke`), and `AccessClaims::access_subject` on the subject's tokens
- **TOTP enrollment:** `setup_totp`, `verify_totp_setup`, `get_totp_status`, `disable_totp`
- **Password:** `change_password` (`{new_password}`, RFC 9470 step-up)
- **Account recovery:** `request_account_recovery` (always returns a `ticket_id`)

Password login, registration, OTP login, TOTP login, OAuth login, password reset and email
verification are not part of this SDK: they go through the OIDC challenge / hosted login.

## 8. Server contract

Success responses:

```json
{ "data": { "...": "..." }, "meta": { "status": 200, "timestamp": "...", "request_id": "...", "path": "/v1/..." } }
```

Errors:

```json
{ "error": { "code": "...", "message": "...", "details": "..." }, "meta": { "...": "..." } }
```

The SDK maps the HTTP status to `LoginFlowError`: `400`/`422` `Validation { message, code }`, `401` `Authentication` (but `Validation { code: Some("INVALID_CODE") }` for a wrong TOTP code), `403` `Authorization { message, code }`, `404` `NotFound { message, code }`, `409` `Conflict { message, code }`, `429` `RateLimit`, `503` `ServiceUnavailable`, other `5xx` `ServerError`. `code` is `error.code`; the message is `error.details` when it is text (the specific reason of a validation error), otherwise `error.message`. Error bodies are read up to 4 KiB.

A `429` is `RateLimit { message, retry_after_secs }`, where `retry_after_secs` is the `Retry-After` header (`None` when absent). A `503` is `ServiceUnavailable` (the server is busy; try again later). A `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470) is `InsufficientUserAuthentication { max_age_secs }`, not a plain `Authentication` error: the credential is fine, the session is just too old for this operation (e.g. `change_password`), and the caller should have the user re-authenticate and retry.

The `/oauth2/token`, `/oauth2/introspect` and `/.well-known/*` endpoints sit outside this envelope (plain RFC 6749/7662/8414 bodies); `ClientCredentialsClient`/`IntrospectionClient` parse those directly.

## 9. SDK to API map

| SDK method | Route |
|---|---|
| `setup_totp` | `POST /v1/user/totp/setup` |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` |
| `get_totp_status` | `GET /v1/user/totp/status` |
| `disable_totp` | `POST /v1/user/totp/disable` |
| `change_password` | `POST /v1/user/change-password` |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` |
| `userinfo` | `GET /oauth2/userinfo` (resolved from discovery) |
| JWKS (internal) | `GET /oauth2/jwks` (default convention; `discovery().jwks_uri` is the same URL) |
| `discovery` | `GET /.well-known/openid-configuration` |
| `ClientCredentialsClient::access_token` | `POST /oauth2/token` (`grant_type=client_credentials`) |
| `IntrospectionClient::introspect` / `introspect_cached` | `POST /oauth2/introspect` |
| `RevocationClient::revoke` | `POST /oauth2/revoke` |
| `CatalogClient::sync` / `get` | `PUT` / `GET /v1/service/catalog` |
| `OrganizationsClient::ensure` | `PUT /v1/service/organizations/external/{external_id}` |
| `OrganizationsClient::list` / `find_by_external_id` / `root` | `GET /v1/service/organizations[?external_id=&limit=&offset=]` |
| `OrganizationsClient::get` / `delete` | `GET` / `DELETE /v1/service/organizations/{id}` |
| `MembersClient::grantable_roles` | `GET /v1/service/members/grantable-roles` |
| `MembersClient::grant` / `list` | `POST` / `GET /v1/service/members[?organization_id=&principal_id=&external_subject=&role_key=]` |
| `MembersClient::revoke` | `DELETE /v1/service/members/assignments/{id}` |
| `TokenVerifier` (overage only) | `POST /oauth2/introspect` |
| `ServiceUsersClient::create` / `list` | `POST` / `GET /v1/service/users` |
| `ServiceUsersClient::get` / `set_active` / `delete` | `GET` / `PATCH` / `DELETE /v1/service/users/{id}` |
| `AccessCodesClient::issue` / `list` | `POST` / `GET /v1/service/access-codes[?external_subject=]` |
| `AccessCodesClient::revoke` | `DELETE /v1/service/access-codes/{id}` |
| `AccessCodesClient::revoke_subject_sessions` | `POST /v1/service/access-subjects/revoke` |
| `verify_logout_token` / `TokenVerifier` / `AccessClaims::require_recent_auth` | local verification (no HTTP call, except overage introspection) |

## 10. Error handling

```rust
use loginflow_sdk::LoginFlowError;

match client.change_password(&access_token, req).await {
    Ok(_) => { /* success */ }
    Err(LoginFlowError::InsufficientUserAuthentication { max_age_secs }) => {
        /* send the user through a fresh login step-up, then retry */
    }
    Err(err) if err.requires_reauthentication() => { /* clear the local session, go to login */ }
    Err(LoginFlowError::Validation { message, .. }) => eprintln!("invalid input: {message}"),
    Err(err) if err.is_retryable() => eprintln!("retry later: {err}"),
    Err(err) => eprintln!("fatal: {err}"),
}
```

## 11. Reference

- [TUTORIAL.md](TUTORIAL.md)
- [CHANGELOG.md](CHANGELOG.md): migration guides, including 0.13.x to 0.14.0 (error codes)
- `docs/01-configuration.md`, `docs/06-totp-2fa.md`, `docs/10-jwt-local-verification.md`,
  `docs/11-actix-integration.md`, `docs/13-error-handling.md`, `docs/14-sdk-api-traceability.md`
  (the numbering has gaps on purpose: the login-REST docs — password, OTP, OAuth, password
  reset, email verification, refresh/logout, multi-tenant — and the user-account/profile
  administration doc were deleted with the methods they documented)

## 12. Versioning

Every minor version (`0.x`) is its own line — there is no `1.0.0`. A breaking change to the
public surface (removing or renaming a method, changing a type or a claim's meaning, tightening a
check that used to pass) only ships in a new minor, with a **Breaking** section and a migration
note in [CHANGELOG.md](CHANGELOG.md). A patch (`0.14.1`, ...) carries fixes and additions that
break nothing.
