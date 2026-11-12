# LoginFlow SDK (Rust)

Async, type-safe SDK for integrating a Rust backend (Actix, Axum, ...) with the LoginFlow OIDC provider.

Sign-in, registration, password reset, email verification and logout go through LoginFlow's
first-party OIDC challenge / hosted login, outside this SDK. This SDK is how a product's API
consumes LoginFlow: its permission manifest and catalog sync, organizations and role
assignments, the verification of every request (RFC 9068 access tokens for this API and this
company, DPoP, permissions), machine access (another system calling this API, or this API
calling another one, with a short-lived LoginFlow token), a `client_credentials` client, RFC 7662
introspection,
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
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.24.0" }

[dev-dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.24.0", features = ["testing"] }
```

### Feature flags

- `actix` (default): `PermissionRouter`, its gate and the `Authorized`, `MachineAuthorized`,
  `Caller` and `SignedIn` extractors.
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
use loginflow_sdk::actix::Authorized;
use loginflow_sdk::{GrantMember, MembersClient, OrganizationsClient, Principal};

let organizations = OrganizationsClient::new(config.clone(), &client_id, &client_secret)?;
let org = organizations.ensure("client-7", "Transportes Ruiz").await?; // PUT, 201 or 200
let root = organizations.root().await?;                                // the whole application

let members = MembersClient::new(config, &client_id, &client_secret)?;
let roles = members.grantable_roles().await?; // the key's ceiling, each with `held_by`; empty for a new key
// The access token the caller's request carried, as the gate verified it (`auth: Authorized`;
// `SignedIn::access_token` on a signed-in route).
let caller_token = auth.access_token();
members
    .grant(
        &GrantMember {
            organization_id: org.id.clone(),
            role_key: "driver".into(),
            principal: Principal::AccessSubject { external_subject: "driver:42".into() },
            expires_at: None, // or Some(DateTime<Utc>): sent as RFC 3339 with its offset (`...Z`)
        },
        caller_token, // the person the key grants for
    )
    .await?; // scope loginflow.assignments.read loginflow.assignments.write
```

Roles themselves (which permissions each one holds, who holds them: `held_by` `People` or
`AccessCodes`), which roles each role may grant ("Can grant") and which roles a key may grant are
edited in the LoginFlow panel by the application's owner. A key never grants on its own: `grant`
and `revoke` take the `actor_token` — the access token of the person who asked the product, as it
arrived (no DPoP proof needed) — and pass only when the role is in the key's list AND in that
person's Can grant. The refusals keep the server's `code`:
- `Authorization` `key_role_not_grantable` (not in the key's list); `role_not_grantable`,
  `organization_out_of_reach`, `self_assignment_forbidden`, `privilege_exceeds_grantor` (the
  person may not grant it there);
- `Authentication` `invalid_actor_token` (the person's token is expired, revoked, of another
  application or for LoginFlow itself, or an access-code subject's); `Validation`
  `actor_token_required` (an empty token);
- `Validation` `role_not_held_by_principal` (a people role to an access-code subject, or the
  reverse), `expires_at_in_past`, `role_not_assignable_here`;
- `NotFound` `organization_not_found` / `role_not_found` / `member_not_found`; `Conflict`
  `system_application`.

A person managing members with no product in between (an owner inviting a client admin from a
members screen) uses `/v1/app/members` with their own token, from the frontend
(`loginflow_auth`).

### 3.4 Founding an organization: `FoundingClient`

A self-service product lets a signed-in person who belongs to no organization yet create one
("create my company") and become its founder. The product's route for it is a signed-in route
(§4: no organization, no permission); its handler forwards the person's token to
`POST /v1/service/organizations/founded`:

```rust
use loginflow_sdk::actix::SignedIn;
use loginflow_sdk::{FoundOrganizationRequest, FoundingClient, FoundingError};

let founding = FoundingClient::new(config, &client_id, &client_secret)?;
// scope loginflow.organizations.write loginflow.assignments.write

async fn create_my_company(person: SignedIn, founding: &FoundingClient, tenant_id: String) -> Result<(), FoundingError> {
    let founded = founding
        .found(
            &FoundOrganizationRequest { external_id: tenant_id, name: "Barbería Central".into() },
            person.access_token(), // forwarded untouched as `actor_token`
        )
        .await?;
    // founded.organization (as `ensure` returns it), founded.assignment (the founder role, as
    // `grant` returns it), founded.created (`false` on a retry by the same founder: `200`)
    Ok(())
}
```

LoginFlow creates a regular organization under the application's root AND grants the
application's founder role to the person there, in one transaction; it never grants anything on
an organization that already exists. It is the only way a person acquires a role for themselves.
The key must hold `loginflow.organizations.write` and `loginflow.assignments.write`, and the
founder role must be among its grantable roles. `FoundingClient` is a client of its own so that
`OrganizationsClient` and `MembersClient` keep requesting only their own permissions (a key
without `loginflow.assignments.write` keeps using `OrganizationsClient`).

Refusals, typed in `FoundingError`:
- `OrganizationExists` (`409 organization_exists`: that `external_id` exists and the person is
  not its founder);
- `FounderRoleNotConfigured` (`409 founder_role_not_configured`: set the application's founder
  role on the LoginFlow panel);
- `RateLimited { retry_after_secs }` (`429 founding_rate_limited`: at most 5 foundings per person
  and application in a rolling 24 h);
- `KeyRoleNotGrantable` (`403 key_role_not_grantable`: the founder role is not in the key's
  list);
- `LoginFlow(LoginFlowError)` for the rest, with the server's `code`: `Validation`
  `actor_token_required` or the `422` of an invalid `external_id` / `name` (same rules as
  `ensure`), `Authentication` `invalid_actor_token`, `Authorization` `permission_denied`,
  `NotFound` `member_not_found` (the person has no active membership in the application).

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
    .signed_in(Method::POST, "/companies", create_my_company) // any signed-in person, no organization
    .route(Method::GET, "/drivers", "rutafacil.drivers.list", list_drivers)
    .route(Method::POST, "/drivers", "rutafacil.drivers.create", create_driver)
    .build()?; // refuses a permission the manifest does not declare, a duplicate, a relative path

HttpServer::new(move || {
    App::new()
        .wrap(router.gate(verifier.clone())) // wrap the whole App
        .configure(|cfg| router.configure(cfg))
})
```

Route levels, from least to most required:

| Declared with | Who passes | Handler reads |
|---|---|---|
| `public` | anyone, no token | — |
| `signed_in` | a person's verified token, with or without an organization; no permission | `SignedIn` |
| `route` | a person's verified token with an active organization and the permission there | `Authorized` (or `Caller`) |
| `machine` | a machine token with the permission | `MachineAuthorized` (or `Caller`) |
| `person_or_machine` | either of the two above | `Caller` |

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
| Machine token on a route declared for persons (`route`, `signed_in`) | `403 {"error":"machine_not_allowed"}` |
| Access-code subject's token on a signed-in route (`signed_in`) | `403 {"error":"access_subject_not_allowed"}` |
| Person's token on a route declared for machines only (`machine`) | `403 {"error":"person_not_allowed"}` |
| Person's token without an active organization (not on `signed_in`) | `403 {"error":"organization_required"}` |
| Token without the route's permission (not on `signed_in`) | `403 {"error":"permission_denied"}` |

The handler of a person route (`route`) reads `Authorized`: `sub()`, `org_id()`, `org_external_id()`, `company_id()`,
`permissions()`, `has(p)`, `require(p)` (a finer check inside the handler), `subject()` (an
access-code subject's `ext_sub`/`subject_kind`/`ext_profile`), `dpop_jkt()`, `claims()`,
`access_token()` (the token the gate verified, to forward as `actor_token`).
Asking for `Authorized` on a public route answers `500`: there is never an unverified caller.

The handler of a signed-in route (`signed_in`) reads `SignedIn`: `sub()`, `org_id()` (an
`Option`: nothing was checked against it), `dpop_jkt()`, `claims()`, `access_token()`. The token
is verified exactly as on a permission route; only a person passes (a session, `sid`, and no
access-code subject). `Authorized` and `Caller` are not available there (`500`): `Authorized`
always means an organization and the route's permission. The tokens of `access_token()` print
`[REDACTED]` in `Debug`; never log them.
Machine routes (`machine`, `person_or_machine`) are in [Machine access](#6d-machine-access).

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
    // A signed-in route's caller: a person with no organization yet.
    let newcomer = signed_test_token(&verifier, &verifier.claims("CU-2", None, &[]))?;
}
```

Signed-in routes require no permission, so `assert_router_covers_manifest` counts only the
permission routes; `assert_no_unrouted_registrations` accepts `.signed_in(...)` declarations.

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

These are the OAuth building blocks; neither one is how two product APIs talk to each other.
For that, see [Machine access](#6d-machine-access).

**`ClientCredentialsClient`** gets the API's own machine key a token for **LoginFlow itself**
(`aud` = the issuer, no organization, no permissions of any product API): the token of the
`/v1/service/*` door, which the service clients of §3.3, §6a and §6c already request for you.
Another product's API refuses that token (`aud` is not its audience). `with_resource(audience)`
asks for a token for one API instead — what `MachineTokens` does.

```rust
use loginflow_sdk::{ClientCredentialsClient, ClientSecret};
use reqwest::Client;

let cc = ClientCredentialsClient::new(
    Client::new(),
    "https://api.loginflow.dev/oauth2/token",
    "my-api-key",
    ClientSecret::from(std::env::var("MY_API_KEY_SECRET")?),
).with_scope("loginflow.catalog.read");

let token = cc.access_token().await?; // cached, refreshed shortly before expiry, single-flight
```

**`IntrospectionClient`** (RFC 7662) answers only to the **machine key of the API the token is
for** (`oauth_clients.api_id` whose audience is the token's `aud`): it then returns the token's
organization and live permissions for that API (machine tokens: the permissions their grant still
holds, no organization). Any other client — another service, another API's key — gets
`{"active": false}`, so it is not a way to validate a token minted for someone else.
`TokenVerifier` uses it only for an overage token, with this API's own key.

```rust
use loginflow_sdk::IntrospectionClient;

let introspection = IntrospectionClient::new(
    reqwest::Client::new(),
    "https://api.loginflow.dev/oauth2/introspect",
    "my-api-key",
    std::env::var("MY_API_KEY_SECRET")?,
).introspect(&token_for_my_api).await?;
```

For a sensitive operation (money movement, destructive action, privilege change) that wants a
live revocation check without paying a network round trip on every call, use
`introspect_cached` instead of `introspect`: same RFC 7662 answer, cached per token for at most
`INTROSPECTION_CACHE_TTL` (30 s). An `active: false` answer is never cached.

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
(`Principal::AccessSubject`, an `access_codes` role, for the person who asked), and map the token back to your own record in the handler:

```rust
if let Some(subject) = auth.subject() {
    let driver_id = &subject.ext_sub;                     // "driver:42"
    let kind = subject.kind();                            // Some(SubjectKind::Person)
}
```

## 6d. Machine access

One system calling another product's API with no person behind the call (Payments asking
keel-api to send a notification, for instance) — instead of a shared token in environment
variables. Needs a LoginFlow server with machine access (`loginflow_api` 0.21; guide
`docs/guides/machine-access.md` there). **Who receives decides who calls**: the machine client
lives in the company and application that own the receiving API, and its operators grant it
permissions of that API's catalog (`PUT /v1/control/oauth-clients/{client_id}/machine-access`).
The calling system only holds the client's id and secret (`lfsk_…`).

### Receiving API: declare the routes machines may call

A machine token is an RFC 9068 access token for this API like a person's, verified by the same
`TokenVerifier` (ES256 `at+jwt`, `iss`, `aud` = `LOGINFLOW_API`, `exp`, `company_id` =
`LOGINFLOW_COMPANY`, DPoP when it carries `cnf`, overage through introspection). It is told apart
by `sid` being absent and `sub` = `client_id` (`AccessClaims::is_machine`); it has no `org_id`.

```rust
use loginflow_sdk::actix::{Caller, MachineAuthorized, PermissionRouter};

async fn send_notification(machine: MachineAuthorized) -> HttpResponse {
    // machine.client_id() names the calling system; there is no organization.
    HttpResponse::Accepted().json(serde_json::json!({ "caller": machine.client_id() }))
}

async fn read_notification(caller: Caller) -> HttpResponse {
    match caller {
        Caller::Person(person) => { /* scope by person.org_id() */ }
        Caller::Machine(machine) => { /* scope by machine.client_id() */ }
    }
    HttpResponse::Ok().finish()
}

let router = PermissionRouter::new(Arc::new(manifest))
    .route(Method::GET, "/v1/notifications", "keel.notifications.read", list_mine)          // persons only
    .machine(Method::POST, "/v1/notifications", "keel.notifications.send", send_notification) // machines only
    .person_or_machine(Method::GET, "/v1/notifications/{id}", "keel.notifications.read", read_notification)
    .build()?; // a machine route's permission must be in permissions.yaml too
```

| Route declared with | Machine token | Person's token |
|---|---|---|
| `route` | `403 machine_not_allowed` | organization + permission (as before) |
| `machine` | permission in the token → handler | `403 person_not_allowed` |
| `person_or_machine` | permission in the token → handler | organization + permission |

A machine token without the route's permission is `403 permission_denied`. The handler reads
`MachineAuthorized` (`client_id()`, `company_id()`, `app()`, `permissions()`, `has(p)`,
`require(p)`, `dpop_jkt()`, `claims()`) or `Caller` (`Person(Authorized)` | `Machine(..)`).
Asking for `Authorized` where a machine called is a `500`, never a person without an
organization. In tests, `FakeVerifier::machine_claims(client_id, permissions)` builds the claims
LoginFlow issues for a machine.

### Calling API: `MachineTokens`

```rust
use loginflow_sdk::{ClientSecret, MachineTokens};

let keel = MachineTokens::from_discovery(
    reqwest::Client::new(),
    &discovery,                                   // the issuer's discovery document
    std::env::var("KEEL_CALLER_CLIENT_ID")?,
    ClientSecret::from(std::env::var("KEEL_CALLER_CLIENT_SECRET")?),
    "https://api.keel.example",                   // the receiving API's audience, exactly
);                                                // .with_scope("keel.notifications.send") narrows it

let response = http
    .post("https://api.keel.example/v1/notifications")
    .header("Authorization", keel.authorization_header().await?) // "Bearer <token>"
    .json(&body)
    .send()
    .await?;
if response.status() == reqwest::StatusCode::UNAUTHORIZED {
    keel.invalidate().await; // e.g. the grant was removed: the next call asks for a new token
}
```

`POST /oauth2/token` with `grant_type=client_credentials&resource=<audience>[&scope=…]`,
`client_secret_basic`. The token (at most 600 s on LoginFlow, no refresh token) is cached and
fetched again 30 s before it expires; concurrent callers share one request. One `MachineTokens`
per receiving API: a token is for one audience. Refusals keep the OAuth code:
`Authentication { code: Some("invalid_client") }` (unknown client, wrong or expired secret),
`Validation { code: Some("invalid_target") }` (no live grant on that API),
`Validation { code: Some("invalid_scope") }`.

The tokens are plain **Bearer** tokens: this SDK verifies DPoP proofs but does not create them,
so `MachineTokens` never asks for a DPoP-bound token (LoginFlow recommends one; a caller that
needs it sends its own proof). The secret lives in a `ClientSecret` (wiped from memory on drop,
`Debug` prints `[redacted]`); neither the secret nor a token is logged.

## 7. Features

- **Permissions:** `PermissionManifest`, `CatalogClient` (`sync`, `get`; scope `loginflow.catalog.read loginflow.catalog.write`), `OrganizationsClient` (`ensure`, `get`, `find_by_external_id`, `list`, `root`, `delete`; scope `loginflow.organizations.read loginflow.organizations.write`), `MembersClient` (`grantable_roles`, `grant`, `revoke`, `list`; scope `loginflow.assignments.read loginflow.assignments.write`), `FoundingClient` (`found`; scope `loginflow.organizations.write loginflow.assignments.write`)
- **Request verification:** `TokenVerifier` (JWKS, ES256 allow-list, `iss`/`aud`/`exp`/`typ`, DPoP with `JtiReplayCache`, overage through introspection), `PermissionRouter` + gate + `Authorized` / `SignedIn` (feature `actix`), `testing` helpers
- **Userinfo:** `userinfo` — the one sanctioned way to resolve an email live
- **Back-channel logout:** `verify_logout_token` (OIDC Back-Channel Logout 1.0 §2.6)
- **Machine access:** `PermissionRouter::machine` / `person_or_machine`, `MachineAuthorized`, `Caller`, `AccessClaims::is_machine` (receiving API); `MachineTokens` + `ClientSecret` (calling API)
- **`client_credentials` / introspection:** `ClientCredentialsClient` (plus `invalidate`, `with_resource`), `IntrospectionClient` (plus `introspect_cached`, a ≤30 s cache for sensitive operations)
- **Machine-to-machine user management:** `ServiceUsersClient` (`create` with an optional invitation, `list`, `get`, `set_active`, `delete`; scope `loginflow.users.read loginflow.users.write`)
- **Access codes:** `AccessCodesClient` (`issue`, `list`, `revoke`, `revoke_subject_sessions`; scope `loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke`), and `AccessClaims::access_subject` on the subject's tokens
- **TOTP enrollment:** `setup_totp`, `verify_totp_setup`, `get_totp_status`, `disable_totp`
- **Password:** `change_password` (`{new_password}`, RFC 9470 step-up)
- **Account recovery:** `request_account_recovery` (always returns a `ticket_id` when the
  application offers it; `403` `Authorization` with code `account_recovery_disabled` when it does
  not)

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

The SDK maps the HTTP status to `LoginFlowError`: `400`/`422` `Validation { message, code }`, `401` `Authentication` (but `Validation { code: Some("INVALID_CODE") }` for a wrong TOTP code), `403` `Authorization { message, code }`, `404` `NotFound { message, code }`, `409` `Conflict { message, code }`, `429` `RateLimit { message, retry_after_secs, code }`, `503` `ServiceUnavailable`, other `5xx` `ServerError`. `code` is `error.code`; the message is `error.details` when it is text (the specific reason of a validation error), otherwise `error.message`. Error bodies are read up to 4 KiB.

A `429` is `RateLimit { message, retry_after_secs, code }`, where `retry_after_secs` is the `Retry-After` header (`None` when absent) and `code` the envelope's `error.code` (e.g. `founding_rate_limited`). A `503` is `ServiceUnavailable` (the server is busy; try again later). A `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470) is `InsufficientUserAuthentication { max_age_secs }`, not a plain `Authentication` error: the credential is fine, the session is just too old for this operation (e.g. `change_password`), and the caller should have the user re-authenticate and retry.

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
| `MachineTokens::access_token` / `authorization_header` | `POST /oauth2/token` (`grant_type=client_credentials&resource=<audience>`) |
| `IntrospectionClient::introspect` / `introspect_cached` | `POST /oauth2/introspect` |
| `RevocationClient::revoke` | `POST /oauth2/revoke` |
| `CatalogClient::sync` / `get` | `PUT` / `GET /v1/service/catalog` |
| `OrganizationsClient::ensure` | `PUT /v1/service/organizations/external/{external_id}` |
| `OrganizationsClient::list` / `find_by_external_id` / `root` | `GET /v1/service/organizations[?external_id=&limit=&offset=]` |
| `OrganizationsClient::get` / `delete` | `GET` / `DELETE /v1/service/organizations/{id}` |
| `MembersClient::grantable_roles` | `GET /v1/service/members/grantable-roles` |
| `MembersClient::grant` / `list` | `POST` / `GET /v1/service/members[?organization_id=&principal_id=&external_subject=&role_key=]` |
| `MembersClient::revoke` | `DELETE /v1/service/members/assignments/{id}` |
| `FoundingClient::found` | `POST /v1/service/organizations/founded` |
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
- [CHANGELOG.md](CHANGELOG.md): migration guides, including 0.13.x to 0.14.0 (error codes), 0.14.x to 0.15.0 (`actor_token`), 0.15.x to 0.21.0 (machine access) and 0.23.x to 0.24.0 (signed-in routes, founding)
- `docs/01-configuration.md`, `docs/06-totp-2fa.md`, `docs/10-jwt-local-verification.md`,
  `docs/11-actix-integration.md`, `docs/13-error-handling.md`, `docs/14-sdk-api-traceability.md`
  (the numbering has gaps on purpose: the login-REST docs — password, OTP, OAuth, password
  reset, email verification, refresh/logout, multi-tenant — and the user-account/profile
  administration doc were deleted with the methods they documented)

## 12. Versioning

Every minor version (`0.x`) is its own line — there is no `1.0.0`. From 0.21 the SDK shares
`major.minor` with the LoginFlow API it is built against (API 0.24.x ↔ SDK 0.24.x). A breaking
change to the public surface (removing or renaming a method, changing a type or a claim's
meaning, tightening a check that used to pass) only ships in a new minor, with a **Breaking**
section and a migration note in [CHANGELOG.md](CHANGELOG.md). A patch (`0.24.1`, ...) carries
fixes and additions that break nothing.
