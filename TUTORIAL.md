# Implementation tutorial: LoginFlow SDK

A practical integration guide for a Rust API (SDK 0.11.0).

This SDK is how a product's **API** consumes LoginFlow: it declares the API's permissions, syncs
them, creates organizations and grants roles, and verifies every request against those
permissions. It does not log a user in — login (password, OTP, TOTP, OAuth, Native SSO) goes
through the first-party OIDC challenge or the hosted login page, outside this SDK (see
`loginflow_auth`, the Flutter client library, or the server's
`docs/architecture/oidc-provider.md`).

## 1. Setup

### 1.1 Dependency

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.11.0" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

[dev-dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.11.0", features = ["testing"] }
```

### 1.2 Environment

One set per API of the product:

```env
LOGINFLOW_URL=https://api.loginflow.dev
LOGINFLOW_COMPANY=<company_id, CP-...>
LOGINFLOW_API=<the audience of this API>
LOGINFLOW_ISSUER=https://api.loginflow.dev
LOGINFLOW_CLIENT_ID=<this API's machine key>
LOGINFLOW_CLIENT_SECRET=<its secret>
```

### 1.3 Client

Build the client once and share it (clones share the connection pool and the JWKS cache).

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowResult};

fn build_client() -> LoginFlowResult<LoginFlowClient> {
    LoginFlowClient::from_env()
}
```

## 2. Declaring and syncing the permissions

`permissions.yaml`, next to the API's `Cargo.toml`:

```yaml
app: rutafacil
resources:
  drivers:
    description: Drivers of the client company
    sensitive: true
    read:
      - { action: list, description: List the drivers }
    write:
      - { action: create, description: Register a driver }
```

At start-up:

```rust
use std::path::Path;
use loginflow_sdk::{CatalogClient, LoginFlowConfig, PermissionManifest};

let manifest = PermissionManifest::load(Path::new("permissions.yaml"))?;
let catalog = CatalogClient::new(LoginFlowConfig::from_env()?, &client_id, &client_secret)?;
catalog.sync(&manifest).await?;
```

The owner of the application builds roles from these permissions in the LoginFlow panel, and
lists there which roles your API's key may grant. Your API creates the organizations it scopes
data by and grants those roles in them, for what the system provisions itself:

```rust
use loginflow_sdk::{GrantMember, MembersClient, OrganizationsClient, Principal};

let org = organizations.ensure(&client_company.id, &client_company.name).await?;
members.grant(&GrantMember {
    organization_id: org.id,
    role_key: "driver".into(), // one of `members.grantable_roles().await?`
    principal: Principal::AccessSubject { external_subject: format!("driver:{driver_id}") },
    expires_at: None, // or Some(chrono::DateTime<Utc>), sent as `2026-12-31T00:00:00Z`
}).await?;
```

A role a person hands out (an owner inviting a client admin) is granted from the product's
frontend with `loginflow_auth` and that person's own token, never with the key.

## 3. Protecting every route (Actix)

```rust
use std::sync::Arc;
use actix_web::http::Method;
use actix_web::{App, HttpResponse, HttpServer};
use loginflow_sdk::actix::{Authorized, PermissionRouter};
use loginflow_sdk::{InMemoryJtiReplayCache, IntrospectionClient, LoginFlowClient, TokenVerifier};

async fn list_drivers(auth: Authorized) -> HttpResponse {
    // The organization comes from the verified token — never from the body or the path.
    HttpResponse::Ok().json(drivers_of(auth.org_id()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = LoginFlowClient::from_env().map_err(std::io::Error::other)?;
    let discovery = client.discovery().await.map_err(std::io::Error::other)?.clone();
    let introspection = IntrospectionClient::from_discovery(
        reqwest::Client::new(), &discovery, client_id(), client_secret(),
    );
    let verifier = Arc::new(TokenVerifier::new(
        client, Arc::new(InMemoryJtiReplayCache::new()), introspection,
    ));
    let router = PermissionRouter::new(Arc::new(manifest()))
        .public(Method::GET, "/health", health)
        .route(Method::GET, "/drivers", "rutafacil.drivers.list", list_drivers)
        .build()
        .map_err(std::io::Error::other)?;

    HttpServer::new(move || {
        App::new()
            .wrap(router.gate(verifier.clone()))
            .configure(|cfg| router.configure(cfg))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

A route that is not in the router answers `403 permission_unmapped`. A token for another API
(`aud`), from another issuer, expired, not ES256 or not `at+jwt` answers `401 invalid_token`; a
DPoP-bound token needs a fresh, single-use proof from its key. Without an organization the answer
is `403 organization_required`; without the route's permission, `403 permission_denied`. When the
decision cannot be made (JWKS down, overage introspection down) the answer is `503`, never a
pass.

In the API's tests (feature `testing`):

```rust
assert_router_covers_manifest(&router, &manifest);  // every permission guards a route
assert_no_unrouted_registrations(Path::new("src")); // no route outside the router
let verifier = Arc::new(FakeVerifier::new("https://drivers.api.test")?);
let token = signed_test_token(&verifier, &verifier.claims("CU-1", Some("org-1"), &["rutafacil.drivers.list"]))?;
```

## 4. Resolving an email (`userinfo`)

```rust
let info = client.userinfo(&access_token).await?; // UserInfoResponse
if let Some(email) = info.email {
    println!("{email}");
}
```

The server resolves `email`/`user_id` live, gated by the token's scope (`email`,
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
    application_id: "APP-01JABCDEF".into(), // the application the user signs in to
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

## 8. Service-to-service: `client_credentials` and introspection

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

## 9. Back-channel logout and step-up (advanced)

If your client registers a `backchannel_logout_uri`, verify what it receives — LoginFlow
addresses the logout token to that client:

```rust
let logout_claims = client.verify_logout_token(&logout_token, "console").await?;
// Record `logout_claims.jti` (a `JtiReplayCache` does) to reject a replay.
```

Gating your own sensitive endpoint on a recent login (RFC 9470) — the same shape
`change_password` already enforces — inside a permission route:

```rust
async fn payout(auth: Authorized) -> Result<HttpResponse, LoginFlowError> {
    auth.claims().require_recent_auth(300)?; // 401 insufficient_user_authentication if stale
    if !auth.claims().has_mfa() {
        // single factor: maybe require a step-up before a sensitive action
    }
    Ok(HttpResponse::Ok().finish())
}
```

## 10. Versioning and LTS

This SDK follows the same LTS discipline as the server: every minor (`0.x`) is its own LTS line,
there is no `1.0.0`. A patch release only ever gets fixes and small, non-breaking additions; a
breaking change to a method signature or a claim's meaning ships as a new minor (0.11.0 is one).
See README.md §12 for the full policy.
