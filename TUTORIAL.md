# Integrate a Rust backend with LoginFlow

A step-by-step guide for a product's API (Actix-web) on `loginflow_sdk` 0.14. The worked example
is RutaFácil's backend, `apps/server` in the RutaFácil repository: every step names the file
where it lives there.

What the SDK does for the API:

- verifies every request: an access token for THIS API, of THIS company, with its DPoP binding,
  and the route's permission in the token's organization (deny by default);
- keeps LoginFlow's permission catalog equal to the API's `permissions.yaml`;
- provisions through the API's machine key: organizations, role assignments, users, access
  codes.

What stays in the product: `permissions.yaml`, the route table (which permission each route
needs), and scoping every query by the caller's organization. Signing people in is not the
backend's job: the apps do it with `loginflow_auth` (hosted login or the native OIDC challenge).

## 1. Set up the API in the LoginFlow panel

Done once per environment by the application's owner:

1. **The API.** Under the application, create the API and note its **audience** (e.g.
   `https://api.rutafacil.example`; an API created before APIs existed keeps the application id,
   `APP-...`, as its audience). Every access token for it has `aud` = that value.
2. **The machine key.** A confidential OAuth client of the application, bound to that API, with
   the `client_credentials` grant. Note its `client_id` and its secret (shown once).
3. **The key's service permissions.** A key starts with none. Give it the `loginflow.*`
   permissions of the clients the API uses (each client requests all of its own, and the server
   checks each route's exact one in the token and among the key's permissions):

   | Client | Permissions |
   |---|---|
   | `CatalogClient` | `loginflow.catalog.read`, `loginflow.catalog.write` |
   | `OrganizationsClient` | `loginflow.organizations.read`, `loginflow.organizations.write` |
   | `MembersClient` | `loginflow.assignments.read`, `loginflow.assignments.write` |
   | `ServiceUsersClient` | `loginflow.users.read`, `loginflow.users.write` |
   | `AccessCodesClient` | `loginflow.accessCodes.issue`, `loginflow.accessCodes.read`, `loginflow.accessCodes.revoke` |
   | `TokenVerifier` (overage introspection) | none: introspection only needs the key to be the API's key |

4. **Grantable roles.** The roles the key may grant with `MembersClient` (RutaFácil: `driver`
   and `recorder`, the phones' roles). A role outside the list is `403 role_not_grantable`.
5. **Access codes** (only if the API issues them): enabled for the application, with the
   allowed subject kinds and the default lifetime.

The catalog sync of the API's first start (step 5 below) claims the application's permission
prefix; after it, the owner builds the roles out of those permissions in the panel.

## 2. Add the dependency

`apps/server/Cargo.toml`:

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.14.0" }
# The HTTP client IntrospectionClient takes (the SDK's own version).
reqwest = "0.13.2"

[dev-dependencies]
loginflow_sdk = { git = "https://github.com/LoginFlow/loginflow_sdk", tag = "v0.14.0", features = ["testing"] }
```

The default feature `actix` brings the router, the gate and `Authorized`. `testing` is for
`tests/` only.

## 3. Configure

The variables of one API:

```env
LOGINFLOW_URL=https://api.loginflow.dev        # dev: https://api-dev.loginflow.dev
LOGINFLOW_ISSUER=https://api.loginflow.dev     # the `iss` of every token
LOGINFLOW_COMPANY=CP-...                        # the only `company_id` accepted
LOGINFLOW_API=https://api.rutafacil.example     # the only `aud` accepted; never the issuer
LOGINFLOW_CLIENT_ID=rutafacil-api               # the machine key (step 1.2)
LOGINFLOW_CLIENT_SECRET=...
LOGINFLOW_RESOURCE_BASE_URL=https://api.rutafacil.example  # behind a reverse proxy (DPoP `htu`)
```

`LoginFlowConfig::from_env()` reads them, or `from_lookup` from any source. RutaFácil reads its
own configuration type once and hands the SDK what it asks for
(`apps/server/src/integrations/loginflow/mod.rs`):

```rust
use loginflow_sdk::LoginFlowConfig;

pub fn loginflow_config(envy: &Envy) -> Result<LoginFlowConfig, EnvyError> {
    let lookup = |name: &str| -> Option<String> {
        match name {
            "LOGINFLOW_URL" => Some(envy.loginflow_url.clone()),
            "LOGINFLOW_ISSUER" => Some(envy.loginflow_issuer.clone()),
            "LOGINFLOW_COMPANY" => Some(envy.loginflow_company.clone()),
            "LOGINFLOW_API" => Some(envy.loginflow_api.clone()),
            "LOGINFLOW_USER_AGENT" => Some("rutafacil-api".to_string()),
            "LOGINFLOW_RESOURCE_BASE_URL" => Some(envy.public_base_url.clone()),
            _ => None,
        }
    };
    LoginFlowConfig::from_lookup(lookup).map_err(EnvyError::loginflow)
}
```

An empty issuer, audience, company or URL, or an audience equal to the issuer, is a
configuration error: the API does not start. The machine key is not part of `LoginFlowConfig`:
the API passes it to each client.

## 4. Declare the permissions

`apps/server/permissions.yaml`, one permission per route or group of routes:

```yaml
app: rutafacil
resources:
  fleet:
    description: The buses of the company
    read:
      - { action: list, description: "List the buses" }
    write:
      - { action: create, description: "Add a bus" }
      - { action: update, description: "Edit a bus" }
      - { action: retire, description: "Retire a bus" }
```

Every permission is `{app}.{resource}.{action}` (`rutafacil.fleet.create`). The SDK refuses what
the catalog would refuse: a bad or reserved (`loginflow`) prefix, names outside
`[a-z][a-zA-Z0-9_]*`, a duplicate action, a description empty or over 500 characters, more than
200 resources, 0 or more than 500 permissions, an unknown field.

RutaFácil compiles the file into the binary, so the route table and the sync always see the same
text (`apps/server/src/auth/manifest.rs`):

```rust
use loginflow_sdk::{ManifestError, PermissionManifest};

pub const MANIFEST_YAML: &str = include_str!("../../permissions.yaml");

pub fn manifest() -> Result<PermissionManifest, ManifestError> {
    PermissionManifest::from_yaml_str(MANIFEST_YAML)
}
```

## 5. Wire the SDK at start-up

Build everything once, before `HttpServer::new`, and stop the start when anything fails: without
it no request can be authorized. RutaFácil does it in `AppState::connect`
(`apps/server/src/state/app_state.rs`):

```rust
use std::sync::Arc;

use loginflow_sdk::{
    AccessCodesClient, CatalogClient, InMemoryJtiReplayCache, IntrospectionClient,
    LoginFlowClient, MembersClient, OrganizationsClient, ServiceUsersClient, TokenVerifier,
};

let (client_id, secret) = envy.machine_key()?; // LOGINFLOW_CLIENT_ID / LOGINFLOW_CLIENT_SECRET
let secret = secret.expose();
let config = loginflow_config(&envy)?;

// The verifier of every request: JWKS from the issuer, DPoP replay cache, and introspection
// with the API's own key (only an overage token needs it).
let client = LoginFlowClient::new(config.clone())?;
let discovery = client.discovery().await?.clone();
let introspection =
    IntrospectionClient::from_discovery(reqwest::Client::new(), &discovery, client_id, secret);
let verifier = TokenVerifier::new(client, Arc::new(InMemoryJtiReplayCache::new()), introspection);

// The machine door: each client caches its own `client_credentials` token.
let catalog = CatalogClient::new(config.clone(), client_id, secret)?;
let organizations = OrganizationsClient::new(config.clone(), client_id, secret)?;
let members = MembersClient::new(config.clone(), client_id, secret)?;
let users = ServiceUsersClient::new(config.clone(), client_id, secret)?;
let codes = AccessCodesClient::new(config, client_id, secret)?;

// The catalog of THIS API becomes the manifest's (idempotent), then the root organization.
let report = catalog.sync(&manifest()?).await?;
log::info!("catalog {}: {} added, {} obsoleted", report.catalog_hash, report.added.len(), report.obsoleted.len());
let root_organization = organizations.root().await?.id;
```

`InMemoryJtiReplayCache` remembers DPoP proofs in one process. With several instances of the API
behind a balancer, implement `JtiReplayCache` on a shared store (e.g. Redis `SET NX EX`), or a
proof replayed against another instance passes there.

RutaFácil keeps the verifier as `Arc<dyn AccessVerifier>` and each client behind a trait of its
own (`AuthorizationDirectory`, `AccessCodeIssuer`, `Identities`), so its tests inject fakes.

## 6. Declare the routes

Every route goes through a `PermissionRouter`, with the permission it needs or as public. Each
RutaFácil module adds its own (`apps/server/src/modules/fleet/mod.rs`):

```rust
use actix_web::http::Method;
use loginflow_sdk::actix::PermissionRouter;

pub fn routes(router: PermissionRouter) -> PermissionRouter {
    router
        .route(Method::GET, "/vehicles", "rutafacil.fleet.list", handler::vehicles)
        .route(Method::POST, "/vehicles", "rutafacil.fleet.create", handler::add_vehicle)
        .route(Method::PATCH, "/vehicles/{id}", "rutafacil.fleet.update", handler::update_vehicle)
}
```

and the health check is public (`apps/server/src/health/mod.rs`):

```rust
pub fn routes(router: PermissionRouter) -> PermissionRouter {
    router.public(Method::GET, "/health", health)
}
```

The whole table is built once, against the manifest (`apps/server/src/auth/routes.rs`):

```rust
use std::sync::Arc;
use loginflow_sdk::PermissionManifest;
use loginflow_sdk::actix::{BuiltRouter, PermissionRouter, RouteMapError};

pub fn router(manifest: Arc<PermissionManifest>) -> Result<BuiltRouter, RouteMapError> {
    let router = health::routes(PermissionRouter::new(manifest));
    modules::routes(router).build()
}
```

`build()` refuses a permission the manifest does not declare, a route declared twice and a
relative path. Use full paths at the root of the `App`: the gate looks a request up by method
and matched pattern, so a route mounted under a `web::scope` is never found.

## 7. Put the gate in front of the whole app

`apps/server/src/app.rs` and `apps/server/src/main.rs`:

```rust
use actix_web::{App, HttpServer, web};

pub fn build_app(state: AppState) -> App<impl ServiceFactory<...>> {
    let router = state.router().clone();
    let gate = router.gate(state.verifier()); // Arc<dyn AccessVerifier>
    App::new()
        .wrap(gate) // the whole App: no route escapes it
        .app_data(web::Data::new(state))
        .configure(move |cfg| router.configure(cfg))
}

HttpServer::new(move || build_app(state.clone()).wrap(cors(&origins))) // CORS outermost
```

CORS goes outside the gate, so a preflight never needs a token. Allow the `Authorization` and
`DPoP` request headers and expose `WWW-Authenticate` and `DPoP-Nonce` to browser clients.

For each request the gate answers before any handler:

| Case | Answer |
|---|---|
| Method + pattern not in the table (a raw `App::route`, a path nobody declared) | `403 {"error":"permission_unmapped"}` |
| Public route | the handler runs, no token needed |
| No token, another scheme, `alg` not ES256, `typ` not `at+jwt`, unknown `kid`, bad signature, `iss` not `LOGINFLOW_ISSUER`, `aud` not `LOGINFLOW_API`, `company_id` not `LOGINFLOW_COMPANY`, expired (30 s leeway) | `401 {"error":"invalid_token"}` |
| DPoP: a bound token not under `DPoP`, a plain token under `DPoP`, no or two proofs, a proof for another method or URL, from another key, not binding this token (`ath`), stale (60 s), already used, or carrying a private key | `401 {"error":"invalid_token"}` |
| The JWKS cannot be fetched; an overage token's permissions cannot be read | `503 {"error":"authorization_unavailable"}` (fails closed) |
| Token without an active organization | `403 {"error":"organization_required"}` |
| Token without the route's permission in its organization | `403 {"error":"permission_denied"}` |

A `401` carries `WWW-Authenticate: Bearer error="invalid_token"`, or `DPoP error="invalid_token",
algs="ES256"` when the request used the `DPoP` scheme. The reason is logged, never sent.

## 8. Read the caller in the handlers

A permission route's handler takes `Authorized`; the gate already checked the token and the
route's permission. Scope every query by the token's organization, never by an id from the path
or the body:

```rust
use loginflow_sdk::actix::Authorized;

async fn vehicles(auth: Authorized, state: web::Data<AppState>) -> Result<HttpResponse, AppResponse> {
    // The product's own id of the token's organization (`external_id`, step 9).
    let company_id = auth.org_external_id().ok_or(AuthError::UnknownOrganization)?;
    let rows = state.fleet_service().vehicles(company_id).await?;
    Ok(HttpResponse::Ok().json(rows))
}
```

What `Authorized` gives: `sub()` (a `company_users` id, or `AS-...` for an access-code subject),
`org_id()`, `org_external_id()`, `company_id()`, `permissions()`, `has(p)`, `require(p)` (a finer
check inside the handler), `subject()` (`ext_sub`, `subject_kind`, `ext_profile` of an
access-code subject), `dpop_jkt()` and `claims()` (`auth_time`, `amr`, `acr`, ...).

RutaFácil turns the organization into its own scope in one place
(`AuthService::scope`, `apps/server/src/auth/service.rs`): the root organization is the platform
company; any other organization's `org_external_id()` is the client company's id (step 9 creates
it that way), and an organization that is neither is `403`. Its extractors
(`apps/server/src/auth/extractors.rs`) build on `Authorized`, so its real `vehicles` handler takes
a `CompanyCaller` (already scoped) instead of `Authorized` directly.

A step-up check on a sensitive route of your own:

```rust
auth.claims().require_recent_auth(300)?; // 401 + WWW-Authenticate: insufficient_user_authentication
```

## 9. Provision organizations and roles

One organization per unit the product scopes data by, keyed by the product's own id. RutaFácil
keeps one per client company, `external_id` = the company id
(`apps/server/src/integrations/loginflow/authorization.rs`):

```rust
use loginflow_sdk::{GrantMember, LoginFlowError, Principal};

// Created when missing (201), renamed otherwise (200).
let organization_id = organizations.ensure(&company.id, &company.name).await?.id;

// A driver phone gets the `driver` role, as an access-code subject, in its company's organization.
members
    .grant(&GrantMember {
        organization_id,
        role_key: "driver".to_string(),
        principal: Principal::AccessSubject { external_subject: subject.external_subject() },
        expires_at: None,
    })
    .await?;

// A deleted client: its organization goes, with every assignment in it.
if let Some(organization) = organizations.find_by_external_id(&company.id).await? {
    match organizations.delete(&organization.id).await {
        Ok(()) | Err(LoginFlowError::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
}
```

The key grants only the roles of its grantable list (`members.grantable_roles()`). A grant a
PERSON decides (an owner inviting a client's administrator) is not the backend's: the frontend
does it with `loginflow_auth` and that person's own token (`/v1/app/members`).

## 10. Issue access codes (people and devices of your own database)

A driver phone signs in with a one-time code RutaFácil asks LoginFlow for
(`apps/server/src/integrations/loginflow/access_codes.rs`):

```rust
use loginflow_sdk::{IssueAccessCodeRequest, SubjectKind};

let issued = codes
    .issue(IssueAccessCodeRequest {
        subject_kind: SubjectKind::Person,
        external_subject: "driver:42".to_string(), // your id; comes back as `ext_sub`
        profile: "Driver".to_string(),             // comes back as `ext_profile`
        display_name: None,
        ttl_minutes: Some(1440),                   // 420..=7200; None = the application default
        revoke_existing_sessions: None,
    })
    .await?;
// `issued.code` (XXXX-XXXX) is returned only here: show it once, never store it.

codes.revoke(&issued.id).await?;                     // the code, not the sessions
codes.revoke_subject_sessions("driver:42").await?;   // every session of the subject
```

`issue` answers `Conflict { code: Some(ACCESS_CODES_DISABLED_CODE) }` while access codes are off
for the application. The phone redeems the code with `loginflow_auth` (DPoP-bound session); its
tokens reach the API with `auth.subject()` set.

## 11. Read users

`ServiceUsersClient` reads (and, with `.write`, creates, deactivates and deletes) the people of
the key's company and application. RutaFácil only reads, to resolve a person's email from their
`sub` (`apps/server/src/integrations/loginflow/identities.rs`):

```rust
let user = users.get(auth.sub()).await?; // ServiceUser { id, email, first_name, ... }
```

## 12. Map LoginFlow's errors to your own

Every call returns `LoginFlowResult<T>`. Refusals keep the server's `error.code`, so a product
tells them apart without parsing messages:

```rust
use loginflow_sdk::{ACCESS_CODES_DISABLED_CODE, LoginFlowError};

impl From<LoginFlowError> for DirectoryError {
    fn from(error: LoginFlowError) -> Self {
        match error {
            LoginFlowError::NotFound { message, .. } => DirectoryError::NotFound(message),
            LoginFlowError::Authorization { message, code: Some(code) } => {
                DirectoryError::Rejected(format!("{code}: {message}"))
            }
            LoginFlowError::Validation { message, .. }
            | LoginFlowError::Authentication(message)
            | LoginFlowError::Authorization { message, .. }
            | LoginFlowError::Config(message)
            | LoginFlowError::Conflict { message, .. } => DirectoryError::Rejected(message),
            other => DirectoryError::Upstream(other.to_string()), // retryable
        }
    }
}
```

`error.is_retryable()` is `true` for network failures, timeouts, `429` and `5xx`. A machine
call whose cached token was revoked is retried once with a fresh token by the SDK itself.

## 13. Test it

With the `testing` feature (`apps/server/tests/routes_covered_test.rs`):

```rust
use loginflow_sdk::testing::{assert_no_unrouted_registrations, assert_router_covers_manifest};

#[test]
fn every_permission_of_the_manifest_guards_a_route() {
    let manifest = manifest().expect("permissions.yaml");
    let router = router(Arc::new(manifest.clone())).expect("route table");
    assert_router_covers_manifest(&router, &manifest);
}

#[test]
fn no_route_is_registered_outside_the_permission_router() {
    assert_no_unrouted_registrations(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
}
```

To call the real gate with signed tokens and no LoginFlow server, use `FakeVerifier`: the same
header, claims, company and DPoP checks as `TokenVerifier`, with a throwaway key
(`apps/server/tests/dpop_gate_test.rs`):

```rust
use loginflow_sdk::testing::{FakeVerifier, signed_test_token};

let verifier = FakeVerifier::new(envy.loginflow_api)?.with_company(envy.loginflow_company);
let mut claims = verifier.claims("AS-1", Some(&org_id), &["rutafacil.driverPhone.bind"]);
claims.org_ext = Some(company.id.clone());
claims.cnf = Some(CnfClaim { jkt: key.thumbprint() }); // DPoP-bound: send a real proof
let token = signed_test_token(&verifier, &claims)?;
```

An app's own `AccessVerifier` fake works too (RutaFácil's `tests/common/mod.rs` keeps one that
maps opaque test tokens to identities): the gate takes any `Arc<dyn AccessVerifier>`.

## 14. Before production

- The key holds every permission of step 1.3, and its grantable roles are listed.
- `LOGINFLOW_RESOURCE_BASE_URL` is the public URL clients call (behind a proxy, the connection's
  host is not), or every DPoP request is `401`.
- More than one instance: a shared `JtiReplayCache`.
- The access token lives 10 minutes and is verified locally: a revocation reaches the API when
  the token expires. For a sensitive operation, also ask `IntrospectionClient::introspect_cached`.

## Other calls

The account calls on behalf of a person (`setup_totp`, `verify_totp_setup`, `get_totp_status`,
`disable_totp`, `change_password`, `userinfo`), account recovery, back-channel logout
(`verify_logout_token`), `ClientCredentialsClient`, `IntrospectionClient` and
`RevocationClient` are in the [README](README.md). The person's token they take must be a plain
`Bearer` token: a DPoP-bound token needs the person's device key, which a backend never holds.
