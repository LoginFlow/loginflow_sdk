# 11. Actix integration

## Route table and gate

```rust
let router = PermissionRouter::new(Arc::new(manifest))
    .public(Method::GET, "/health", health)
    .route(Method::GET, "/drivers", "rutafacil.drivers.list", list_drivers)
    .build()?;
App::new()
    .wrap(router.gate(verifier.clone()))   // Arc<dyn AccessVerifier>: TokenVerifier (or FakeVerifier in tests)
    .configure(|cfg| router.configure(cfg))
```

`build()` refuses a permission the manifest does not declare (`RouteMapError::UnknownPermission`), a route declared twice and a relative path. Register the router at the root of the `App` with full paths: the gate looks the request up by method + matched pattern.

## What the gate answers

| Case | Status | Body `error` |
|---|---|---|
| Route not in the table (a raw `App::route`, `#[get]`, an unknown path or method) | 403 | `permission_unmapped` |
| Public route | the handler runs | - |
| Token missing or rejected (see [10-jwt-local-verification.md](10-jwt-local-verification.md)), DPoP binding not satisfied, proof replayed | 401 + `WWW-Authenticate: Bearer error="invalid_token"`, or `DPoP error="invalid_token", algs="ES256"` when the request used the `DPoP` scheme | `invalid_token` |
| Keys or overage permissions unavailable | 503 | `authorization_unavailable` |
| No active organization | 403 | `organization_required` |
| The route's permission not granted | 403 | `permission_denied` |

Bodies are fixed: the reason is logged, never sent, and the missing permission is not named.

## DPoP (RFC 9449 §7.1)

| Token | `Bearer` | `DPoP` |
|---|---|---|
| no `cnf` | accepted | 401 |
| `cnf.jkt` (DPoP-bound) | 401 | exactly one `DPoP` header whose proof is signed by the `cnf.jkt` key, for this method and `htu`, with `ath` = this token, `iat` within 60 s and a `jti` not seen before; otherwise 401 |

The expected `htu` is `LoginFlowConfig::resource_base_url` + the request path when set, otherwise
the connection's scheme + host + path (`ConnectionInfo`, which honours `Forwarded` /
`X-Forwarded-*`: set `resource_base_url` behind a reverse proxy). The query string is never part
of `htu`. The `jti` is recorded in the verifier's `JtiReplayCache` for 120 s;
`InMemoryJtiReplayCache` covers one process (implement the trait on a shared store for several
instances) and refuses new proofs when full. Server-issued DPoP nonces are not checked.

## `Authorized`
`sub()`, `org_id()`, `org_external_id()`, `company_id()`, `permissions()`, `has(p)`, `require(p) -> Result<(), AccessDenied>`, `subject()`, `dpop_jkt()`, `claims()`. Only the gate builds it: asking for it on a public route is a 500, never an unverified caller. Scope every query by `org_id()`, never by an id from the request.

## Helpers
- `extract_authorization(&HttpRequest) -> Result<AuthorizationHeader, LoginFlowError>`: scheme (`AuthScheme::Bearer` / `AuthScheme::Dpop`) and token, header parsing only
- `extract_token_from_request(&HttpRequest) -> Result<String, LoginFlowError>`: the token only (to forward it); no verification

`LoginFlowError` implements `ResponseError`: Config 500, Authentication 401, InsufficientUserAuthentication 401 (with the RFC 9470 `WWW-Authenticate` challenge), Authorization 403, Validation 422, NotFound 404, Conflict 409, RateLimit 429 (with `Retry-After` when `retry_after_secs` is set), ServiceUnavailable 503, Jwks 503, Timeout 504, other upstream errors 502. 5xx bodies carry a fixed message; the detail is logged, never sent to the client.

## Tests (feature `testing`)
- `assert_router_covers_manifest(&router, &manifest)`: every permission guards a route.
- `assert_no_unrouted_registrations(Path::new("src"))`: no route registered outside the router.
- `FakeVerifier::new(audience)` (optionally `.with_company(company_id)`; default `FAKE_COMPANY_ID`, `CP-TEST`), `verifier.claims(sub, org_id, permissions)`, `signed_test_token(&verifier, &claims)`: tokens without a LoginFlow server, with the same header, claims, company and DPoP checks as `TokenVerifier` (an overage token is a 503).
