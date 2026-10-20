# 11. Actix integration

## Registration (required)

```rust
App::new().app_data(web::Data::new(client.clone()))
```

Every extractor verifies the token with this client (see [10-jwt-local-verification.md](10-jwt-local-verification.md)). If it is not registered, the extractors fail with `LoginFlowError::Config` (HTTP 500). A token is never decoded without verification.

## Extractors
- `AuthMiddleware`: requires a valid access token. 401 when it is missing or rejected.
- `AdminAuth`: like `AuthMiddleware`, plus role `app_admin` or `master` (403 otherwise).
- `MasterAuth`: like `AuthMiddleware`, plus role `master` (403 otherwise).
- `OptionalAuth`: anonymous (`user() == None`) when the header is missing or the token is rejected. A missing client (500) and a JWKS outage (503) are still errors.

## DPoP (RFC 9449 §7.1, 0.7.0)
The extractors accept `Authorization: Bearer <token>` and `Authorization: DPoP <token>` (scheme
case-insensitive); any other scheme is a 401.

| Token | `Bearer` | `DPoP` |
|---|---|---|
| no `cnf` | accepted | 401 |
| `cnf.jkt` (DPoP-bound) | 401 | exactly one `DPoP` header whose proof is signed by the `cnf.jkt` key, for this method and `htu`, with `ath` = this token, `iat` within 60 s; otherwise 401 |

The expected `htu` is `LoginFlowConfig::resource_base_url` + the request path when set, otherwise
the connection's scheme + host + path (`ConnectionInfo`, which honours `Forwarded` /
`X-Forwarded-*`: set `resource_base_url` behind a reverse proxy). The query string is never part
of `htu`.

Replay protection is the caller's job: the SDK holds no storage, so it cannot enforce a
single-use `jti`. Read `AuthMiddleware::dpop_proof()` (also on `AdminAuth`/`MasterAuth`) and
reject a `claims.jti` already seen within `dpop::MAX_PROOF_AGE_SECS`. Server-issued DPoP nonces
are not checked by the extractors.

## Accessors
`company_user_id()`, `company_id()` and `application_id()` return `&str` (0.7.0): the ids are
opaque strings (`CP-...`, `APP-...`, a client_id for a `client_credentials` token), never UUIDs.

## Helpers
- `extract_authorization(&HttpRequest) -> Result<AuthorizationHeader, LoginFlowError>`: scheme (`AuthScheme::Bearer` / `AuthScheme::Dpop`) and token, header parsing only
- `extract_token_from_request(&HttpRequest) -> Result<String, LoginFlowError>`: the token only; no verification, no DPoP check
- `extract_user_from_request(&HttpRequest).await -> Result<AuthenticatedUser, LoginFlowError>`
- `registered_client(&HttpRequest) -> Result<web::Data<LoginFlowClient>, LoginFlowError>`

`LoginFlowError` implements `ResponseError`: Config 500, Authentication 401, Authorization 403, Validation 422, NotFound 404, Conflict 409, RateLimit 429 (with `Retry-After` when `retry_after_secs` is set), ServiceUnavailable 503, Jwks 503, Timeout 504, other upstream errors 502.

5xx bodies carry a fixed message ("Authentication service unavailable", "Authentication is not configured"); the detail is logged, never sent to the client.
