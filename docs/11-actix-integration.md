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

## Helpers
- `extract_token_from_request(&HttpRequest) -> Result<String, LoginFlowError>`
- `extract_user_from_request(&HttpRequest).await -> Result<AuthenticatedUser, LoginFlowError>`
- `registered_client(&HttpRequest) -> Result<web::Data<LoginFlowClient>, LoginFlowError>`

`LoginFlowError` implements `ResponseError`: Config 500, Authentication 401, Authorization 403, Validation 422, NotFound 404, RateLimit 429, Jwks 503, Timeout 504, other upstream errors 502.

5xx bodies carry a fixed message ("Authentication service unavailable", "Authentication is not configured"); the detail is logged, never sent to the client.
