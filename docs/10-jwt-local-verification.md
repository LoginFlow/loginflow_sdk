# 10. Local access-token verification (ES256 + JWKS)

## API
- `LoginFlowClient::verify_token(token).await -> JwtClaims`
- `LoginFlowClient::extract_user_from_token(token).await -> AuthenticatedUser`
- `JwksCache`: the key cache used by the client. It is public for advanced use.

## What is checked

1. Header: `alg` must be `ES256` and `kid` must be present. HS256 and any other algorithm are rejected before any network call.
2. Key: the `kid` is looked up in the issuer's JWKS (`GET {base_url}/oauth2/jwks`). Only `kty=EC`, `crv=P-256`, `alg=ES256` keys (with `use` absent or `sig`) are kept.
3. Signature, `iss` = `LOGINFLOW_ISSUER`, `aud` = `LOGIN_FLOW_APPLICATION`, `exp` with a 30 s leeway. `exp`, `iss`, `aud` and `sub` are required.
4. `user_id`, `company_id` and `application_id` must be UUIDs. `token_type` must be `access` (refresh, TOTP-challenge and password-reset tokens are rejected) and `status` must be `active`.

Failures are `LoginFlowError::Authentication`. If the key set cannot be fetched or parsed, the error is `LoginFlowError::Jwks`.

## JWKS cache

- Downloaded on first use, fresh for `LOGINFLOW_JWKS_CACHE_TTL_SECS` (default 600 s).
- Unknown `kid`: one refresh, at most once every 30 s (`JWKS_MIN_REFRESH_INTERVAL`). This picks up key rotation; repeated unknown `kid`s cannot make the SDK hammer the server.
- A failed download is not retried for 30 s either. If keys were downloaded before, they keep being served (a warning is logged); only a cache that never obtained keys fails with `LoginFlowError::Jwks`.
- Concurrent refreshes share a single request.
- The response is capped at 64 KiB (`JWKS_BODY_LIMIT`).

## Removed in 0.5.0

`decode_jwt_claims` (decoded without checking the signature), `verify_jwt_claims` and `JwtDecodeError` (HS256 with a shared secret), `LoginFlowClient::can_verify_locally`, and the `signing_secret` setting.
