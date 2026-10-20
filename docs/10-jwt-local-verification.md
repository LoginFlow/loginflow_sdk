# 10. Local access-token verification (ES256 + JWKS)

## API
- `LoginFlowClient::verify_token(token).await -> JwtClaims`
- `LoginFlowClient::extract_user_from_token(token).await -> AuthenticatedUser`
- `JwksCache`: the key cache used by the client. It is public for advanced use.

## What is checked

1. Header: `alg` must be `ES256` and `kid` must be present. HS256 and any other algorithm are rejected before any network call.
2. Key: the `kid` is looked up in the issuer's JWKS. By default this is `GET {base_url}/oauth2/jwks` (`LoginFlowConfig::resolved_jwks_url`), the exact URL the server's own discovery document (`jwks_uri`) also publishes — set `jwks_url` explicitly, or build a `JwksCache` yourself from `client.discovery().await?.jwks_uri`, if your deployment's issuer and `base_url` ever diverge. Only `kty=EC`, `crv=P-256`, `alg=ES256` keys (with `use` absent or `sig`) are kept.
3. Signature, `iss` = `LOGINFLOW_ISSUER`, `aud` = `LOGINFLOW_APPLICATION`, `exp` with a 30 s leeway. `exp`, `iss`, `aud` and `sub` are required.
4. `sub`, `company_id`, `application_id` and `auth_cid` are opaque strings, never parsed as UUIDs (0.7.0): companies are `CP-...`, applications `APP-...`, and a `client_credentials` token's `sub` is its client_id. `AuthenticatedUser` and the Actix extractors expose them as `String`/`&str`. The access token carries no `token_type`/`status` claim — a refresh token is opaque (never a JWT), and a TOTP-challenge/password-reset token is rejected by its header `typ` (`"JWT"`, never `"at+jwt"`) before any claim is even looked at.

Failures are `LoginFlowError::Authentication`. If the key set cannot be fetched or parsed, the error is `LoginFlowError::Jwks`.

## JWKS cache

- Downloaded on first use, fresh for `LOGINFLOW_JWKS_CACHE_TTL_SECS` (default 600 s).
- Unknown `kid`: one refresh, at most once every 30 s (`JWKS_MIN_REFRESH_INTERVAL`). This picks up key rotation; repeated unknown `kid`s cannot make the SDK hammer the server.
- A failed download is not retried for 30 s either. If keys were downloaded before, they keep being served (a warning is logged); only a cache that never obtained keys fails with `LoginFlowError::Jwks`.
- Concurrent refreshes share a single request.
- The response is capped at 64 KiB (`JWKS_BODY_LIMIT`).

## `acr`/`amr` and step-up (0.6.1)

- `JwtClaims::is_phishing_resistant()` — `true` only for `acr: "urn:loginflow:acr:phr"` (a
  passkey, WebAuthn L3).
- `JwtClaims::has_mfa()` — `true` for `acr` `phr` or `"urn:loginflow:acr:mfa"`; `false` for
  `"urn:loginflow:acr:pwd"` or an absent `acr`.
- `JwtClaims::auth_age_secs()` — seconds since `auth_time`, no claim parsing required.
- `JwtClaims::require_recent_auth(max_age_secs)` — `Err(LoginFlowError::InsufficientUserAuthentication { max_age_secs: Some(max_age_secs) })`
  when `auth_age_secs() > max_age_secs`; `Ok(())` otherwise. Behind the `actix` feature, returning
  that error from your own handler sends the identical RFC 9470 `WWW-Authenticate` challenge the
  server's own `change_password` endpoint sends.
