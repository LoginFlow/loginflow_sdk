# 10. Local access-token verification (ES256 + JWKS)

## API
- `TokenVerifier::new(client, replay, introspection)` and `TokenVerifier::verify_presented(&PresentedToken) -> Result<VerifiedAccess, VerifyError>`: framework-agnostic; the Actix permission gate calls it for every permission route ([11-actix-integration.md](11-actix-integration.md)).
- `JwksCache`: the key cache used by the client. It is public for advanced use.

## What is checked

1. Header: `alg` must be in the allow-list (`ES256` only), `typ` must be `at+jwt`, and `kid` must be present. HS256 and any other algorithm are rejected before any network call.
2. Key: the `kid` is looked up in the issuer's JWKS. By default this is `GET {base_url}/oauth2/jwks` (`LoginFlowConfig::resolved_jwks_url`), the exact URL the server's own discovery document (`jwks_uri`) also publishes. Only `kty=EC`, `crv=P-256`, `alg=ES256` keys (with `use` absent or `sig`) are kept.
3. Signature, `iss` = `LOGINFLOW_ISSUER`, `aud` = `LOGINFLOW_API` (this API only: a token of another API of the same application, or LoginFlow's own token, is rejected), `exp` with a 30 s leeway. `exp`, `iss`, `aud` and `sub` are required; so are `company_id` and `app`. `company_id` must equal `LOGINFLOW_COMPANY` (`InvalidToken`, 401, otherwise): an application can belong to several companies and its API audience is per application, so `aud` alone does not keep another company's token out. An empty `LOGINFLOW_COMPANY` is a configuration error.
4. DPoP (RFC 9449 §7.1): a `cnf`-bound token only under the `DPoP` scheme with one proof (`typ: dpop+jwt`, ES256, a public P-256 `jwk` — one carrying a private key `d` is refused) signed by that key for this method and `htu`, with `ath` = this token, `iat` within 60 s, and a `jti` never seen before (`JtiReplayCache`); a token without `cnf` only under `Bearer`. Server-issued DPoP nonces are not required.
5. Permissions: `permissions` (a list) → `TokenPermissions::Listed`; `permissions_overage: true` → `Overage`, read live from `POST /oauth2/introspect` with the API's key. An introspection that fails, or answers without `permissions`, is `VerifyError::Unavailable` (503); an inactive token, or one whose `org_id` is no longer the active one, is `InvalidToken` (401). A token with both claims is malformed.

`sub`, `company_id`, `app`, `org_id` and `auth_cid` are opaque strings, never parsed as UUIDs. The access token carries no `token_type`/`status` claim and no PII.

Failures are `VerifyError::InvalidToken`; when the key set cannot be fetched or parsed, `VerifyError::Unavailable`.

## JWKS cache

- Downloaded on first use, fresh for `LOGINFLOW_JWKS_CACHE_TTL_SECS` (default 600 s).
- Unknown `kid`: one refresh, at most once every 30 s (`JWKS_MIN_REFRESH_INTERVAL`). This picks up key rotation; repeated unknown `kid`s cannot make the SDK hammer the server.
- A failed download is not retried for 30 s either. If keys were downloaded before, they keep being served (a warning is logged); only a cache that never obtained keys fails.
- Concurrent refreshes share a single request.
- The response is capped at 64 KiB (`JWKS_BODY_LIMIT`).

## `acr`/`amr` and step-up

- `AccessClaims::is_phishing_resistant()` — `true` only for `acr: "urn:loginflow:acr:phr"` (a
  passkey, WebAuthn L3).
- `AccessClaims::has_mfa()` — `true` for `acr` `phr` or `"urn:loginflow:acr:mfa"`; `false` for
  `"urn:loginflow:acr:pwd"` or an absent `acr`.
- `AccessClaims::auth_age_secs()` — seconds since `auth_time`.
- `AccessClaims::require_recent_auth(max_age_secs)` — `Err(LoginFlowError::InsufficientUserAuthentication { max_age_secs: Some(max_age_secs) })`
  when `auth_age_secs() > max_age_secs`; `Ok(())` otherwise. Behind the `actix` feature, returning
  that error from your own handler sends the identical RFC 9470 `WWW-Authenticate` challenge the
  server's own `change_password` endpoint sends.
