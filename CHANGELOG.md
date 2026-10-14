# Changelog

## 0.5.0

LoginFlow now signs every token with **ES256** and publishes its public keys as a JWKS. This release verifies tokens only that way. There is no HS256 path, no shared signing secret and no compatibility window. Consumers and the LoginFlow server switch in the same deploy window, and every user signs in again once.

### Security fixes
- **Unverified tokens are never trusted.** In 0.4.x the Actix extractors and `extract_user_from_token` fell back to decoding the token *without checking the signature* when no `signing_secret` was configured. A forged token with `"role":"master"` was accepted. Now the extractors require a registered `LoginFlowClient` (HTTP 500 otherwise) and always verify.
- **Only access tokens are accepted.** Refresh, TOTP-challenge and password-reset tokens are rejected (`token_type` must be `access`). The `aud` (application) and `iss` (issuer) claims are also checked.
- **No refresh-token fallback.** `effective_refresh_token()` fell back to the access token when the refresh token was missing. It is gone, and `refresh_token` is now a required `String`.
- **Bounded memory.** One shared `reqwest::Client` (multi-tenant calls used to build a new client per request), error bodies are read up to 4 KiB, and JWKS bodies up to 64 KiB.
- The register call no longer logs its request body (it contained the password), and delegated codes are no longer logged.
- **No secrets in `Debug`.** Requests and responses that carry passwords, tokens, codes or the TOTP secret print `[REDACTED]` for them (`RegisterRequest`, `LoginRequest`, `ChangePasswordRequest`, `CompleteResetRequest`, `LoginResponse`, `OtpLoginResponse`, `RefreshTokenResponse`, `RefreshTokenRequest`, `TotpSetupResponse`, `TotpChallengeResponse`, the TOTP/OTP/reset/delegated code requests, `OAuthLoginRequest`, and their multi-tenant twins).
- **No server error bodies in error logs.** Failed calls log the status and the server's error code at `error`; the bounded body (it can contain emails) is logged at `debug` only.
- **No upstream details in HTTP responses.** In the Actix `ResponseError`, 5xx bodies are fixed messages ("Authentication service unavailable", "Authentication is not configured"). The detail (transport error, URL) is logged instead.
- **Strict identity claims.** A verified token whose `company_id` or `application_id` is not a UUID is rejected (`Authentication`); it used to become `Uuid::nil()`.

### Fixed
- Tokens carrying both `exp` and `expires_in` (or `iat` and `created_at`) failed to parse because of serde aliases (`duplicate field`). The aliases are removed.
- A JWKS refresh that fails after the TTL expired no longer breaks verification: the previously downloaded keys keep being served (with a warning) until a refresh succeeds. Only a cold cache, or an unknown `kid`, fails.
- `change_password` returned an invented `{ success: true, message: "Password changed successfully" }`. It now returns the server's own message (the server answers `data` with a bare string).
- An invalid `LOGIN_FLOW_TIMEOUT` silently fell back to 30 s; it is now a configuration error, like `LOGINFLOW_JWKS_CACHE_TTL_SECS`.
- Account and profile methods called `/v1/user-accounts/...` and `/v1/user-profiles/...`, which the server does not mount (404). They now call `/v1/master/user-accounts/...` and `/v1/master/user-profiles/...` and need a master token.

### Added
- `jwks` module: `JwksCache` (TTL cache, refresh on unknown `kid` at most every 30 s, single-flight refresh, 64 KiB cap, only `kty=EC`/`crv=P-256`/`alg=ES256` keys), `JWKS_BODY_LIMIT`, `JWKS_MIN_REFRESH_INTERVAL`.
- `config::DEFAULT_JWKS_CACHE_TTL_SECS` (600) and `config::DEFAULT_TIMEOUT_SECS` (30).
- `LoginFlowConfig::from_lookup`: build the config from any variable source (a secrets store, a map); `from_env` uses it.
- `models::REDACTED`, the placeholder used by the redacting `Debug` impls.
- Config: `issuer` (`LOGINFLOW_ISSUER`, required), `jwks_url` (`LOGINFLOW_JWKS_URL`, default `{base_url}/oauth2/jwks`), `jwks_cache_ttl_secs` (`LOGINFLOW_JWKS_CACHE_TTL_SECS`, default 600), `LoginFlowConfig::validate`, `LoginFlowConfig::resolved_jwks_url`.
- `JwtClaims` fields `iss`, `sub`, `aud`, `exp`, `iat`, `token_type`; `JwtClaims::is_access_token`; `ACCESS_TOKEN_TYPE`; `TOKEN_LEEWAY_SECS` (30 s).
- `LoginFlowError::Jwks` (HTTP 503 in Actix), `LoginFlowError::kind`, `ConfigError::MissingValue`.
- `actix::registered_client`, `AuthenticatedUser::from_claims`.
- Multi-tenant OTP: `request_otp_login_with_company`, `login_with_otp_with_company`, `MultiTenantRequestOtpRequest`, `MultiTenantOtpLoginRequest`.

### Breaking changes (removed or changed public API)

Removed:
- `LoginFlowConfig::signing_secret` and the `LOGINFLOW_SIGNING_SECRET` variable.
- `decode_jwt_claims`, `verify_jwt_claims`, `JwtDecodeError`.
- `LoginFlowClient::can_verify_locally`.
- `actix::verify_token_with_secret`.
- `LoginResponse::effective_refresh_token`, `OtpLoginResponse::effective_refresh_token`, `LoginResult::effective_refresh_token`.
- Passwordless (merged into OTP login): `LoginFlowClient::request_passwordless_code`, `LoginFlowClient::authenticate_passwordless`, `RequestPasswordlessCodeRequest`, `RequestPasswordlessCodeResponse`, `PasswordlessAuthRequest`, `PasswordlessAuthResponse`, `MultiTenantExt::request_passwordless_code_with_company`, `MultiTenantExt::authenticate_passwordless_with_company`, `MultiTenantRequestPasswordlessCodeRequest`, `MultiTenantPasswordlessAuthRequest`.
- Unused models: `ResetPasswordRequest`, `MessageResponse`.
- Fields the server ignores or no longer has: `RegisterRequest::phone`, `MultiTenantRegisterRequest::phone`, `MultiTenantRegisterRequest::role`, `RequestEmailVerificationRequest::skip_email`, `RequestEmailVerificationResponse::verification_code`.

Changed:
- `LoginFlowClient::verify_token` is `async` and verifies ES256 via JWKS. `extract_user_from_token` and `actix::extract_user_from_request` are `async`.
- `LoginFlowClient::new` fails when `issuer`, `application_id` or `base_url` is empty. `LoginFlowConfig::from_env` requires `LOGINFLOW_ISSUER`.
- `LoginFlowConfig` has three new fields, so struct literals must add `issuer`, `jwks_url`, `jwks_cache_ttl_secs`.
- `JwtClaims`: `jti`, `email`, `role`, `status`, `company_id`, `application_id` no longer have defaults; `exp`/`iat` are numeric claims of their own; `remaining_validity()` returns `i64`; `is_expired()` uses `exp`.
- `RegisterResponse` is now `{ user_id, company_id, application_id }` (was `{ user_id, email, message }`).
- `LoginResponse::refresh_token` and `OtpLoginResponse::refresh_token`: `Option<String>` -> `String`.
- `change_password(token, user_id, company_id, req)` -> `change_password(token, req)`. The body carries only the passwords, and the error mapping is the standard one (no more "incorrect password" guessing from the body).
- `ChangePasswordResponse` is now `{ message }` holding the server's message (it was `{ success, message }` built by the SDK).
- `AuthenticatedUser::from_claims` / `extract_user_from_token` reject non-UUID `company_id` / `application_id`.
- `LoginFlowConfig::from_env` fails on a non-numeric `LOGIN_FLOW_TIMEOUT`.
- The secret-bearing models listed above no longer derive `Debug`; they implement it by hand with redaction (the output format changed).
- Actix 5xx error bodies carry a fixed message instead of the error text.
- `logout` returns `LoginFlowError::Validation` without calling the server when the request names neither `session_token` nor `logout_all_devices: Some(true)`.
- Actix extractors answer 500 when no `LoginFlowClient` is registered, and 503 when the JWKS cannot be obtained. `OptionalAuth` maps only rejected tokens to anonymous.
- `LoginFlowError` gained the `Jwks` variant (exhaustive matches must handle it) and implements `ResponseError::status_code`.
- `MultiTenantExt` uses native `impl Future + Send` methods instead of `#[async_trait]`; it is no longer object safe (`dyn MultiTenantExt`).
- Dependencies: removed `jwt`, `hmac`, `sha2`, `base64`, `async-trait` and `actix-web-httpauth`; added `jsonwebtoken` 11 (aws-lc-rs backend).

### Migration guide: 0.4.x to 0.5.0

1. **Dependency:** bump to `tag = "v0.5.0"` (repository `https://github.com/LoginFlow/loginflow_sdk`).
2. **Environment:** add `LOGINFLOW_ISSUER=https://api.loginflow.dev` (dev: `https://api-dev.loginflow.dev`). Remove `LOGINFLOW_SIGNING_SECRET` after the cut-over. The JWKS URL defaults to `{LOGIN_FLOW_URL}/oauth2/jwks`; set `LOGINFLOW_JWKS_URL` only if it differs.
3. **Explicit config:** replace `signing_secret: ...` with
   ```rust
   issuer: "https://api.loginflow.dev".into(),
   jwks_url: None,
   jwks_cache_ttl_secs: 600,
   ```
4. **Token verification:** `client.verify_token(t)?` -> `client.verify_token(t).await?`, and the same for `extract_user_from_token`. Replace `decode_jwt_claims` (insecure) and `verify_jwt_claims` / `verify_token_with_secret` with `client.verify_token(t).await`.
5. **Actix:** make sure every `App` registers the client: `.app_data(web::Data::new(client.clone()))`. Without it, every protected route returns 500.
6. **Refresh tokens:** `resp.effective_refresh_token()` -> `resp.refresh_token` (always present). Send it with `session.id` to `refresh_token`, and store the rotated token you get back.
7. **Passwordless -> OTP:** `request_passwordless_code(RequestPasswordlessCodeRequest { .. })` -> `request_otp_login(RequestOtpRequest { email, metadata, language })`; `authenticate_passwordless(PasswordlessAuthRequest { .. })` -> `login_with_otp(OtpLoginRequest { email, code })`. Multi-tenant: `request_otp_login_with_company` / `login_with_otp_with_company`. Automatic account creation for unknown emails is now an application setting on the server (self sign-up).
8. **Registration:** drop `phone` (and `role` in multi-tenant); roles are assigned through the master API. Read `company_id` / `application_id` from `RegisterResponse` instead of `email` / `message`.
9. **Email verification:** drop `skip_email`; the code is only delivered by email.
10. **Change password:** `change_password(&token, &user_id, &company_id, req)` -> `change_password(&token, req)`; read `response.message` (there is no `success` field any more; an error is returned on failure).
11. **Logout:** pass `session_token: Some(session.id)` or `logout_all_devices: Some(true)`.
12. **Accounts and profiles:** call them with a master token (they target `/v1/master/...`).
13. **Error matches:** handle `LoginFlowError::Jwks` (signing keys unavailable; retryable).
14. **Cut-over:** publish this SDK, prepare the consumers with it and `LOGINFLOW_ISSUER`, deploy LoginFlow (ES256) and then the consumers in the same window. Sessions issued before the switch stop working, and users sign in once.
