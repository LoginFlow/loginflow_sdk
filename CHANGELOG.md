# Changelog

## 0.11.0

Permissions per application (LoginFlow IAM phase 1). Breaking: every product adapts in the same
cut; nothing of the role model remains.

### Breaking
- `LoginFlowConfig::application_id` / `LOGINFLOW_APPLICATION` → `api_audience` / `LOGINFLOW_API`:
  the audience of THIS API. A token is accepted only when `aud` equals it; the application id is
  no longer an audience (an API created before APIs existed keeps it as its audience value).
  `api_audience` equal to the issuer is a configuration error.
- An access token is accepted only when its `company_id` equals `LoginFlowConfig::company_id`
  (`LOGINFLOW_COMPANY`); another company's token for the same API audience is `InvalidToken`
  (401). An empty `company_id` is a configuration error.
- `JwtClaims` → `AccessClaims`: no `role`, no `application_id`; `app` (required), `org_id`,
  `org_ext`, `permissions: TokenPermissions` (`Listed` / `Overage`, from the `permissions` and
  `permissions_overage` claims; both at once is refused), `access_subject` (the `ext_sub`,
  `subject_kind`, `ext_profile` claims, flattened).
- Removed: `AuthenticatedUser` (and its `role`, `is_admin`, `is_master`), the Actix extractors
  `AuthMiddleware`, `OptionalAuth`, `AdminAuth`, `MasterAuth`, `extract_user_from_request`,
  `registered_client`, `LoginFlowClient::verify_token` and `extract_user_from_token`. Every
  request is verified by the `PermissionRouter` gate (`TokenVerifier`), and the handler reads
  `Authorized`.
- Removed: `ServiceUserRole`, `ServiceUsersClient::set_role` and `update`,
  `UpdateServiceUserRequest`, and `role` on `ServiceUser`, `CreateServiceUserRequest`,
  `FullUserAccountResponse`, `UserAccountResponse`, `UpdateUserAccountRequest` and
  `UserInfoResponse`. Grant roles with `AssignmentsClient`.
- Machine scopes are LoginFlow permissions: `USERS_MANAGE_SCOPE` (`users:manage`) →
  `USERS_WRITE_SCOPE` (`loginflow.users.write`); `ACCESS_CODES_ISSUE_SCOPE` is now
  `loginflow.accessCodes.issue`.
- `verify_logout_token(token, client_id)`: the logout token's `aud` is the RP's client_id (what
  LoginFlow puts there), no longer compared to the application.
- `AccountRecoveryRequest` carries `application_id` (the config names an API, not an
  application).

### Added
- `PermissionManifest` (`permissions.yaml`) and `CatalogClient` (`PUT`/`GET /v1/service/catalog`,
  scope `loginflow.catalog.write`, the catalog of the key's own API).
- `OrganizationsClient` (`/v1/service/organizations`, scope `loginflow.organizations.write`) and
  `AssignmentsClient` (`/v1/service/assignments`, scope `loginflow.assignments.write`) with
  `Principal::CompanyUser` / `Principal::AccessSubject`. `GrantAssignment.expires_at` is a
  `chrono::DateTime<Utc>`, sent as RFC 3339 with its offset (the API refuses a naive date-time);
  `Catalog.app` is `None` until the application's first sync.
- `TokenVerifier`: ES256 allow-list, `typ at+jwt`, `iss`/`aud`/`exp`, DPoP with single-use proofs
  (`JtiReplayCache`, `InMemoryJtiReplayCache`), overage permissions through introspection
  (fails closed, `503`). `IntrospectionResponse` gained `org_id`, `org_ext`, `permissions`.
- `actix::PermissionRouter` / `BuiltRouter::gate` / `Authorized`: deny by default
  (`403 permission_unmapped`, `organization_required`, `permission_denied`; fixed
  `401 invalid_token` and `503 authorization_unavailable` bodies).
- Feature `testing`: `assert_router_covers_manifest`, `assert_no_unrouted_registrations`,
  `FakeVerifier`, `signed_test_token`.

### Server
Needs the LoginFlow API with IAM phase 1 (catalog, organizations, assignments, `app`/`org_id`/
`permissions` claims, `aud` per API, the `loginflow.*` machine scopes). Dev only until LoginFlow
PROD is updated.

## 0.10.0

### Breaking
- `CreateServiceUserRequest` gained `send_invitation: bool` and `ServiceUser` gained
  `invitation: Option<InvitationStatus>`: struct literals must set them (usually `false` /
  `None`). The wire body is unchanged when `send_invitation` is `false` (the field is omitted).

### Added
- `CreateServiceUserRequest::send_invitation`: `true` asks LoginFlow to email the application's
  invitation once the user exists (`POST /v1/service/users` with `"send_invitation": true`) — the
  editable `account_invitation` template with the application's sign-in and Android/iOS/desktop
  links. The `201` reports it in `ServiceUser::invitation` (`InvitationStatus::Sent`, `Failed`,
  `RateLimited`; `Unknown` for a value this version does not know); a failed invitation never
  fails the create.
- `ServiceUsersClient::set_role(id, ServiceUserRole)` and `update(id, UpdateServiceUserRequest)`:
  `PATCH /v1/service/users/{id}` with `"role"` (`user`/`app_admin`, never `master`) and/or
  `"is_active"`, only the fields set. The new role reaches the user's tokens at their next
  refresh. `422` (`Validation`) for an update with no field set.
- Both need a LoginFlow API that accepts them; an older server answers `400` (unknown field)
  to `"send_invitation": true` and to `"role"`.

## 0.9.0

- New: `ServiceUsersClient::delete(id)` — `DELETE /v1/service/users/{id}`, permanently deletes
  the person's membership in the token's application (and the profile when it was their last
  account), answering `ServiceUserDeleted { id, profile_deleted }`. `409 Conflict` when other
  data depends on the membership, `404 NotFound` for an id outside the tenant or already
  deleted. Requires the LoginFlow API with that route (loginflow_api PR "identity reuse and
  service delete").

## 0.8.0

### Breaking
- `JwtClaims` gained `ext_sub`, `subject_kind` and `ext_profile` (`Option<String>`, absent on every
  ordinary token) and `AuthenticatedUser` gained the same three fields: struct literals must
  set them (usually `None`). Tokens and `AuthenticatedUser::from_claims` need no change.

### Added
- `AccessCodesClient`: one-time access codes for subjects that live in the caller's own
  database (`/v1/service/access-codes`, `/v1/service/access-subjects/revoke`) with a
  `client_credentials` token requested with scope `access_codes:issue`
  (`ACCESS_CODES_ISSUE_SCOPE`). `new(config, client_id, client_secret)` / `from_discovery(...)`;
  `issue` (the code is returned once), `list(external_subject)`, `revoke(id)` (`204`),
  `revoke_subject_sessions(external_subject)`, `invalidate_token`. `409` with
  `code: Some("access_codes_disabled")` (`ACCESS_CODES_DISABLED_CODE`) when the application has
  access codes off; `422` is `Validation`. Typed models `IssueAccessCodeRequest`,
  `IssuedAccessCode` (`Debug` redacts the code), `AccessCodeInfo`, `RevokeAccessSubjectRequest`,
  `RevokedSessions`, `SubjectKind`.
- `JwtClaims::ext_sub()`, `subject_kind()` (typed `SubjectKind`; `None` for an unknown kind),
  `ext_profile()` and `is_access_code_subject()`; `AuthenticatedUser.ext_sub` / `subject_kind` /
  `ext_profile`, so a resource server maps an access-code subject's token (`sub` = `AS-...`) to
  its own record. The issuer's profile label travels as `ext_profile`, not `profile`: OIDC
  registers `profile` as the End-User's profile page URL.

### Changed
- `ServiceUsersClient` and `AccessCodesClient` share one machine-door implementation (scoped
  token cache, single retry on a rejected token, `401 INVALID_CODE` never resent). No
  behaviour change for `ServiceUsersClient`.

## 0.7.0

### Breaking
- **Ids are opaque strings, never UUIDs.** `AuthenticatedUser.company_user_id`, `company_id`
  and `application_id` are `String`, `auth_cid` is `Option<String>`; the Actix
  `AuthMiddleware`/`AdminAuth`/`MasterAuth` accessors `company_user_id()`, `company_id()` and
  `application_id()` return `&str`. LoginFlow issues `CP-...` company ids, `APP-...` application
  ids, and a `client_credentials` token's `sub` is its client_id: up to 0.6 every real token was
  rejected by the UUID parsing. `AuthenticatedUser::from_claims` is now infallible (returns
  `Self`). Migration: drop `.to_string()`/`Uuid` conversions and compare the strings directly.
- **The Actix extractors enforce DPoP binding (RFC 9449 §7.1).** A DPoP-bound token (`cnf.jkt`)
  presented as `Bearer` is now a 401 (it used to pass). See "Added".
- `LoginFlowConfig` gained `resource_base_url: Option<String>` (struct literals must set it,
  usually `None`).
- `LoginFlowError` gained the `Conflict` variant: exhaustive `match`es need an arm.

### Added
- `ServiceUsersClient`: machine-to-machine user management over `/v1/service/users` with a
  `client_credentials` token requested with scope `users:manage` (`USERS_MANAGE_SCOPE`).
  `new(config, client_id, client_secret)` / `from_discovery(...)`; `create`, `list`, `get`,
  `set_active`, `request_email_change`, `confirm_email_change`, `invalidate_token`. Typed models
  `ServiceUser`, `ServiceUserRole`, `CreateServiceUserRequest`, `EmailChangeRequested`. When the
  API rejects the cached token (`401` `UNAUTHORIZED`), the token is dropped and the request
  resent exactly once; a `401` about the request (`INVALID_CODE`) is never resent.
- `ClientCredentialsClient::invalidate()`: drop the cached token.
- `LoginFlowError::Conflict { message, code }` for `409` (HTTP 409 in the Actix
  `ResponseError`), carrying the server's `error.code` (e.g. `"email_shared"`).
- DPoP in the Actix extractors: `Authorization: Bearer <token>` or `DPoP <token>`
  (case-insensitive scheme; `Basic` and anything else still rejected). No `cnf` + `Bearer`:
  accepted; no `cnf` + `DPoP`: 401; `cnf` + `Bearer`: 401; `cnf` + `DPoP`: exactly one `DPoP`
  header verified with `dpop::verify_proof_matches_cnf` against the request method and `htu`
  (`resource_base_url` + path, or the connection's scheme + host + path). Single-use `jti`
  remains the caller's job: `AuthMiddleware::dpop_proof()` exposes the verified proof.
  New helpers `actix::extract_authorization`, `AuthScheme`, `AuthorizationHeader`.
- `LOGINFLOW_RESOURCE_BASE_URL` / `LoginFlowConfig::resource_base_url`.

### Dependencies
- `uuid` removed: nothing in the crate uses it anymore.

## 0.6.0

### Dependencies
- `chrono` removed: nothing in the crate used it.
- `IntrospectionClient::introspect_cached` keeps at most `INTROSPECTION_CACHE_MAX_ENTRIES` (10 000) answers.

### Configuration
- Every environment variable uses the `LOGINFLOW_` prefix: `LOGINFLOW_URL`, `LOGINFLOW_VERSION`, `LOGINFLOW_COMPANY`, `LOGINFLOW_APPLICATION`, `LOGINFLOW_TIMEOUT`. The `LOGIN_FLOW_*` names and the short names (`LOGIN_URL`, `LOGIN_VERSION`, `COMPANY`, `APPLICATION`) are no longer read.

The OIDC cutover. LoginFlow's own REST login surface (password login,
registration, OTP login, OAuth login, password reset, email verification, delegated auth,
logout) is removed in this release: those flows now go through the first-party OIDC challenge /
hosted login. There is no deprecation window; the SDK and the server switch in the same deploy.

### Breaking — removed
- `register`, `login`, `refresh_token`, `logout`, `verify_email`, `resend_verification`,
  `request_otp_login`, `login_with_otp`, `verify_totp_login`, `verify_totp_code`,
  `login_with_oauth`, `request_password_reset`, `verify_reset_code`, `complete_password_reset`,
  `create_delegated_token`, `validate_delegated_token`, `request_email_verification`, and every
  model/test that only existed to support them (`RegisterRequest/Response`, `LoginRequest`,
  `LoginResponse`, `LoginResult`, `LogoutRequest`, `RefreshTokenRequest/Response`,
  `VerifyEmailRequest`, `Resend/RequestEmailVerificationRequest/Response`, `RequestOtpRequest`,
  `OtpLoginRequest/Response`, `OAuthLoginRequest`, `VerifyResetCodeRequest/Response`,
  `CompleteResetRequest`, `CreateDelegatedTokenRequest/Response`,
  `ValidateDelegatedTokenRequest/Response`, `TotpChallengeResponse`, `VerifyTotpLoginRequest`,
  `VerifyTotpCodeRequest`, `UserInfo`, `CompanyInfo`, `SessionInfo`, `ApplicationInfo`).
- The `multi-tenant` feature and the `multi_tenant` module: every method it wrapped is gone.
- The internal single-flight refresh (`refresh_flight`): it existed only for `refresh_token`.

### Changed
- `change_password`'s body is now `{ "new_password": "..." }` (`ChangePasswordRequest` lost
  `current_password`/`confirm_password`). The endpoint now requires a recent authentication
  (`auth_time` within 300 s, RFC 9470); a stale token gets `401` with
  `WWW-Authenticate: Bearer error="insufficient_user_authentication"`, surfaced as the new
  `LoginFlowError::InsufficientUserAuthentication { max_age_secs }` instead of a plain
  `Authentication` error, so a caller can tell a step-up apart from a rejected credential and
  retry after re-authenticating. `LoginFlowError::requires_reauthentication` now covers it too.
- `verify_token` enforces the RFC 9068 header `typ: at+jwt` before trusting any claim (rejects
  token-type confusion: an ID token or any other JWT reused as an access token).
- `JwtClaims` gained the RFC 9068 claims: `client_id`, `scope`, `sid` (optional), `auth_time`,
  `amr`, `acr` (optional), plus accessors `company_user_id()` (the RFC 9068 `sub`, which is now
  `company_users.id` rather than the profile id), `scopes()`, `has_scope()`, `has_amr()`.
- **Breaking — the access token carries no PII anymore.** `JwtClaims` lost `user_id`, `email`,
  `status` and `token_type` (the header `typ`/`alg` already fix the token's type; `verify_token`
  dropped the now-pointless `is_access_token`/`is_active` checks along with them).
  `AuthenticatedUser.user_id` is renamed `company_user_id` (parsed from `sub`) and its `email`
  field is gone — resolve one, when actually needed, through the new `userinfo` call below.
  `AuthMiddleware`/`AdminAuth`/`MasterAuth`'s `user_id()`/`email()` accessors are renamed/removed
  the same way (`company_user_id()` only).
- `JwtClaims` gained `cnf: Option<CnfClaim>` (RFC 7800): `Some` when the token is DPoP-bound
  (RFC 9449 §6), with the `jkt` thumbprint a presented proof must match.

### Added
- `oauth2` module: `ClientCredentialsClient` (a confidential-client token source with a cache
  refreshed shortly before expiry and single-flight refresh — concurrent callers past a stale
  cache share one `POST /oauth2/token` request) and `IntrospectionClient` (RFC 7662
  `POST /oauth2/introspect`, parses the short `{"active": false}` form too, plus
  `introspect_cached` — the same check with a ≤30 s per-token cache, for a sensitive operation
  that wants a live revocation check without paying a network round trip on every call). Both
  take their own `reqwest::Client` and full endpoint URL: they do not need a `LoginFlowConfig`.
- `LoginFlowClient::userinfo`: `GET /oauth2/userinfo`, the one sanctioned way to resolve a
  user's email (and, by scope, `role`/`user_id`) live — never off an access token claim.
- `LoginFlowClient::verify_logout_token`: verifies an OIDC Back-Channel Logout 1.0 §2.6 logout
  token delivered to an RP's own `backchannel_logout_uri` (header `typ: logout+jwt`, ES256 via
  JWKS, `iss`/`aud`, the `events` member, `sub`/`sid` presence, and rejects a stray `nonce`).
  Single-use `jti` enforcement against replay is the caller's own job (the SDK holds no storage).
- `dpop` module (RFC 9449): `verify_proof_matches_cnf` for a resource server validating a
  presented DPoP proof against a token's `cnf.jkt` (signature, `htm`/`htu`, freshness, `ath`, and
  the actual key match — not just "a valid proof from some key"). `jti` single-use is again the
  caller's job.
- `JwtClaims.auth_cid` / `AuthenticatedUser.auth_cid` (federations): the company whose credential
  actually authenticated the token's session, present only when it differs from `company_id` (a
  `session`-level federation reuse or a cross-company Native SSO exchange). Authorization
  decisions must still key off `company_id`, never `auth_cid`.
- `JwtClaims::is_phishing_resistant`, `::has_mfa`, `::auth_age_secs` and `::require_recent_auth`
  (RFC 9470): the `acr` constants (`ACR_PHISHING_RESISTANT`, `ACR_MULTI_FACTOR`,
  `ACR_SINGLE_FACTOR`, matching the server's `acr_for_amr`) and the step-up gate a backend's own
  sensitive endpoint needs — the same shape `change_password` already enforces, now available for
  any endpoint the consumer defines. Returns `LoginFlowError::InsufficientUserAuthentication`,
  which (via the `actix` feature) now also carries the `WWW-Authenticate: Bearer
  error="insufficient_user_authentication", max_age=<n>` header on its `ResponseError` response —
  previously the body alone carried the reason.
- `oauth2::RevocationClient`: an RFC 7009 `/oauth2/revoke` client with `client_secret_basic`
  client authentication, for a confidential backend revoking one of its own tokens early. The
  server now requires confidential-client authentication on this endpoint; there was previously
  no client for it in this SDK.
- `discovery` module and `LoginFlowClient::discovery`: fetches and caches
  `{base_url}/.well-known/openid-configuration` once per client. `LoginFlowClient::userinfo` now
  resolves `userinfo_endpoint` from it instead of a hardcoded path, and
  `ClientCredentialsClient`/`IntrospectionClient`/`RevocationClient` gained a `from_discovery`
  constructor that reads `token_endpoint`/`introspection_endpoint`/`revocation_endpoint` from the
  same document — the explicit-URL `new` constructors are unchanged, for a caller that already
  has the URL.

### Kept
- `setup_totp`, `verify_totp_setup`, `get_totp_status`, `disable_totp` (TOTP enrollment is an
  account API, unaffected by the login cutover).
- `get_account`, `update_account`, `soft_delete_account`, `restore_account`,
  `hard_delete_account`, `get_profile`, `search_profile_by_email`, `update_profile`,
  `delete_profile`, `request_account_recovery`, `verify_token`, `extract_user_from_token`.

### Docs
- `TUTORIAL.md` and `README.md` rewritten for the 0.6.0 surface (no more register/login/refresh
  examples, no `user_id`/`email` on `JwtClaims`/`AuthenticatedUser`).
- `docs/02-auth-password.md`, `03-password-reset.md`, `04-email-verification.md`,
  `05-otp-login.md`, `07-oauth-login.md`, `08-session-refresh-logout.md` and `12-multi-tenant.md`
  deleted: they documented methods that no longer exist. `docs/06-totp-2fa.md`,
  `docs/13-error-handling.md` and `docs/14-sdk-api-traceability.md` updated for what remains.

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
- `change_password` returned an invented `{ success: true, message: "Password changed successfully" }`. It now returns the server's own message, read from the `data` object `{ "message": "..." }`.
- An invalid `LOGIN_FLOW_TIMEOUT` silently fell back to 30 s; it is now a configuration error, like `LOGINFLOW_JWKS_CACHE_TTL_SECS`.
- Account and profile methods called `/v1/user-accounts/...` and `/v1/user-profiles/...`, which the server does not mount (404). They now call `/v1/master/user-accounts/...` and `/v1/master/user-profiles/...` and need a master token.
- `validate_delegated_token` now sends the creator's `email`, which the server requires. Delegated tokens are 8 characters from `23456789ABCDEFGHJKMNPQRSTUVWXYZ` (case-insensitive), valid 15 minutes.
- A rejected OTP code or delegated token (the server answers one generic `401`) was reported as "token may be expired, revoked, or session inactive". `login_with_otp`, `login_with_otp_with_company` and `validate_delegated_token` now report every rejection as `Authentication(INVALID_CODE_MESSAGE)` ("The code is invalid or has expired"). A rejected reset code (one `401`) stays `Authentication(INVALID_RESET_CODE_MESSAGE)`; a `404` is no longer folded into it.
- `logout` sent a `user_id` the server ignores (the user is the owner of the access token). The field is gone.
- `verify_email` and `resend_verification` reported a rate limit (`429`) or a server error (`5xx`) as `false`, as if the server had rejected the code or the request. They now return the error; `false` only means a `4xx` rejection.
- Concurrent `refresh_token` calls with the same refresh token raced: the server rotates the token on every refresh and revokes the session when a rotated token is presented again. Refreshes are now single-flight per session and refresh token: concurrent callers share one request and all get the new tokens. Callers with a different token are never joined, and nothing is cached once the request finished.
- Documented the server's uniform answers: `request_otp_login`, `request_password_reset`, `request_email_verification` and `resend_verification` succeed the same way whether or not a code was sent; `register` answers an already registered email with the same shape and a random `user_id`; `request_account_recovery` always returns a ticket; reset codes have 8 digits and may start with `0`; accounts created by the OTP login have `auth_type: "otp"`.

### Added
- `jwks` module: `JwksCache` (TTL cache, refresh on unknown `kid` at most every 30 s, single-flight refresh, 64 KiB cap, only `kty=EC`/`crv=P-256`/`alg=ES256` keys), `JWKS_BODY_LIMIT`, `JWKS_MIN_REFRESH_INTERVAL`.
- `config::DEFAULT_JWKS_CACHE_TTL_SECS` (600) and `config::DEFAULT_TIMEOUT_SECS` (30).
- `LoginFlowConfig::from_lookup`: build the config from any variable source (a secrets store, a map); `from_env` uses it.
- `models::REDACTED`, the placeholder used by the redacting `Debug` impls.
- `client::INVALID_CODE_MESSAGE` and `client::INVALID_RESET_CODE_MESSAGE`, the messages of the uniform code-rejection errors.
- Config: `issuer` (`LOGINFLOW_ISSUER`, required), `jwks_url` (`LOGINFLOW_JWKS_URL`, default `{base_url}/oauth2/jwks`), `jwks_cache_ttl_secs` (`LOGINFLOW_JWKS_CACHE_TTL_SECS`, default 600), `LoginFlowConfig::validate`, `LoginFlowConfig::resolved_jwks_url`.
- `JwtClaims` fields `iss`, `sub`, `aud`, `exp`, `iat`, `token_type`; `JwtClaims::is_access_token`; `ACCESS_TOKEN_TYPE`; `TOKEN_LEEWAY_SECS` (30 s).
- `LoginFlowError::Jwks` (HTTP 503 in Actix), `LoginFlowError::kind`, `ConfigError::MissingValue`.
- `LoginFlowError::ServiceUnavailable` for a `503` from LoginFlow (busy password hashing, too many emails queued); retryable, HTTP 503 in Actix with the fixed "Authentication service unavailable" body.
- `LoginFlowError::RateLimit::retry_after_secs`: the `Retry-After` header of a `429`, when the server sent one. The Actix `ResponseError` forwards it as `Retry-After` on its own `429`.
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
- Fields the server ignores or no longer has: `LogoutRequest::user_id`, `RegisterRequest::phone`, `MultiTenantRegisterRequest::phone`, `MultiTenantRegisterRequest::role`, `RequestEmailVerificationRequest::skip_email`, `RequestEmailVerificationResponse::verification_code`, `RequestEmailVerificationResponse::verification_id`.

Changed:
- `LoginFlowClient::verify_token` is `async` and verifies ES256 via JWKS. `extract_user_from_token` and `actix::extract_user_from_request` are `async`.
- `LoginFlowClient::new` fails when `issuer`, `application_id` or `base_url` is empty. `LoginFlowConfig::from_env` requires `LOGINFLOW_ISSUER`.
- `LoginFlowConfig` has three new fields, so struct literals must add `issuer`, `jwks_url`, `jwks_cache_ttl_secs`.
- `JwtClaims`: `jti`, `email`, `role`, `status`, `company_id`, `application_id` no longer have defaults; `exp`/`iat` are numeric claims of their own; `remaining_validity()` returns `i64`; `is_expired()` uses `exp`.
- `RegisterResponse` is now `{ user_id, company_id, application_id }` (was `{ user_id, email, message }`).
- `LoginResponse::refresh_token` and `OtpLoginResponse::refresh_token`: `Option<String>` -> `String`.
- `change_password(token, user_id, company_id, req)` -> `change_password(token, req)`. The body carries only the passwords, and the error mapping is the standard one (no more "incorrect password" guessing from the body).
- `ChangePasswordResponse` is now `{ message }` holding the server's message (it was `{ success, message }` built by the SDK), deserialized from the `data` object.
- `MultiTenantCompleteResetWithTokenRequest::temporary_token` -> `reset_token`, the name of the field on the wire and in `VerifyResetCodeResponse`.
- `LoginFlowError::RateLimit(String)` -> `LoginFlowError::RateLimit { message, retry_after_secs }`.
- `LoginFlowError::from_status(status, body)` -> `LoginFlowError::from_status(status, body, retry_after_secs)`; a `503` maps to `ServiceUnavailable` instead of `ServerError`.
- `verify_email` / `resend_verification` (and `verify_email_with_company`) return an error, not `false`, for `429` and `5xx`.
- `ValidateDelegatedTokenRequest` has a required `email` field (the token creator's email).
- `AccountRecoveryResponse::ticket_id` and `support_contact`: `Option<String>` -> `String` (the server always returns both).
- `AuthenticatedUser::from_claims` / `extract_user_from_token` reject non-UUID `company_id` / `application_id`.
- `LoginFlowConfig::from_env` fails on a non-numeric `LOGIN_FLOW_TIMEOUT`.
- The secret-bearing models listed above no longer derive `Debug`; they implement it by hand with redaction (the output format changed).
- Actix 5xx error bodies carry a fixed message instead of the error text.
- `logout` returns `LoginFlowError::Validation` without calling the server when the request names neither `session_token` nor `logout_all_devices: Some(true)`.
- Actix extractors answer 500 when no `LoginFlowClient` is registered, and 503 when the JWKS cannot be obtained. `OptionalAuth` maps only rejected tokens to anonymous.
- `LoginFlowError` gained the `Jwks` and `ServiceUnavailable` variants (exhaustive matches must handle them) and implements `ResponseError::status_code`.
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
9. **Email verification:** drop `skip_email` and stop reading `verification_id`; the code is only delivered by email.
10. **Change password:** `change_password(&token, &user_id, &company_id, req)` -> `change_password(&token, req)`; read `response.message` (there is no `success` field any more; an error is returned on failure).
11. **Logout:** drop `user_id`; pass `session_token: Some(session.id)` or `logout_all_devices: Some(true)`.
12. **Accounts and profiles:** call them with a master token (they target `/v1/master/...`).
13. **Delegated login:** add the creator's email: `ValidateDelegatedTokenRequest { code, email }`. Tokens are now 8 characters; do not validate them as 6 digits.
14. **Account recovery:** `response.ticket_id` and `response.support_contact` are `String`.
15. **Code errors:** match a rejected OTP code or delegated token as `LoginFlowError::Authentication(_)` (message `INVALID_CODE_MESSAGE`); do not branch on "account not found" in the public flows, the server no longer reveals it.
16. **Error matches:** handle `LoginFlowError::Jwks` (signing keys unavailable; retryable) and `LoginFlowError::ServiceUnavailable` (retryable); match rate limits as `LoginFlowError::RateLimit { message, retry_after_secs }` and wait `retry_after_secs` when it is set.
17. **Refresh:** let concurrent requests call `refresh_token` freely (they share one request) and always store the newest refresh token. Tokens issued without `token_type` are refused by the server: those users sign in again.
18. **Cut-over:** publish this SDK, prepare the consumers with it and `LOGINFLOW_ISSUER`, deploy LoginFlow (ES256) and then the consumers in the same window. Sessions issued before the switch stop working, and users sign in once.
