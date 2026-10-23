# 14. SDK to API traceability

Verified against the server handlers (`loginflow_api`, `src/features/**/handler` and
`src/features/oidc_provider`) for 0.6.0; the `ServiceUsersClient` rows follow the shared
service-users contract of 0.7.0; the `AccessCodesClient` rows and the access-subject claims follow
the access-codes contract of 0.8.0 (`loginflow_api`
`src/features/access_codes/handler/service_access_codes_handler.rs`,
`docs/architecture/access-codes.md`); the catalog, organization, assignment and overage rows
follow the IAM phase 1 contract of 0.11.0; the `MembersClient` rows follow the IAM phase 2
members contract of 0.12.0 (`loginflow_api`
`src/features/authorization/handler/service_authorization_handler.rs`,
`docs/api/v1/service/members/`).

| SDK method | Route | Auth |
|---|---|---|
| `setup_totp` | `POST /v1/user/totp/setup` | access token |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` | access token |
| `get_totp_status` | `GET /v1/user/totp/status` | access token |
| `disable_totp` | `POST /v1/user/totp/disable` | access token |
| `change_password` | `POST /v1/user/change-password` | access token, recent `auth_time` (RFC 9470) |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` | - |
| `userinfo` | `GET /oauth2/userinfo` | access token (scope `openid`, `email`/`profile` by need) |
| `TokenVerifier::verify_presented` (and the Actix gate) | `GET /oauth2/jwks` (JWKS, cached); `POST /oauth2/introspect` only for an overage token | API key (introspection) |
| `verify_logout_token` | `GET /oauth2/jwks` (same JWKS; the token itself is delivered by the server to the RP's own `backchannel_logout_uri`, not fetched by the SDK) | - |
| `dpop::verify_proof_matches_cnf` / `AccessClaims::require_recent_auth` | local verification, no HTTP call | - |
| `CatalogClient::sync` / `get` | `PUT` / `GET /v1/service/catalog` (409 `catalog_app_mismatch`, `catalog_prefix_taken`, `resource_owned_by_other_api`, `permission_used_by_sign_in_gate`) | `client_credentials` token; `PUT` needs `loginflow.catalog.write`, `GET` `loginflow.catalog.read` |
| `OrganizationsClient::ensure` | `PUT /v1/service/organizations/external/{external_id}` (201/200) | `client_credentials` token, permission `loginflow.organizations.write` |
| `OrganizationsClient::list` / `find_by_external_id` / `root` | `GET /v1/service/organizations[?external_id=&limit=&offset=]` | `client_credentials` token, permission `loginflow.organizations.read` |
| `OrganizationsClient::get` / `delete` | `GET` / `DELETE /v1/service/organizations/{id}` (409 `root_organization`) | `client_credentials` token; `GET` needs `loginflow.organizations.read`, `DELETE` `loginflow.organizations.write` |
| `MembersClient::grantable_roles` | `GET /v1/service/members/grantable-roles` (the key's own list; empty for a new key) | `client_credentials` token, permission `loginflow.assignments.read` |
| `MembersClient::grant` / `list` | `POST` / `GET /v1/service/members` (403 `role_not_grantable` for a role outside the key's list; 404 `organization_not_found`, `role_not_found`, `member_not_found`; 422 `expires_at_in_past`, `role_not_assignable_here`; 409 `system_application`) | `client_credentials` token; `POST` needs `loginflow.assignments.write`, `GET` `loginflow.assignments.read` |
| `MembersClient::revoke` | `DELETE /v1/service/members/assignments/{id}` (204; 404 `assignment_not_found`, 403 `role_not_grantable`) | `client_credentials` token, permission `loginflow.assignments.write` |
| `discovery` | `GET /.well-known/openid-configuration` | - |
| `ClientCredentialsClient::access_token` (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`) | client secret |
| `IntrospectionClient::introspect` / `introspect_cached` (`new` or `from_discovery`) | `POST /oauth2/introspect` | client secret |
| `RevocationClient::revoke` (`new` or `from_discovery`) | `POST /oauth2/revoke` | client secret (RFC 7009 §2.1) |
| `ServiceUsersClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.users.read loginflow.users.write`) | client secret |
| `ServiceUsersClient::create` | `POST /v1/service/users` (201) | `client_credentials` token, permission `loginflow.users.write` |
| `ServiceUsersClient::list` | `GET /v1/service/users` | `client_credentials` token, permission `loginflow.users.read` |
| `ServiceUsersClient::get` | `GET /v1/service/users/{id}` | `client_credentials` token, permission `loginflow.users.read` |
| `ServiceUsersClient::set_active` (`{is_active}` only) | `PATCH /v1/service/users/{id}` | `client_credentials` token, permission `loginflow.users.write` |
| `AccessCodesClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke`) | client secret |
| `AccessCodesClient::issue` | `POST /v1/service/access-codes` (201; 409 `access_codes_disabled`; 422 validation) | `client_credentials` token, permission `loginflow.accessCodes.issue` |
| `AccessCodesClient::list` | `GET /v1/service/access-codes[?external_subject=]` | `client_credentials` token, permission `loginflow.accessCodes.read` |
| `AccessCodesClient::revoke` | `DELETE /v1/service/access-codes/{id}` (204) | `client_credentials` token, permission `loginflow.accessCodes.revoke` |
| `AccessCodesClient::revoke_subject_sessions` | `POST /v1/service/access-subjects/revoke` | `client_credentials` token, permission `loginflow.accessCodes.revoke` |
| `AccessClaims::access_subject`, `Authorized::subject` | local verification (claims of a token minted for an access-code subject), no HTTP call | - |

## Not exposed by the SDK
- The LoginFlow panel's routes: application/OAuth-client management (including the client-secret issuance/rotation, the `loginflow.*` machine scopes, the API of a machine key, its grantable roles and the sign-in gate), roles, their grantable roles, the permission catalog, user accounts and profiles, sessions, security events and the access-code settings. The SDK has no admin API for these: they are operator tools (dashboard), behind a token no product backend can obtain.
- `/v1/app/members` (a person granting roles with their own DPoP-bound LoginFlow token): the SDK verifies DPoP but never signs it, so a backend cannot act there; the product's frontend does, with `loginflow_auth` (ASVS V8.3.3: the person, not the backend, authorizes).
- Redeeming an access code (`/oauth2/authorize-challenge`, `method=access_code`) is the app's job (`loginflow_auth`), like every other end-user sign-in.
- The hosted/native OIDC challenge (`/oauth2/authorize-challenge`, `/login/*`) and the end-user session endpoints (`/oauth2/authorize`, `/oauth2/end-session`, `/oauth2/device-logout`, `/oauth2/logout-everywhere`): issuing or ending a *user's own* session is the hosted/native login's job, not this SDK's — see `loginflow_auth` (Flutter) or the server's `docs/architecture/oidc-provider.md`. `/oauth2/revoke` is the one exception: a confidential backend revoking a token it holds (not a user-facing sign-out) is exactly this SDK's job, hence `RevocationClient`.

## Removed from the SDK in 0.6.0
Every REST login method (`register`, `login`, `refresh_token`, `logout`, `request_otp_login`,
`login_with_otp`, `verify_totp_login`, `verify_totp_code`, `login_with_oauth`,
`request_password_reset`, `verify_reset_code`, `complete_password_reset`,
`request_email_verification`, `verify_email`, `resend_verification`,
`create_delegated_token`, `validate_delegated_token`) and the `multi-tenant` feature — see
`CHANGELOG.md` 0.6.0. Their server routes are deleted too (`removed_endpoints_test.rs` in
`loginflow_api`), not just unreachable from this SDK.

## Session security
The server checks the session and the token revocation list on every authenticated request.
Local verification (`TokenVerifier`) checks signature and claims only, so a revoked token keeps
verifying locally until its `exp` — this is why the access token is short-lived (10 minutes by
default) and why a sensitive operation should use `IntrospectionClient::introspect_cached`
instead of relying on local verification alone. Treat a `401` from an authenticated call as a
signal to clear the local session.
