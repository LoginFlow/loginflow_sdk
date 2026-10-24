# 14. SDK to API traceability

Verified route by route, body by body and answer by answer against `loginflow_api` main
(`src/features/**/handler`, `src/features/control_plane/model/route_permissions.rs`
`SERVICE_ROUTES`, `src/features/oidc_provider`, `docs/api/**`) in the 0.14.0 audit. Every
`/v1/service/*` route takes the tenant from the token only, refuses unknown body and query fields
(`400`), and answers an id that is not a UUID with `400 BAD_REQUEST` (`Validation`). The account
calls send the person's token as `Bearer`: a DPoP-bound token is refused (`401`).

| SDK method | Route | Auth |
|---|---|---|
| `setup_totp` | `POST /v1/user/totp/setup` (optional `{issuer}`) | access token |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` (`401 INVALID_CODE` for a wrong code → `Validation`) | access token |
| `get_totp_status` | `GET /v1/user/totp/status` | access token |
| `disable_totp` | `POST /v1/user/totp/disable` (`401 INVALID_CODE` → `Validation`) | access token |
| `change_password` | `POST /v1/user/change-password` | access token, recent `auth_time` (RFC 9470) |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` | - |
| `userinfo` | `GET /oauth2/userinfo` | access token (scope `openid`, `email`/`profile` by need) |
| `TokenVerifier::verify_presented` (and the Actix gate) | `GET /oauth2/jwks` (JWKS, cached); `POST /oauth2/introspect` only for an overage token (`active`, `org_id`, `permissions` of the token's API) | API key (introspection: only the key of the token's API gets an answer) |
| `verify_logout_token` | `GET /oauth2/jwks` (same JWKS; the token itself is delivered by the server to the RP's own `backchannel_logout_uri`, not fetched by the SDK) | - |
| `dpop::verify_proof_matches_cnf` / `AccessClaims::require_recent_auth` | local verification, no HTTP call | - |
| `CatalogClient::sync` / `get` | `PUT` / `GET /v1/service/catalog` (409 `catalog_app_mismatch`, `catalog_prefix_taken`, `resource_owned_by_other_api`, `permission_used_by_sign_in_gate`, `system_catalog`; 403 `catalog_writer_not_allowed`; 422 with the reason in `details`) | `client_credentials` token; `PUT` needs `loginflow.catalog.write`, `GET` `loginflow.catalog.read` |
| `OrganizationsClient::ensure` | `PUT /v1/service/organizations/external/{external_id}` (201/200) | `client_credentials` token, permission `loginflow.organizations.write` |
| `OrganizationsClient::list` / `find_by_external_id` / `root` | `GET /v1/service/organizations[?external_id=&limit=&offset=]` | `client_credentials` token, permission `loginflow.organizations.read` |
| `OrganizationsClient::get` / `delete` | `GET` / `DELETE /v1/service/organizations/{id}` (409 `root_organization`) | `client_credentials` token; `GET` needs `loginflow.organizations.read`, `DELETE` `loginflow.organizations.write` |
| `MembersClient::grantable_roles` | `GET /v1/service/members/grantable-roles` (the key's own list, each with `held_by`; empty for a new key) | `client_credentials` token, permission `loginflow.assignments.read` |
| `MembersClient::grant` / `list` | `POST` / `GET /v1/service/members`; `grant` sends `actor_token` (400 `actor_token_required`; 401 `invalid_actor_token`; 403 `key_role_not_grantable` for a role outside the key's list, `role_not_grantable` / `organization_out_of_reach` / `self_assignment_forbidden` / `privilege_exceeds_grantor` for the person; 404 `organization_not_found`, `role_not_found`, `member_not_found`; 422 `role_not_held_by_principal`, `expires_at_in_past`, `role_not_assignable_here`; 409 `system_application`) | `client_credentials` token; `POST` needs `loginflow.assignments.write`, `GET` `loginflow.assignments.read` |
| `MembersClient::revoke` | `DELETE /v1/service/members/assignments/{id}` with `{"actor_token"}` (204; 404 `assignment_not_found`; 403 `key_role_not_grantable`, `role_not_grantable`; 400 `actor_token_required`; 401 `invalid_actor_token`) | `client_credentials` token, permission `loginflow.assignments.write` |
| `discovery` | `GET /.well-known/openid-configuration` | - |
| `ClientCredentialsClient::access_token` (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`) | client secret |
| `IntrospectionClient::introspect` / `introspect_cached` (`new` or `from_discovery`) | `POST /oauth2/introspect` | client secret |
| `RevocationClient::revoke` (`new` or `from_discovery`) | `POST /oauth2/revoke` | client secret (RFC 7009 §2.1) |
| `ServiceUsersClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.users.read loginflow.users.write`) | client secret |
| `ServiceUsersClient::create` | `POST /v1/service/users` (201) | `client_credentials` token, permission `loginflow.users.write` |
| `ServiceUsersClient::list` | `GET /v1/service/users` | `client_credentials` token, permission `loginflow.users.read` |
| `ServiceUsersClient::get` | `GET /v1/service/users/{id}` | `client_credentials` token, permission `loginflow.users.read` |
| `ServiceUsersClient::set_active` (`{is_active}` only) | `PATCH /v1/service/users/{id}` (403 `principal_outranks_client`) | `client_credentials` token, permission `loginflow.users.write` |
| `ServiceUsersClient::delete` | `DELETE /v1/service/users/{id}` (200 `{id, profile_deleted}`; 409 when data depends on it) | `client_credentials` token, permission `loginflow.users.write` |
| `AccessCodesClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke`) | client secret |
| `AccessCodesClient::issue` | `POST /v1/service/access-codes` (201; 409 `access_codes_disabled`; 422 validation) | `client_credentials` token, permission `loginflow.accessCodes.issue` |
| `AccessCodesClient::list` | `GET /v1/service/access-codes[?external_subject=]` | `client_credentials` token, permission `loginflow.accessCodes.read` |
| `AccessCodesClient::revoke` | `DELETE /v1/service/access-codes/{id}` (204) | `client_credentials` token, permission `loginflow.accessCodes.revoke` |
| `AccessCodesClient::revoke_subject_sessions` | `POST /v1/service/access-subjects/revoke` (404 for a subject never issued a code) | `client_credentials` token, permission `loginflow.accessCodes.revoke` |
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
