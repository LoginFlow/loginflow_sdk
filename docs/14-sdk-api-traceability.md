# 14. SDK to API traceability

Verified against the server handlers (`loginflow_api`, `src/features/**/handler` and
`src/features/oidc_provider`) for 0.6.0; the `ServiceUsersClient` rows follow the shared
service-users contract of 0.7.0; the `AccessCodesClient` rows and the access-subject claims follow
the access-codes contract of 0.8.0 (`loginflow_api`
`src/features/access_codes/handler/service_access_codes_handler.rs`,
`docs/architecture/access-codes.md`); the catalog, organization, assignment and overage rows
follow the IAM phase 1 contract of 0.11.0 (server side in progress on `feat/iam-authorization`).

| SDK method | Route | Auth |
|---|---|---|
| `setup_totp` | `POST /v1/user/totp/setup` | access token |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` | access token |
| `get_totp_status` | `GET /v1/user/totp/status` | access token |
| `disable_totp` | `POST /v1/user/totp/disable` | access token |
| `change_password` | `POST /v1/user/change-password` | access token, recent `auth_time` (RFC 9470) |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` | - |
| `userinfo` | `GET /oauth2/userinfo` | access token (scope `openid`, `email`/`profile` by need) |
| `get_account` / `update_account` / `hard_delete_account` | `GET` / `PATCH` / `DELETE /v1/master/user-accounts/{id}` | master token |
| `soft_delete_account` / `restore_account` | `POST /v1/master/user-accounts/{id}/soft-delete` / `restore` | master token |
| `get_profile` / `update_profile` / `delete_profile` | `GET` / `PATCH` / `DELETE /v1/master/user-profiles/{id}` | master token |
| `search_profile_by_email` | `GET /v1/master/user-profiles/search?email=` | master token |
| `TokenVerifier::verify_presented` (and the Actix gate) | `GET /oauth2/jwks` (JWKS, cached); `POST /oauth2/introspect` only for an overage token | API key (introspection) |
| `verify_logout_token` | `GET /oauth2/jwks` (same JWKS; the token itself is delivered by the server to the RP's own `backchannel_logout_uri`, not fetched by the SDK) | - |
| `dpop::verify_proof_matches_cnf` / `AccessClaims::require_recent_auth` | local verification, no HTTP call | - |
| `CatalogClient::sync` / `get` | `PUT` / `GET /v1/service/catalog` (409 `catalog_app_mismatch`, `catalog_prefix_taken`, `resource_owned_by_other_api`, `permission_used_by_sign_in_gate`) | `client_credentials` token, scope `loginflow.catalog.write` |
| `OrganizationsClient::ensure` | `PUT /v1/service/organizations/external/{external_id}` (201/200) | `client_credentials` token, scope `loginflow.organizations.write` |
| `OrganizationsClient::list` / `find_by_external_id` / `root` | `GET /v1/service/organizations[?external_id=&limit=&offset=]` | `client_credentials` token, scope `loginflow.organizations.write` |
| `OrganizationsClient::get` / `delete` | `GET` / `DELETE /v1/service/organizations/{id}` (409 `root_organization`) | `client_credentials` token, scope `loginflow.organizations.write` |
| `AssignmentsClient::grant` / `list` | `POST` / `GET /v1/service/assignments` | `client_credentials` token, scope `loginflow.assignments.write` |
| `AssignmentsClient::revoke` | `DELETE /v1/service/assignments/{id}` (204) | `client_credentials` token, scope `loginflow.assignments.write` |
| `discovery` | `GET /.well-known/openid-configuration` | - |
| `ClientCredentialsClient::access_token` (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`) | client secret |
| `IntrospectionClient::introspect` / `introspect_cached` (`new` or `from_discovery`) | `POST /oauth2/introspect` | client secret |
| `RevocationClient::revoke` (`new` or `from_discovery`) | `POST /oauth2/revoke` | client secret (RFC 7009 §2.1) |
| `ServiceUsersClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.users.write`) | client secret |
| `ServiceUsersClient::create` | `POST /v1/service/users` (201) | `client_credentials` token, scope `loginflow.users.write` |
| `ServiceUsersClient::list` | `GET /v1/service/users` | `client_credentials` token, scope `loginflow.users.write` |
| `ServiceUsersClient::get` | `GET /v1/service/users/{id}` | `client_credentials` token, scope `loginflow.users.write` |
| `ServiceUsersClient::set_active` (`{is_active}` only) | `PATCH /v1/service/users/{id}` | `client_credentials` token, scope `loginflow.users.write` |
| `ServiceUsersClient::request_email_change` | `POST /v1/service/users/{id}/email-change` (202) | `client_credentials` token, scope `loginflow.users.write` |
| `ServiceUsersClient::confirm_email_change` | `POST /v1/service/users/{id}/email-change/confirm` (409 `email_shared`) | `client_credentials` token, scope `loginflow.users.write` |
| `AccessCodesClient` token (`new` or `from_discovery`) | `POST /oauth2/token` (`grant_type=client_credentials`, `scope=loginflow.accessCodes.issue`) | client secret |
| `AccessCodesClient::issue` | `POST /v1/service/access-codes` (201; 409 `access_codes_disabled`; 422 validation) | `client_credentials` token, scope `loginflow.accessCodes.issue` |
| `AccessCodesClient::list` | `GET /v1/service/access-codes[?external_subject=]` | `client_credentials` token, scope `loginflow.accessCodes.issue` |
| `AccessCodesClient::revoke` | `DELETE /v1/service/access-codes/{id}` (204) | `client_credentials` token, scope `loginflow.accessCodes.issue` |
| `AccessCodesClient::revoke_subject_sessions` | `POST /v1/service/access-subjects/revoke` | `client_credentials` token, scope `loginflow.accessCodes.issue` |
| `AccessClaims::access_subject`, `Authorized::subject` | local verification (claims of a token minted for an access-code subject), no HTTP call | - |

## Not exposed by the SDK
- Application/OAuth-client management (`/v1/master/applications`, `/v1/master/oauth-clients`, including the client-secret issuance/rotation, `PATCH .../scopes` that grants the `loginflow.*` machine scopes, the API of a machine key and the sign-in gate), roles and the permission catalog of the panel: the SDK has no admin API for these; they are operator tools (dashboard).
- `/v1/master/sessions*`, `/v1/master/security/*`: operator-only master endpoints.
- The access-code panel routes (`/v1/master/applications/{application_id}/access-code-settings`, `/v1/master/applications/{application_id}/access-codes`, `/v1/master/access-codes*`): operator tools (dashboard). Redeeming a code (`/oauth2/authorize-challenge`, `method=access_code`) is the app's job (`loginflow_auth`), like every other end-user sign-in.
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
