# 13. Error handling

## Variants (`LoginFlowError`)
- `Config`: a missing or invalid setting, an HTTP client that cannot be built, or `Authorized`
  asked for outside the permission gate
- `Network`: the request could not be sent or answered, or an unexpected HTTP status
- `Authentication`: the access token or the client credentials were refused (expired, revoked,
  ended session, wrong secret)
- `Authorization { message, code }`: `403`; `code` is the envelope's `error.code` (e.g.
  `"role_not_grantable"`, `"organization_out_of_reach"`, `"principal_outranks_client"`,
  `"catalog_writer_not_allowed"`, `"permission_denied"`)
- `Validation { message, code }`: `400`/`422`, or a `401` with code `INVALID_CODE` (a wrong or
  locked-out TOTP code); `message` is the server's specific reason, `code` e.g.
  `"VALIDATION_ERROR"`, `"BAD_REQUEST"`, `"INVALID_CODE"`, `"expires_at_in_past"`,
  `"role_not_assignable_here"`. A check the SDK runs before sending (the manifest) has no `code`
- `NotFound { message, code }`: `404`; `code` e.g. `"member_not_found"`,
  `"organization_not_found"`, `"role_not_found"`, `"assignment_not_found"`, `"NOT_FOUND"`
- `Conflict { message, code }`: `409`; `code` e.g. `"access_codes_disabled"`
  (`ACCESS_CODES_DISABLED_CODE`), `"root_organization"`, `"system_application"`,
  `"catalog_app_mismatch"`, `"CONFLICT"`
- `RateLimit { message, retry_after_secs }`: `retry_after_secs` comes from the `Retry-After`
  header (`None` when the server sent none)
- `ServiceUnavailable`: the server is temporarily unable to serve the request (busy, too many
  emails queued); try again later
- `ServerError`
- `ParseError`
- `Timeout`
- `Jwks`: the signing keys could not be downloaded or are unusable
- `InsufficientUserAuthentication { max_age_secs }`: `401` with `WWW-Authenticate: Bearer
  error="insufficient_user_authentication"` (RFC 9470) — the credential is fine, the session is
  just too old for this operation (e.g. `change_password`); send the user through a fresh login
  step-up and retry, it is not a plain rejected-credential `Authentication`

## HTTP mapping (server responses)
- `400`, `422` -> `Validation` (with `error.code`)
- `401` with code `INVALID_CODE` -> `Validation`
- `401` with `WWW-Authenticate: ... insufficient_user_authentication` -> `InsufficientUserAuthentication`
- any other `401` -> `Authentication`
- `403` -> `Authorization` (with `error.code`)
- `404` -> `NotFound` (with `error.code`)
- `409` -> `Conflict` (with `error.code`)
- `429` -> `RateLimit` (with `Retry-After` seconds when present)
- `503` -> `ServiceUnavailable`
- other `5xx` -> `ServerError`
- anything else -> `Network`

The message is `error.details` when it is text (the server puts the specific reason of a
validation error there, under a generic `error.message`), otherwise `error.message`, otherwise
the raw body. Error bodies are read up to 4 KiB. Failed calls log the status and error code at
`error`; the body is logged at `debug` only, because it can contain personal data.
`/oauth2/token`, `/oauth2/introspect`, `/oauth2/userinfo` and the back-channel-logout/DPoP local
verification sit outside the `{data, meta}` envelope entirely — see the README for their own
shapes. `LoginFlowErrorResponse` parses the envelope itself when a product needs it (`details`
is text or a JSON object; `meta.request_id` and `meta.path` may be `null`).

## Retry
`is_retryable()` is `true` for `Network`, `Timeout`, `RateLimit`, `ServiceUnavailable`,
`ServerError` and `Jwks`. On a `RateLimit`, wait `retry_after_secs` when it is set. The
`/v1/service/*` clients already retry once, with a fresh token, a `401` caused by their cached
token.

## Re-authentication
`requires_reauthentication()` is `true` for `Authentication` and
`InsufficientUserAuthentication`. When it is true, clear the person's local tokens and send them
to login (or to a step-up). A wrong TOTP code is a `Validation` error and never asks for it.
