# 13. Error handling

## Variants (`LoginFlowError`)
- `Config`: missing or invalid configuration, client not registered in Actix
- `Network`
- `Authentication`: bad credentials, rejected token
- `Authorization { message, code }` (0.12.0): `403`; `code` is the envelope's `error.code` (e.g. `"role_not_grantable"`, `"organization_out_of_reach"`, `"privilege_exceeds_grantor"` from `MembersClient`)
- `Validation`
- `NotFound`
- `Conflict { message, code }` (0.7.0): `409`; `code` is the envelope's `error.code` (e.g. `"email_shared"` from `ServiceUsersClient::confirm_email_change`)
- `RateLimit { message, retry_after_secs }`: `retry_after_secs` comes from the `Retry-After` header (`None` when the server sent none)
- `ServiceUnavailable`: the server is temporarily unable to serve the request (busy, too many emails queued); try again later
- `ServerError`
- `ParseError`
- `Timeout`
- `Jwks`: the signing keys could not be downloaded or are unusable
- `InsufficientUserAuthentication { max_age_secs }`: `401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication"` (RFC 9470) — the credential is fine, the session is just too old for this operation (e.g. `change_password`); send the user through a fresh login step-up and retry, it is not a plain rejected-credential `Authentication`

## HTTP mapping (server responses)
- `400/422 -> Validation`
- `401 -> Authentication`
- `403 -> Authorization` (with `error.code`)
- `404 -> NotFound`
- `409 -> Conflict` (with `error.code`)
- `429 -> RateLimit` (with `Retry-After` seconds when present)
- `503 -> ServiceUnavailable`
- other `5xx -> ServerError`

The message is `error.message` from the server's error envelope. Error bodies are read up to 4
KiB. Failed calls log the status and error code at `error`; the body is logged at `debug` only,
because it can contain personal data. `/oauth2/token`, `/oauth2/introspect`, `/oauth2/userinfo`
and the back-channel-logout/DPoP local verification sit outside the `{data, meta}` envelope
entirely — see the README for their own shapes.

## Retry
`is_retryable()` is `true` for `Network`, `Timeout`, `RateLimit`, `ServiceUnavailable`, `ServerError` and `Jwks`. On a `RateLimit`, wait `retry_after_secs` when it is set.

## Re-authentication
`requires_reauthentication()` is `true` for `Authentication`. When it is true, clear the local tokens and send the user to login.
