# 13. Error handling

## Variants (`LoginFlowError`)
- `Config`: missing or invalid configuration, client not registered in Actix
- `Network`
- `Authentication`: bad credentials, rejected token
- `Authorization`
- `Validation`
- `NotFound`
- `RateLimit`
- `ServerError`
- `ParseError`
- `Timeout`
- `Jwks`: the signing keys could not be downloaded or are unusable

## HTTP mapping (server responses)
- `400/422 -> Validation`
- `401 -> Authentication`
- `403 -> Authorization`
- `404 -> NotFound`
- `429 -> RateLimit`
- `5xx -> ServerError`

The message is `error.message` from the server's error envelope, except for rejected one-time codes, where the server's body is generic: `login_with_otp` and `validate_delegated_token` report `Authentication(INVALID_CODE_MESSAGE)` ("The code is invalid or has expired"), and `verify_reset_code` / `complete_password_reset` report `Authentication(INVALID_RESET_CODE_MESSAGE)` ("Invalid or expired reset code"). Error bodies are read up to 4 KiB. Failed calls log the status and error code at `error`; the body is logged at `debug` only, because it can contain personal data.

## Retry
`is_retryable()` is `true` for `Network`, `Timeout`, `RateLimit`, `ServerError` and `Jwks`.

## Re-authentication
`requires_reauthentication()` is `true` for `Authentication`. When it is true, clear the local tokens and send the user to login. On the anonymous code flows above it only means the code was rejected.
