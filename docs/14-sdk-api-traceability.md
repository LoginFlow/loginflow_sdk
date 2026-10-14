# 14. SDK to API traceability

Verified against the server handlers (`loginflow_api`, `src/features/**/handler`) for 0.5.0.

| SDK method | Route | Auth |
|---|---|---|
| `register` | `POST /v1/public/user-accounts` | - |
| `login` | `POST /v1/public/login-password` | - |
| `refresh_token` | `POST /v1/public/refresh-token` | - |
| `logout` | `POST /v1/user/logout` | access token |
| `request_otp_login` | `POST /v1/public/request-otp-login` | - |
| `login_with_otp` | `POST /v1/public/login-with-otp` | - |
| `verify_totp_login` | `POST /v1/public/verify-totp` | - |
| `setup_totp` | `POST /v1/user/totp/setup` | access token |
| `verify_totp_setup` | `POST /v1/user/totp/verify-setup` | access token |
| `verify_totp_code` | `POST /v1/user/totp/verify-code` | access token |
| `get_totp_status` | `GET /v1/user/totp/status` | access token |
| `disable_totp` | `POST /v1/user/totp/disable` | access token |
| `login_with_oauth` | `POST /v1/public/oauth-login` | - |
| `request_password_reset` | `POST /v1/public/reset-password` | - |
| `verify_reset_code` | `POST /v1/public/reset-password/verify` | - |
| `complete_password_reset` | `POST /v1/public/reset-password/complete` | - |
| `change_password` | `POST /v1/user/change-password` | access token |
| `request_email_verification` | `POST /v1/public/request-email-verification` | - |
| `verify_email` | `POST /v1/public/verify-email` | - |
| `resend_verification` | `POST /v1/public/resend-verification` | - |
| `create_delegated_token` | `POST /v1/user/auth/create-delegated-token` | access token |
| `validate_delegated_token` | `POST /v1/public/auth/validate-delegated-token` | - |
| `request_account_recovery` | `POST /v1/public/auth/request-account-recovery` | - |
| account methods | `/v1/master/user-accounts/...` | master token |
| profile methods | `/v1/master/user-profiles/...` | master token |
| token verification | `GET /oauth2/jwks` | - |

## Not exposed by the SDK
- `/v1/master/clients/send-reset`, `/v1/master/clients/send-login`, `/v1/master/accounts-verification`: moved from `/v1/public` to the master scope on the server; they are operator tools, not consumer flows.
- `POST /v1/public/validate` (client-code validation, answers `401` on any failure): an operator flow paired with the master client-code endpoints.
- Application management (`/v1/master/applications`, including `allow_self_signup`): the SDK has no applications API.

## Removed on the server
- The former passwordless routes (`/v1/public/request-passwordless-code`, `/v1/public/authenticate-passwordless`): merged into the OTP login.
- `POST /v1/master/verification-codes`.

## Uniform answers (anti-enumeration)
- `request_otp_login`, `request_password_reset`, `request_email_verification`, `resend_verification`: same success response whether or not a code was sent.
- `register`: an existing email gets the same shape with a random `user_id`.
- `request_account_recovery`: always returns a `ticket_id`.
- `login_with_otp`, `validate_delegated_token`: every rejected code is one `401`, reported as `Authentication(INVALID_CODE_MESSAGE)`. `verify_reset_code`: one `401`, reported as `Authentication(INVALID_RESET_CODE_MESSAGE)`. `verify_email`: one `401` (`false`).

## Session security
The server checks the session and the token revocation list on every authenticated request. Local verification (`verify_token`) checks signature and claims only, so a revoked token keeps verifying locally until its `exp`. Keep access tokens short-lived. Treat a `401` from an authenticated call as a signal to clear the local session; on the anonymous code flows (`login_with_otp`, `validate_delegated_token`, `verify_reset_code`) it only means the code was rejected.
