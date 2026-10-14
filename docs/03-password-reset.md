# 03. Password reset and change

## SDK methods
- `request_password_reset(email: &str, language: Option<&str>) -> ()`
- `verify_reset_code(VerifyResetCodeRequest) -> VerifyResetCodeResponse`
- `complete_password_reset(CompleteResetRequest) -> ()`
- `change_password(token: &str, ChangePasswordRequest) -> ChangePasswordResponse`

## Reset flow
1. Request the code: `POST /v1/public/reset-password`. The server answers with the same message whether or not a code was sent (unknown email, inactive, unverified or locked account, request limit), so `Ok(())` means "accepted". Only a malformed email is an error.
2. Verify it: `POST /v1/public/reset-password/verify` returns `{ reset_token }`
3. Complete: `POST /v1/public/reset-password/complete`

Models:
- `VerifyResetCodeRequest { email, code }`
- `CompleteResetRequest { email, code, new_password, confirm_password }`
- `VerifyResetCodeResponse { reset_token }`

The reset code has 8 digits and may start with `0`: keep it as a `String`, never parse it as a number. A code is burned after 5 failed attempts.

`complete_password_reset` runs step 2 internally to obtain the `reset_token`, then step 3. Every rejected code (wrong, expired, burned, unknown; the server answers one `422`) is reported as `LoginFlowError::Authentication(INVALID_RESET_CODE_MESSAGE)` (`"Invalid or expired reset code"`); rate limits and server errors keep their own variant.

## Change password (authenticated)

`POST /v1/user/change-password` with `Authorization: Bearer <access_token>`.

```rust
ChangePasswordRequest { current_password, new_password, confirm_password }
```

The body carries only the passwords. User, company and application come from the access token. The result is `ChangePasswordResponse { message }` with the server's message; failures are errors.
