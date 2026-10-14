# 03. Password reset and change

## SDK methods
- `request_password_reset(email: &str, language: Option<&str>) -> ()`
- `verify_reset_code(VerifyResetCodeRequest) -> VerifyResetCodeResponse`
- `complete_password_reset(CompleteResetRequest) -> ()`
- `change_password(token: &str, ChangePasswordRequest) -> ChangePasswordResponse`

## Reset flow
1. Request the code: `POST /v1/public/reset-password`
2. Verify it: `POST /v1/public/reset-password/verify` returns `{ reset_token }`
3. Complete: `POST /v1/public/reset-password/complete`

Models:
- `VerifyResetCodeRequest { email, code }`
- `CompleteResetRequest { email, code, new_password, confirm_password }`
- `VerifyResetCodeResponse { reset_token }`

`complete_password_reset` runs step 2 internally to obtain the `reset_token`, then step 3. A rejected code is reported as `LoginFlowError::Authentication("Invalid or expired reset code")`; rate limits and server errors keep their own variant.

## Change password (authenticated)

`POST /v1/user/change-password` with `Authorization: Bearer <access_token>`.

```rust
ChangePasswordRequest { current_password, new_password, confirm_password }
```

The body carries only the passwords. User, company and application come from the access token. The result is `ChangePasswordResponse { message }` with the server's message; failures are errors.
