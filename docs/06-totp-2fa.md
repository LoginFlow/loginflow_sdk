# 06. TOTP 2FA

## Enrollment and management (access token required)
- `setup_totp(token, issuer: Option<&str>) -> TotpSetupResponse`: `POST /v1/user/totp/setup`
- `verify_totp_setup(token, code) -> ()`: activates TOTP, `POST /v1/user/totp/verify-setup`
- `verify_totp_code(token, code) -> ()`: stateless check, `POST /v1/user/totp/verify-code`
- `get_totp_status(token) -> TotpStatusResponse`: `GET /v1/user/totp/status`
- `disable_totp(token, code) -> ()`: `POST /v1/user/totp/disable`

## Login with TOTP
- `login()` (and `login_with_oauth()`) can return `LoginResult::TotpRequired`.
- Complete it with `verify_totp_login(VerifyTotpLoginRequest)`: `POST /v1/public/verify-totp`.

The challenge `totp_token` has `token_type = "totp_challenge"` and `aud` = the issuer. `verify_token` and the Actix extractors reject it.

## Models
- `TotpSetupResponse { secret, otpauth_uri, issuer }`
- `TotpStatusResponse { enabled, verified_at }`
- `TotpChallengeResponse { requires_2fa, totp_token, expires_in }`
- `VerifyTotpLoginRequest { totp_token, code }`
