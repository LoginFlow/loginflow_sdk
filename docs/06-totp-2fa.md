# 06. TOTP 2FA

## Setup y administración (usuario autenticado)
- `setup_totp(token) -> TotpSetupResponse`
- `verify_totp_setup(token, code) -> TotpStatusResponse`
- `get_totp_status(token) -> TotpStatusResponse`
- `disable_totp(token, code) -> ()`

## Login con TOTP
- `login()` puede devolver `LoginResult::TotpRequired`
- completar con `verify_totp_login(VerifyTotpLoginRequest)`

## Modelos
- `TotpSetupResponse { secret, otp_auth_uri, issuer }`
- `TotpChallengeResponse { requires_2fa, totp_token, expires_in }`
- `VerifyTotpLoginRequest { totp_token, code }`
