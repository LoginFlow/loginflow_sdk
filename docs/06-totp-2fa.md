# 06. TOTP 2FA

## Enrollment and management (access token required)
- `setup_totp(token, issuer: Option<&str>) -> TotpSetupResponse`: `POST /v1/user/totp/setup`
- `verify_totp_setup(token, code) -> ()`: activates TOTP, `POST /v1/user/totp/verify-setup`
- `get_totp_status(token) -> TotpStatusResponse`: `GET /v1/user/totp/status`
- `disable_totp(token, code) -> ()`: `POST /v1/user/totp/disable`

## Login with TOTP

TOTP as a second factor is now the challenge's `next: totp` step, outside this SDK (see the
`loginflow_auth` Flutter library or the server's `docs/architecture/oidc-provider.md`). This SDK
only covers enrollment and management above.

## Models
- `TotpSetupResponse { secret, otpauth_uri, issuer }`
- `TotpStatusResponse { enabled, verified_at }`
