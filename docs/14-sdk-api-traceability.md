# 14. Trazabilidad SDK ↔ API

## Alineación confirmada
- `login` -> `POST /v1/public/login-password`
- `refresh_token` -> `POST /v1/public/refresh-token`
- `logout` -> `POST /v1/user/logout` (requiere `Authorization: Bearer <jwt>`)
- `request_otp_login` -> `POST /v1/public/request-otp-login`
- `login_with_otp` -> `POST /v1/public/login-with-otp`
- `verify_totp_login` -> `POST /v1/public/verify-totp`
- `setup_totp` -> `POST /v1/user/totp/setup`
- `verify_totp_setup` -> `POST /v1/user/totp/verify-setup`
- `get_totp_status` -> `GET /v1/user/totp/status`
- `disable_totp` -> `POST /v1/user/totp/disable`
- `login_with_oauth` -> `POST /v1/public/oauth-login`
- `request_password_reset` -> `POST /v1/public/reset-password`
- `verify_reset_code` -> `POST /v1/public/reset-password/verify`
- `complete_password_reset` -> `POST /v1/public/reset-password/complete`
- `verify_email` -> `POST /v1/public/verify-email`
- `resend_verification` -> `POST /v1/public/resend-verification`

## Desalineaciones críticas
1. `register`
- SDK: `POST /v1/public/users`
- Backend actual: `POST /v1/public/user-accounts`

2. `change_password`
- SDK: `POST /v1/public/change-password`
- Backend actual: `POST /v1/user/change-password`

## Impacto
Si backend está en versión actual de `login_flow`, estos dos métodos pueden fallar por 404/route mismatch hasta alinear rutas.

## Nota de seguridad de sesión
- Backend actual valida blacklist + sesión activa en middleware JWT y en refresh.
- Implicación SDK: errores `401` deben tratarse como señal para invalidar sesión local y forzar relogin.
