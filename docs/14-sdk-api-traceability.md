# 14. Trazabilidad SDK ↔ API

## Alineación confirmada
- `register` -> `POST /v1/public/user-accounts`
- `login` -> `POST /v1/public/login-password`
- `refresh_token` -> `POST /v1/public/refresh-token`
- `logout` -> `POST /v1/user/logout` (requiere `Authorization: Bearer <jwt>`)
- `request_otp_login` -> `POST /v1/public/request-otp-login`
- `login_with_otp` -> `POST /v1/public/login-with-otp`
- `request_passwordless_code` -> `POST /v1/public/request-passwordless-code`
- `authenticate_passwordless` -> `POST /v1/public/authenticate-passwordless`
- `verify_totp_login` -> `POST /v1/public/verify-totp`
- `setup_totp` -> `POST /v1/user/totp/setup`
- `verify_totp_setup` -> `POST /v1/user/totp/verify-setup`
- `get_totp_status` -> `GET /v1/user/totp/status`
- `disable_totp` -> `POST /v1/user/totp/disable`
- `login_with_oauth` -> `POST /v1/public/oauth-login`
- `request_password_reset` -> `POST /v1/public/reset-password`
- `verify_reset_code` -> `POST /v1/public/reset-password/verify`
- `complete_password_reset` -> `POST /v1/public/reset-password/complete`
- `change_password` -> `POST /v1/user/change-password`
- `verify_email` -> `POST /v1/public/verify-email`
- `resend_verification` -> `POST /v1/public/resend-verification`

## Nota sobre passwordless
- El SDK ya soporta el flujo passwordless dedicado del backend.
- Paso 1: `request_passwordless_code`
- Paso 2: `authenticate_passwordless`
- En modo multi-tenant: `request_passwordless_code_with_company` y `authenticate_passwordless_with_company`

## Nota de seguridad de sesión
- Backend actual valida blacklist + sesión activa en middleware JWT y en refresh.
- Implicación SDK: errores `401` deben tratarse como señal para invalidar sesión local y forzar relogin.
