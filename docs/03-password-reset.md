# 03. Password reset

## Métodos SDK
- `request_password_reset(email: &str) -> ()`
- `verify_reset_code(VerifyResetCodeRequest) -> VerifyResetCodeResponse`
- `complete_password_reset(CompleteResetRequest) -> ()`

## Flujo
1. Solicitar reset (`/public/reset-password`)
2. Verificar código (`/public/reset-password/verify`)
3. Completar (`/public/reset-password/complete`)

## Request models
- `VerifyResetCodeRequest { email, code }`
- `CompleteResetRequest { email, code, new_password, confirm_password }`

## Response clave
- `VerifyResetCodeResponse { reset_token }`

## Comportamiento interno
`complete_password_reset` primero ejecuta verify para obtener `reset_token` y luego completa el reset.
