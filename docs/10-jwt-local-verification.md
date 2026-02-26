# 10. Verificación local JWT

## Funciones
- `decode_jwt_claims(token)` -> decode sin validar firma.
- `verify_jwt_claims(token, signing_secret)` -> valida HMAC SHA-256 + expiración.
- `LoginFlowClient::verify_token(token)` -> usa `signing_secret` de config.

## Recomendación
En backend productivo usa siempre verificación con firma (`LOGINFLOW_SIGNING_SECRET`).
