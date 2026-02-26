# 11. Integración Actix

## Componentes
- `AuthMiddleware`: requiere JWT válido, retorna 401 si falla.
- `OptionalAuth`: no falla, entrega `None` cuando no hay auth válida.

## Helpers
- `extract_token_from_request`
- `extract_user_from_request`
- `verify_token_with_secret`

## Nota de seguridad
Si `LoginFlowClient` está en `app_data` y tiene `signing_secret`, el extractor valida firma. Si no, hace decode-only.
