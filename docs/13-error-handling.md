# 13. Manejo de errores

## Tipos
- `Config`
- `Network`
- `Authentication`
- `Authorization`
- `Validation`
- `NotFound`
- `RateLimit`
- `ServerError`
- `ParseError`
- `Timeout`

## Mapeo HTTP
- `400/422 -> Validation`
- `401 -> Authentication`
- `403 -> Authorization`
- `404 -> NotFound`
- `429 -> RateLimit`
- `5xx -> ServerError`

## Retry
`is_retryable()` es `true` para `Network`, `Timeout`, `RateLimit`, `ServerError`.
