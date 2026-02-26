# 07. OAuth login

## Método SDK
- `login_with_oauth(OAuthLoginRequest) -> LoginResult`

## Request
`OAuthLoginRequest { provider, id_token }`

El SDK añade `company_id` y `application_id` automáticamente.

## Endpoint
`POST /v1/public/oauth-login`

## Providers válidos backend
- `google`
- `microsoft`

## Nota
Se requiere configuración previa de provider en API master (`/v1/master/oauth-providers`).
