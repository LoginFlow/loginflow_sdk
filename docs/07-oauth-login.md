# 07. OAuth login

## SDK method
- `login_with_oauth(OAuthLoginRequest) -> LoginResult`

## Request
`OAuthLoginRequest { provider, id_token }`. The SDK adds `company_id` and `application_id`.

## Endpoint
`POST /v1/public/oauth-login`

## Providers
- `google`
- `microsoft`

The provider must be configured first through the master API (`/v1/master/oauth-providers`). The result can be a TOTP challenge, see [06-totp-2fa.md](06-totp-2fa.md).
