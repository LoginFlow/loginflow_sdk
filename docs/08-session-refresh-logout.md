# 08. Refresh y logout

## Métodos SDK
- `refresh_token(RefreshTokenRequest) -> RefreshTokenResponse`
- `logout(LogoutRequest) -> ()`

## Refresh
Request: `RefreshTokenRequest { refresh_token, session_id }`

Response: `RefreshTokenResponse { access_token, refresh_token, expires_at, refresh_expires_at }`

## Logout
Request: `LogoutRequest { user_id, session_token?, logout_all_devices? }`

Endpoint logout: `POST /v1/user/logout`
