# 08. Refresh and logout

## SDK methods
- `refresh_token(RefreshTokenRequest) -> RefreshTokenResponse`
- `logout(access_token: &str, LogoutRequest) -> ()`

## Refresh

`POST /v1/public/refresh-token`

```rust
RefreshTokenRequest { refresh_token: String, session_id: String }
```

Use `LoginResponse.refresh_token` and `LoginResponse.session.id`. The refresh token is a separate token (`token_type = "refresh"`), never the access token.

```rust
RefreshTokenResponse {
    access_token: String,
    refresh_token: String,      // rotated: store it, the old one stops working
    expires_at: String,
    refresh_expires_at: String,
}
```

Errors: `401 Authentication` (invalid, revoked or reused refresh token, inactive session), `5xx ServerError`.

## Logout

`POST /v1/user/logout` with `Authorization: Bearer <access_token>`.

```rust
LogoutRequest {
    user_id: String,
    session_token: Option<String>,    // session ID to close (LoginResponse.session.id)
    logout_all_devices: Option<bool>, // Some(true) closes every session of the user
}
```

One of the two targets is required. Without `session_token` and without `logout_all_devices: Some(true)` the SDK returns `LoginFlowError::Validation` without calling the server (the server rejects it as well). The user is always the owner of the access token.

```rust
client.logout(&access_token, LogoutRequest {
    user_id,
    session_token: Some(session_id),
    logout_all_devices: None,
}).await?;
```

Errors: `401 Authentication` (missing, expired or revoked token), `422 Validation` (no target), `5xx ServerError`.
