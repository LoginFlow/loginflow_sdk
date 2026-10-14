# 02. Password authentication

## SDK methods
- `register(RegisterRequest) -> RegisterResponse`
- `login(LoginRequest) -> LoginResult`

## Register

`POST /v1/public/user-accounts`

```rust
RegisterRequest { email, first_name, last_name, password }
```

The SDK adds `company_id`, `application_id` and `auth_type: "password"`. Public registration never carries a role: the account is always a `user`. Roles are assigned only through the master API.

Response (the server's `data`):

```rust
RegisterResponse { user_id, company_id, application_id }
```

A verification code is emailed to the user.

## Login

`POST /v1/public/login-password`

```rust
LoginRequest { email, password }
```

Response:
- `LoginResult::Success(Box<LoginResponse>)`
- `LoginResult::TotpRequired(TotpChallengeResponse)`: see [06-totp-2fa.md](06-totp-2fa.md)

`LoginResponse` contains `jwt` (access token), `refresh_token` (always present), `expires_in`, `user`, `company`, `session`, `application`.
