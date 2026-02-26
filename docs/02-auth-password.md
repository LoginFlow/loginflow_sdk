# 02. Auth con password

## Métodos SDK
- `register(RegisterRequest) -> RegisterResponse`
- `login(LoginRequest) -> LoginResult`

## Register
Request:
```rust
RegisterRequest { email, first_name, last_name, password, phone }
```
Response:
```rust
RegisterResponse { user_id, email, message }
```

## Login
Request:
```rust
LoginRequest { email, password }
```
Response:
- `LoginResult::Success(Box<LoginResponse>)`
- `LoginResult::TotpRequired(TotpChallengeResponse)`

`LoginResponse` incluye: `jwt`, `expires_in`, `user`, `company`, `session`, `application`.

## Nota de compatibilidad
- `register()` usa endpoint `public/users` (desalineado con backend actual `public/user-accounts`).
