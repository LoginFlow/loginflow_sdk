# 08. Refresh y logout

## Métodos SDK
- `refresh_token(RefreshTokenRequest) -> RefreshTokenResponse`
- `logout(access_token: &str, LogoutRequest) -> ()`

## Contrato de sesión (backend actual)
- Toda sesión válida debe existir en `auth_sessions`, estar activa y no expirada.
- Tokens con JTI en blacklist (`auth_token_blacklist`) se rechazan.
- `refresh` valida:
  - `session_id` existente
  - sesión activa/no expirada para refresh
  - hash de `refresh_token` contra la sesión
  - JTI no blacklisteado
- `logout` blacklistea el JWT actual y desactiva sesión(es).

## Refresh

### Request
```rust
RefreshTokenRequest {
    refresh_token: String,
    session_id: String,
}
```

### Response esperada
```rust
RefreshTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_at: String,         // ISO-like string
    refresh_expires_at: String, // ISO-like string
}
```

### Errores esperados
- `401 Authentication`: token inválido, sesión inactiva/expirada, o token revocado.
- `5xx ServerError`: error temporal del servicio.

## Logout

### Request
```rust
LogoutRequest {
    user_id: String,
    session_token: Option<String>,      // recomendado: session_id actual
    logout_all_devices: Option<bool>,   // true para cerrar todas
}
```

### Header requerido
- `Authorization: Bearer <access_token_actual>`

### Ejemplo SDK
```rust
client.logout(
    &access_token,
    LogoutRequest {
        user_id,
        session_token: Some(session_id),
        logout_all_devices: Some(false),
    },
).await?;
```

### Errores esperados
- `401 Authentication`: JWT ausente/expirado/revocado/no asociado a sesión activa.
- `403 Authorization`: token válido pero sin permisos para el recurso.
- `5xx ServerError`: error interno.
