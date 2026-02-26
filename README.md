# LoginFlow SDK

SDK en Rust para integrar con el servicio de autenticacion LoginFlow. Provee una API completa, type-safe y async para todos los flujos de autenticacion.

## Funcionalidades

| Funcionalidad | Descripcion | Obligatorio |
|---|---|---|
| **Registro** | Crear cuenta con email + password | Base |
| **Login con password** | Email + password, retorna JWT | Base |
| **Login con OAuth** | Google o Microsoft con un click (ID token) | Opcional |
| **Login con OTP** | Codigo de 6 digitos enviado por email (passwordless) | Opcional |
| **TOTP 2FA** | Autenticacion de dos factores con app (Google Authenticator) | Opcional |
| **Refresh Token** | Renovar JWT sin re-login | Base |
| **Logout** | Invalidar sesion | Base |
| **Verificacion de Email** | Verificar email con codigo | Base |
| **Password Reset** | Flujo de 3 pasos para recuperar password | Base |
| **Cambio de Password** | Con password actual (autenticado) | Base |
| **JWT local** | Verificar JWT sin llamar al servidor | Opcional |
| **Gestion de Cuentas** | CRUD de cuentas de usuario | Admin |
| **Gestion de Perfiles** | CRUD de perfiles de usuario | Admin |
| **Actix-web Middleware** | Middleware y extractores listos para usar | Feature flag |
| **Multi-tenant** | `company_id` dinamico por request | Feature flag |

## Instalacion

### Dependencia Git

```toml
[dependencies]
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk", tag = "v0.1.0" }

# O usar branch main para la ultima version
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk" }
```

### Feature Flags

| Feature | Default | Descripcion |
|---------|---------|-------------|
| `actix` | Si | Middleware y extractores para Actix-web |
| `multi-tenant` | No | Soporte multi-tenant con `company_id` dinamico |

```toml
# Con todo (Actix + Multi-tenant)
loginflow_sdk = { git = "...", features = ["multi-tenant"] }

# Sin Actix (solo el client HTTP)
loginflow_sdk = { git = "...", default-features = false }

# Solo multi-tenant, sin Actix
loginflow_sdk = { git = "...", default-features = false, features = ["multi-tenant"] }
```

## Variables de Entorno

### Obligatorias

| Variable | Alternativa | Descripcion |
|----------|-------------|-------------|
| `LOGINFLOW_URL` | `LOGIN_URL` | URL base del servidor LoginFlow (ej: `https://auth.tuapp.com`) |
| `LOGINFLOW_COMPANY` | `COMPANY` | UUID de la empresa en LoginFlow |
| `LOGINFLOW_APPLICATION` | `APPLICATION` | UUID de la aplicacion en LoginFlow |

### Opcionales

| Variable | Default | Descripcion |
|----------|---------|-------------|
| `LOGINFLOW_VERSION` | `1` | Numero de version de la API |
| `LOGINFLOW_TIMEOUT` | `30` | Timeout de requests en segundos |
| `LOGINFLOW_USER_AGENT` | - | Header User-Agent personalizado |
| `LOGINFLOW_SIGNING_SECRET` | - | Secret per-app para verificar JWT localmente sin llamar al servidor. Se obtiene al crear la aplicacion en LoginFlow (API key con scope `jwt:signing`) |

### Ejemplo `.env`

```env
# Obligatorias
LOGINFLOW_URL=https://auth.tuapp.com
LOGINFLOW_COMPANY=550e8400-e29b-41d4-a716-446655440000
LOGINFLOW_APPLICATION=6ba7b810-9dad-11d1-80b4-00c04fd430c8

# Opcionales
LOGINFLOW_VERSION=1
LOGINFLOW_TIMEOUT=30
LOGINFLOW_SIGNING_SECRET=tu-secret-per-app
```

## Quick Start

### 1. Crear el Client

```rust
use loginflow_sdk::LoginFlowClient;

// Desde variables de entorno (recomendado)
let client = LoginFlowClient::from_env()?;

// O con configuracion explicita
use loginflow_sdk::LoginFlowConfig;

let client = LoginFlowClient::new(LoginFlowConfig {
    base_url: "https://auth.tuapp.com".into(),
    api_version: 1,
    company_id: "tu-company-uuid".into(),
    application_id: "tu-app-uuid".into(),
    timeout_secs: 30,
    user_agent: None,
    signing_secret: Some("tu-signing-secret".into()),
})?;
```

### 2. Registro + Login basico

```rust
use loginflow_sdk::{LoginFlowClient, RegisterRequest, LoginRequest, LoginResult};

async fn auth_flow(client: &LoginFlowClient) -> Result<(), Box<dyn std::error::Error>> {
    // Registrar usuario
    let register = client.register(RegisterRequest {
        email: "user@example.com".into(),
        first_name: "Juan".into(),
        last_name: "Perez".into(),
        password: "SecurePass123!".into(),
        phone: Some("+573001234567".into()),
    }).await?;
    println!("User ID: {}", register.user_id);

    // Login
    let result = client.login(LoginRequest {
        email: "user@example.com".into(),
        password: "SecurePass123!".into(),
    }).await?;

    match result {
        LoginResult::Success(response) => {
            println!("JWT: {}", response.jwt);
            println!("User: {} {}", response.user.first_name, response.user.last_name);
            println!("Expires in: {} seconds", response.expires_in);
        }
        LoginResult::TotpRequired(challenge) => {
            println!("2FA requerido! Token temporal: {}", challenge.totp_token);
            // Ver seccion TOTP mas abajo
        }
    }

    Ok(())
}
```

## Flujos de Autenticacion

### Login con Password (obligatorio)

El flujo base. Retorna `LoginResult` que puede ser `Success` o `TotpRequired` si el usuario tiene 2FA habilitado.

```rust
use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult};

let result = client.login(LoginRequest {
    email: "user@example.com".into(),
    password: "password".into(),
}).await?;

match result {
    LoginResult::Success(response) => {
        // response.jwt - JWT para autenticar requests
        // response.user - Datos del usuario
        // response.company - Datos de la empresa
        // response.session - Datos de la sesion
        // response.application - Datos de la app
    }
    LoginResult::TotpRequired(challenge) => {
        // challenge.totp_token - Token temporal (5 min)
        // challenge.expires_in - Segundos restantes
    }
}
```

### Login con OAuth (opcional)

Login con un click usando Google o Microsoft. El frontend maneja el redirect OAuth y obtiene un ID token. El SDK envia ese token a LoginFlow para validacion server-side (JWKS).

**Prerequisito:** El admin debe configurar el provider OAuth via la API master de LoginFlow (`POST /v1/master/oauth-providers`) con el `client_id` de Google/Microsoft.

```rust
use loginflow_sdk::{LoginFlowClient, OAuthLoginRequest, LoginResult};

async fn google_login(client: &LoginFlowClient, google_id_token: &str) {
    let result = client.login_with_oauth(OAuthLoginRequest {
        provider: "google".to_string(),
        id_token: google_id_token.to_string(),
    }).await;

    match result {
        Ok(LoginResult::Success(response)) => {
            println!("JWT: {}", response.jwt);
            // El usuario fue creado automaticamente si no existia
        }
        Ok(LoginResult::TotpRequired(challenge)) => {
            println!("2FA requerido: {}", challenge.totp_token);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

// Microsoft/Outlook funciona igual:
let result = client.login_with_oauth(OAuthLoginRequest {
    provider: "microsoft".to_string(),
    id_token: microsoft_id_token.to_string(),
}).await?;
```

**Flujo completo:**
1. Frontend redirige al usuario a Google/Microsoft
2. Usuario se autentica en el provider
3. Provider retorna un ID token (JWT) al frontend
4. Frontend envia el ID token al SDK: `client.login_with_oauth(...)`
5. LoginFlow valida la firma del token (JWKS RS256), audience, issuer, expiracion
6. Si el usuario no existe, se crea automaticamente (auto-registro)
7. Si el usuario ya existe (mismo email), se vincula la identidad OAuth
8. Retorna `LoginResult::Success` con JWT, o `TotpRequired` si tiene 2FA

### Login con OTP (opcional)

Login sin password, usando un codigo de 6 digitos enviado por email.

```rust
use loginflow_sdk::{LoginFlowClient, RequestOtpRequest, OtpLoginRequest};

// Paso 1: Solicitar codigo OTP
let otp_response = client.request_otp_login(RequestOtpRequest {
    email: "user@example.com".into(),
    metadata: None,
}).await?;
println!("Codigo enviado a: {}", otp_response.email_sent_to);

// Paso 2: Login con el codigo recibido por email
let login = client.login_with_otp(OtpLoginRequest {
    email: "user@example.com".into(),
    code: "123456".into(),
}).await?;
println!("JWT: {}", login.jwt);
```

### TOTP 2FA (opcional)

Autenticacion de dos factores con apps como Google Authenticator, Authy, etc.

#### Activar TOTP

```rust
use loginflow_sdk::{LoginFlowClient, TotpSetupResponse};

// 1. Iniciar setup (requiere JWT valido)
let setup: TotpSetupResponse = client.setup_totp(jwt_token).await?;
// setup.otp_auth_uri -> Mostrar como QR code
// setup.secret -> Secret base32 (para entrada manual)
// setup.issuer -> Nombre de la app en el authenticator

// 2. Verificar con codigo del authenticator (activa TOTP)
let status = client.verify_totp_setup(jwt_token, "123456").await?;
assert!(status.enabled);

// 3. Consultar estado
let status = client.get_totp_status(jwt_token).await?;
println!("TOTP habilitado: {}", status.enabled);

// 4. Desactivar (requiere codigo actual)
client.disable_totp(jwt_token, "123456").await?;
```

#### Login con TOTP habilitado

Cuando un usuario tiene TOTP activo, `login()` y `login_with_oauth()` retornan `TotpRequired`:

```rust
use loginflow_sdk::{LoginFlowClient, LoginRequest, LoginResult, VerifyTotpLoginRequest};

let result = client.login(LoginRequest {
    email: "user@example.com".into(),
    password: "password".into(),
}).await?;

if let LoginResult::TotpRequired(challenge) = result {
    // El usuario ingresa el codigo de su authenticator
    let login = client.verify_totp_login(VerifyTotpLoginRequest {
        totp_token: challenge.totp_token,
        code: "123456".into(), // Codigo del authenticator
    }).await?;

    println!("JWT: {}", login.jwt);
}
```

## Refresh Token

Renovar el JWT sin que el usuario tenga que re-autenticarse.

```rust
use loginflow_sdk::{LoginFlowClient, RefreshTokenRequest};

let new_tokens = client.refresh_token(RefreshTokenRequest {
    refresh_token: "current-refresh-token".into(),
    session_id: "session-uuid".into(),
}).await?;

println!("Nuevo JWT: {}", new_tokens.access_token);
```

## Verificacion de Email

```rust
use loginflow_sdk::{LoginFlowClient, VerifyEmailRequest, ResendVerificationRequest};

// Verificar con codigo
let verified = client.verify_email(VerifyEmailRequest {
    verification_code: "123456".into(),
    user_id: "user-uuid".into(),
}).await?;

// Reenviar codigo
client.resend_verification(ResendVerificationRequest {
    user_id: "user-uuid".into(),
    email: "user@example.com".into(),
}).await?;
```

## Password Reset (3 pasos)

### Opcion A: Flujo simple con codigo

```rust
use loginflow_sdk::{LoginFlowClient, CompleteResetRequest};

// Paso 1: Solicitar reset (envia codigo por email)
client.request_password_reset("user@example.com").await?;

// Pasos 2 & 3: Verificar codigo y cambiar password
// (El SDK internamente verifica el codigo para obtener el reset_token)
client.complete_password_reset(CompleteResetRequest {
    email: "user@example.com".into(),
    code: "123456".into(),
    new_password: "NewSecurePass123!".into(),
    confirm_password: "NewSecurePass123!".into(),
}).await?;
```

### Opcion B: Flujo con temporary token (recomendado)

Cuando la UI verifica el codigo primero y navega a otra pantalla:

```rust
use loginflow_sdk::{LoginFlowClient, VerifyResetCodeRequest};

// Paso 1: Solicitar reset
client.request_password_reset("user@example.com").await?;

// Paso 2: Verificar codigo -> obtener reset_token
let verify = client.verify_reset_code(VerifyResetCodeRequest {
    email: "user@example.com".into(),
    code: "123456".into(),
}).await?;
// verify.reset_token -> Guardar para paso 3

// Paso 3: Completar con el reset_token (en otra pantalla)
// Usar multi-tenant: complete_password_reset_with_token_with_company()
```

## Cambio de Password (autenticado)

```rust
use loginflow_sdk::{LoginFlowClient, ChangePasswordRequest};

client.change_password(
    jwt_token,
    "user-uuid",
    "company-uuid",
    ChangePasswordRequest {
        current_password: "OldPass123!".into(),
        new_password: "NewPass456!".into(),
        confirm_password: "NewPass456!".into(),
    },
).await?;
```

## JWT - Verificacion Local

Verificar tokens sin hacer requests al servidor (requiere `LOGINFLOW_SIGNING_SECRET`).

```rust
use loginflow_sdk::{LoginFlowClient, decode_jwt_claims};

// Con signing_secret configurado: verifica firma + expiracion
if client.can_verify_locally() {
    let claims = client.verify_token("eyJ...")?;
    println!("User ID: {}", claims.user_id);
    println!("Expirado: {}", claims.is_expired());
}

// Extraer usuario autenticado del JWT
let user = client.extract_user_from_token("eyJ...")?;
println!("User ID: {}", user.user_id);
println!("Email: {}", user.email);
println!("Role: {}", user.role);

// Decodificar claims sin verificar firma (sin signing_secret)
let claims = decode_jwt_claims("eyJ...")?;
```

## Gestion de Cuentas de Usuario

Operaciones admin sobre cuentas (requieren JWT con permisos master).

```rust
use loginflow_sdk::{LoginFlowClient, UpdateUserAccountRequest};

// Obtener cuenta
let account = client.get_account(token, "account-uuid").await?;

// Actualizar cuenta
let updated = client.update_account(token, "account-uuid", UpdateUserAccountRequest {
    role: Some("admin".into()),
    auth_type: None,
    is_active: Some(true),
}).await?;

// Soft-delete / Restore / Hard-delete
client.soft_delete_account(token, "account-uuid").await?;
client.restore_account(token, "account-uuid").await?;
client.hard_delete_account(token, "account-uuid").await?;
```

## Gestion de Perfiles

```rust
use loginflow_sdk::{LoginFlowClient, UpdateUserProfileRequest};

// Obtener perfil
let profile = client.get_profile(token, "profile-uuid").await?;

// Buscar por email
let profile = client.search_profile_by_email(token, "user@example.com").await?;

// Actualizar perfil
let updated = client.update_profile(token, "profile-uuid", UpdateUserProfileRequest {
    email: None,
    first_name: Some("Juan Carlos".into()),
    last_name: None,
}).await?;

// Eliminar perfil (permanente)
client.delete_profile(token, "profile-uuid").await?;
```

## Integracion Actix-web

El SDK provee middleware y extractores listos para proteger endpoints.

```rust
use actix_web::{web, App, HttpServer, HttpResponse, post, get};
use loginflow_sdk::LoginFlowClient;
use loginflow_sdk::actix::{AuthMiddleware, OptionalAuth};

// Endpoint protegido - requiere autenticacion
#[post("/protected")]
async fn protected_endpoint(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role()
    }))
}

// Autenticacion opcional - funciona con o sin token
#[get("/profile")]
async fn profile_endpoint(auth: OptionalAuth) -> HttpResponse {
    if let Some(user) = auth.user() {
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": true,
            "user_id": user.user_id.to_string()
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({ "authenticated": false }))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let client = LoginFlowClient::from_env().expect("LoginFlow config");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .service(protected_endpoint)
            .service(profile_endpoint)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### AuthMiddleware API

```rust
auth.user_id()        // -> Uuid
auth.email()          // -> &str
auth.role()           // -> &str
auth.company_id()     // -> Uuid
auth.application_id() // -> Uuid
auth.user()           // -> &AuthenticatedUser
auth.token()          // -> &str (JWT raw para forwarding)
auth.is_admin()       // -> bool
auth.is_master()      // -> bool
```

## Multi-tenant

Para aplicaciones donde el `company_id` varia por request en vez de ser fijo.

```toml
loginflow_sdk = { git = "...", features = ["multi-tenant"] }
```

```rust
use loginflow_sdk::{LoginFlowClient, LoginResult};
use loginflow_sdk::multi_tenant::{
    MultiTenantLoginRequest, MultiTenantOAuthLoginRequest, MultiTenantExt,
};

async fn multi_tenant_examples(client: &LoginFlowClient) {
    // Login con password + company dinamico
    let result = client.login_with_company(MultiTenantLoginRequest {
        email: "user@company-a.com".into(),
        password: "password".into(),
        company_id: "company-a-uuid".into(),
    }).await;

    // Login con OAuth + company dinamico
    let result = client.login_with_oauth_with_company(MultiTenantOAuthLoginRequest {
        provider: "google".into(),
        id_token: "google-id-token".into(),
        company_id: "company-b-uuid".into(),
    }).await;
}
```

Metodos multi-tenant disponibles:
- `login_with_company()` - Login con password
- `login_with_oauth_with_company()` - Login con OAuth
- `register_with_company()` - Registro
- `verify_email_with_company()` - Verificar email
- `request_password_reset_with_company()` - Solicitar reset
- `verify_reset_code_with_company()` - Verificar codigo reset
- `complete_password_reset_with_company()` - Completar reset
- `complete_password_reset_with_token_with_company()` - Completar con token temporal

## Manejo de Errores

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowError, LoginRequest};

async fn handle_errors(client: &LoginFlowClient) {
    match client.login(LoginRequest { .. }).await {
        Ok(result) => { /* manejar LoginResult */ }
        Err(LoginFlowError::Authentication(msg)) => {
            // Credenciales invalidas, cuenta bloqueada, token expirado
            println!("Auth error: {}", msg);
        }
        Err(LoginFlowError::Validation(msg)) => {
            // Input invalido (email mal formado, password debil, etc.)
            println!("Validation error: {}", msg);
        }
        Err(LoginFlowError::Network(msg)) => {
            // Error de red (timeout, servidor no disponible)
            println!("Network error: {}", msg);
        }
        Err(LoginFlowError::NotFound(msg)) => {
            // Recurso no encontrado
            println!("Not found: {}", msg);
        }
        Err(LoginFlowError::RateLimited(msg)) => {
            // Demasiados intentos
            println!("Rate limited: {}", msg);
        }
        Err(e) => println!("Other: {}", e),
    }
}
```

## Referencia Completa de Metodos

### Autenticacion (publicos, sin JWT)

| Metodo | Descripcion | Retorno |
|--------|-------------|---------|
| `register(req)` | Registrar usuario | `RegisterResponse` |
| `login(req)` | Login con email + password | `LoginResult` |
| `login_with_oauth(req)` | Login con Google/Microsoft | `LoginResult` |
| `request_otp_login(req)` | Solicitar codigo OTP por email | `RequestOtpResponse` |
| `login_with_otp(req)` | Login con codigo OTP | `OtpLoginResponse` |
| `verify_totp_login(req)` | Completar login con TOTP 2FA | `LoginResponse` |
| `refresh_token(req)` | Renovar JWT | `RefreshTokenResponse` |
| `verify_email(req)` | Verificar email con codigo | `bool` |
| `resend_verification(req)` | Reenviar codigo de verificacion | `bool` |
| `request_password_reset(email)` | Solicitar reset de password | `()` |
| `verify_reset_code(req)` | Verificar codigo de reset | `VerifyResetCodeResponse` |
| `complete_password_reset(req)` | Completar reset de password | `()` |

### Autenticados (requieren JWT)

| Metodo | Descripcion | Retorno |
|--------|-------------|---------|
| `logout(req)` | Cerrar sesion | `()` |
| `change_password(token, uid, cid, req)` | Cambiar password | `ChangePasswordResponse` |
| `setup_totp(token)` | Iniciar setup TOTP | `TotpSetupResponse` |
| `verify_totp_setup(token, code)` | Verificar setup TOTP | `TotpStatusResponse` |
| `get_totp_status(token)` | Estado del TOTP | `TotpStatusResponse` |
| `disable_totp(token, code)` | Desactivar TOTP | `()` |
| `get_account(token, id)` | Obtener cuenta | `FullUserAccountResponse` |
| `update_account(token, id, req)` | Actualizar cuenta | `UserAccountResponse` |
| `soft_delete_account(token, id)` | Soft-delete cuenta | `OperationResponse` |
| `restore_account(token, id)` | Restaurar cuenta | `OperationResponse` |
| `hard_delete_account(token, id)` | Eliminar permanente | `OperationResponse` |
| `get_profile(token, id)` | Obtener perfil | `UserProfileResponse` |
| `search_profile_by_email(token, email)` | Buscar perfil | `UserProfileResponse` |
| `update_profile(token, id, req)` | Actualizar perfil | `UserProfileResponse` |
| `delete_profile(token, id)` | Eliminar perfil | `OperationResponse` |

### Utilidades (sin request HTTP)

| Metodo | Descripcion | Retorno |
|--------|-------------|---------|
| `verify_token(token)` | Verificar JWT local (requiere signing_secret) | `JwtClaims` |
| `can_verify_locally()` | Tiene signing_secret configurado? | `bool` |
| `extract_user_from_token(token)` | Extraer usuario del JWT | `AuthenticatedUser` |

## License

MIT
