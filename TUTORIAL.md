# Tutorial: Cómo usar LoginFlow SDK

Guía paso a paso para integrar autenticación en tu proyecto Rust con Actix-web.

---

## Paso 1: Agregar la dependencia

Abre el archivo `Cargo.toml` de tu proyecto y agrega:

```toml
[dependencies]
# Usando tag específico (recomendado para producción)
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk", tag = "v0.1.0" }

# O usando la rama main (última versión)
loginflow_sdk = { git = "https://github.com/JhonaCodes/loginflow_sdk" }
```

---

## Paso 2: Configurar variables de entorno

Crea o edita tu archivo `.env` con estas variables:

```env
# REQUERIDAS - Sin estas el SDK no funcionará
LOGINFLOW_URL=https://your-loginflow-server.com
LOGINFLOW_COMPANY=tu-company-uuid-aqui
LOGINFLOW_APPLICATION=tu-application-uuid-aqui

# OPCIONALES
LOGINFLOW_VERSION=1
LOGINFLOW_TIMEOUT=30
```

### Ejemplo para DESARROLLO vs PRODUCCIÓN

**.env.development:**
```env
LOGINFLOW_URL=https://your-loginflow-dev-server.com
LOGINFLOW_COMPANY=uuid-de-tu-company-dev
LOGINFLOW_APPLICATION=uuid-de-tu-app-dev
```

**.env.production:**
```env
LOGINFLOW_URL=https://your-loginflow-server.com
LOGINFLOW_COMPANY=uuid-de-tu-company-prod
LOGINFLOW_APPLICATION=uuid-de-tu-app-prod
```

**Nota:** También puedes usar los nombres alternativos:
- `LOGIN_URL` en lugar de `LOGINFLOW_URL`
- `COMPANY` en lugar de `LOGINFLOW_COMPANY`
- `APPLICATION` en lugar de `LOGINFLOW_APPLICATION`

---

## Paso 3: Crear el cliente

En tu archivo `main.rs`:

```rust
use loginflow_sdk::LoginFlowClient;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Cargar variables de entorno (si usas dotenv)
    dotenv::dotenv().ok();

    // Crear el cliente de LoginFlow
    let client = LoginFlowClient::from_env()
        .expect("Error: Verifica tus variables de entorno LOGINFLOW_*");

    println!("✅ Cliente LoginFlow creado correctamente");

    // ... resto de tu código
    Ok(())
}
```

---

## Paso 4: Crear endpoint de Login

```rust
use actix_web::{web, HttpResponse, post};
use loginflow_sdk::{LoginFlowClient, LoginRequest};

#[post("/api/login")]
async fn login(
    client: web::Data<LoginFlowClient>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    match client.login(body.into_inner()).await {
        Ok(response) => {
            // response.jwt contiene el token JWT
            // response.user contiene info del usuario
            HttpResponse::Ok().json(serde_json::json!({
                "token": response.jwt,
                "user": {
                    "id": response.user.id,
                    "email": response.user.email,
                    "first_name": response.user.first_name,
                    "last_name": response.user.last_name
                }
            }))
        }
        Err(e) => {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}
```

---

## Paso 5: Crear endpoint de Registro

```rust
use loginflow_sdk::RegisterRequest;

#[post("/api/register")]
async fn register(
    client: web::Data<LoginFlowClient>,
    body: web::Json<RegisterRequest>,
) -> HttpResponse {
    match client.register(body.into_inner()).await {
        Ok(response) => {
            HttpResponse::Created().json(serde_json::json!({
                "message": response.message,
                "user_id": response.user_id
            }))
        }
        Err(e) => {
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}
```

---

## Paso 6: Proteger endpoints con AuthMiddleware

Este es el paso más importante. Usa `AuthMiddleware` para proteger rutas:

```rust
use loginflow_sdk::actix::AuthMiddleware;

// Este endpoint REQUIERE autenticación
#[post("/api/mi-perfil")]
async fn mi_perfil(auth: AuthMiddleware) -> HttpResponse {
    // auth ya contiene el usuario autenticado
    // Si el token es inválido, Actix retorna 401 automáticamente

    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role(),
        "company_id": auth.company_id().to_string()
    }))
}
```

**¿Cómo funciona?**
1. El cliente envía: `Authorization: Bearer <token-jwt>`
2. `AuthMiddleware` extrae y decodifica el token
3. Si es válido, tu función recibe el usuario autenticado
4. Si es inválido, retorna `401 Unauthorized` automáticamente

---

## Paso 7: Configurar el servidor completo

Aquí está el `main.rs` completo:

```rust
use actix_web::{web, App, HttpServer, HttpResponse, post, get};
use loginflow_sdk::{LoginFlowClient, LoginRequest, RegisterRequest};
use loginflow_sdk::actix::AuthMiddleware;

// ============================================
// ENDPOINTS PÚBLICOS (sin autenticación)
// ============================================

#[post("/api/login")]
async fn login(
    client: web::Data<LoginFlowClient>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    match client.login(body.into_inner()).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({
            "token": res.jwt,
            "user": {
                "id": res.user.id,
                "email": res.user.email
            }
        })),
        Err(e) => HttpResponse::Unauthorized().body(e.to_string()),
    }
}

#[post("/api/register")]
async fn register(
    client: web::Data<LoginFlowClient>,
    body: web::Json<RegisterRequest>,
) -> HttpResponse {
    match client.register(body.into_inner()).await {
        Ok(res) => HttpResponse::Created().json(serde_json::json!({
            "user_id": res.user_id,
            "message": res.message
        })),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}

// ============================================
// ENDPOINTS PROTEGIDOS (requieren token)
// ============================================

#[get("/api/me")]
async fn get_me(auth: AuthMiddleware) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": auth.user_id().to_string(),
        "email": auth.email(),
        "role": auth.role()
    }))
}

#[post("/api/crear-recurso")]
async fn crear_recurso(auth: AuthMiddleware) -> HttpResponse {
    // Aquí puedes usar auth.user_id() para asociar el recurso al usuario
    let user_id = auth.user_id();

    HttpResponse::Created().json(serde_json::json!({
        "mensaje": "Recurso creado",
        "creado_por": user_id.to_string()
    }))
}

// ============================================
// MAIN
// ============================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. Cargar .env
    dotenv::dotenv().ok();

    // 2. Inicializar logs
    env_logger::init();

    // 3. Crear cliente LoginFlow
    let client = LoginFlowClient::from_env()
        .expect("Error creando cliente LoginFlow");

    println!("🚀 Servidor iniciando en http://localhost:8080");

    // 4. Iniciar servidor
    HttpServer::new(move || {
        App::new()
            // Compartir el cliente con todos los handlers
            .app_data(web::Data::new(client.clone()))
            // Rutas públicas
            .service(login)
            .service(register)
            // Rutas protegidas
            .service(get_me)
            .service(crear_recurso)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

---

## Paso 8: Probar con curl

### Registrar usuario:
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@ejemplo.com",
    "first_name": "Juan",
    "last_name": "Pérez",
    "password": "miPassword123"
  }'
```

### Login:
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "usuario@ejemplo.com",
    "password": "miPassword123"
  }'
```

Respuesta:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "uuid-del-usuario",
    "email": "usuario@ejemplo.com"
  }
}
```

### Acceder a ruta protegida:
```bash
# Guarda el token de la respuesta anterior
TOKEN="eyJhbGciOiJIUzI1NiIs..."

curl -X GET http://localhost:8080/api/me \
  -H "Authorization: Bearer $TOKEN"
```

### Sin token (error):
```bash
curl -X GET http://localhost:8080/api/me
# Respuesta: 401 Unauthorized
```

---

## Paso 9: Reset de contraseña (3 pasos)

### Paso 9.1: Solicitar código de reset
```rust
#[post("/api/forgot-password")]
async fn forgot_password(
    client: web::Data<LoginFlowClient>,
    body: web::Json<serde_json::Value>,
) -> HttpResponse {
    let email = body["email"].as_str().unwrap_or("");

    match client.request_password_reset(email).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Si el email existe, recibirás un código"
        })),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}
```

### Paso 9.2: Completar reset con código
```rust
use loginflow_sdk::CompleteResetRequest;

#[post("/api/reset-password")]
async fn reset_password(
    client: web::Data<LoginFlowClient>,
    body: web::Json<CompleteResetRequest>,
) -> HttpResponse {
    match client.complete_password_reset(body.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Contraseña cambiada correctamente"
        })),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}
```

**Request body:**
```json
{
  "email": "usuario@ejemplo.com",
  "code": "123456",
  "new_password": "nuevaPassword123",
  "confirm_password": "nuevaPassword123"
}
```

---

## Paso 10: Cambiar contraseña (usuario autenticado)

```rust
use loginflow_sdk::ChangePasswordRequest;

#[post("/api/change-password")]
async fn change_password(
    auth: AuthMiddleware,
    client: web::Data<LoginFlowClient>,
    body: web::Json<ChangePasswordRequest>,
) -> HttpResponse {
    match client.change_password(
        auth.token(),
        &auth.user_id().to_string(),
        &auth.company_id().to_string(),
        body.into_inner(),
    ).await {
        Ok(res) => HttpResponse::Ok().json(res),
        Err(e) => HttpResponse::BadRequest().body(e.to_string()),
    }
}
```

**Request body:**
```json
{
  "current_password": "passwordActual",
  "new_password": "nuevoPassword123",
  "confirm_password": "nuevoPassword123"
}
```

---

## Resumen de imports

```rust
// Cliente y configuración
use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};

// Modelos de request
use loginflow_sdk::{
    LoginRequest,           // Para login
    RegisterRequest,        // Para registro
    CompleteResetRequest,   // Para reset de password
    ChangePasswordRequest,  // Para cambiar password
    LogoutRequest,          // Para logout
};

// Middleware de autenticación
use loginflow_sdk::actix::AuthMiddleware;

// (Opcional) Para autenticación opcional
use loginflow_sdk::actix::OptionalAuth;
```

---

## Checklist final

- [ ] Agregaste `loginflow_sdk` a `Cargo.toml`
- [ ] Configuraste las variables de entorno en `.env`
- [ ] Creaste el cliente con `LoginFlowClient::from_env()`
- [ ] Compartiste el cliente con `.app_data(web::Data::new(client.clone()))`
- [ ] Usaste `AuthMiddleware` en los endpoints protegidos
- [ ] Probaste con curl que funciona

---

## Errores comunes

| Error | Solución |
|-------|----------|
| `Missing environment variable: LOGINFLOW_URL` | Verifica que `.env` tiene `LOGINFLOW_URL` |
| `401 Unauthorized` | El token es inválido o expiró |
| `Missing Authorization header` | Agrega `Authorization: Bearer <token>` |
| `Invalid Authorization header format` | Debe ser `Bearer <token>`, no solo `<token>` |

---

¡Listo! Ahora tienes autenticación funcionando en tu proyecto. 🎉
