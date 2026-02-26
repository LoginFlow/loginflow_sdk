# 01. Configuración

## Objetivo
Configurar `LoginFlowClient` de forma correcta y reproducible.

## Variables
- `LOGINFLOW_URL` / `LOGIN_URL` (requerida)
- `LOGINFLOW_COMPANY` / `COMPANY` (requerida)
- `LOGINFLOW_APPLICATION` / `APPLICATION` (requerida)
- `LOGINFLOW_VERSION` (opcional, default `1`)
- `LOGINFLOW_TIMEOUT` (opcional, default `30`)
- `LOGINFLOW_USER_AGENT` (opcional)
- `LOGINFLOW_SIGNING_SECRET` (opcional)

## Inicialización
```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};

let client = LoginFlowClient::from_env()?;

let client2 = LoginFlowClient::new(LoginFlowConfig {
    base_url: "https://auth.example.com".into(),
    api_version: 1,
    company_id: "<company_uuid>".into(),
    application_id: "<app_uuid>".into(),
    timeout_secs: 30,
    user_agent: Some("my-service/1.0".into()),
    signing_secret: None,
})?;
```

## URL final de endpoint
El SDK compone: `{base_url}/v{api_version}/{endpoint}`.
