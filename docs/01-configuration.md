# 01. Configuration

## Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `LOGINFLOW_URL` | yes | - | Base URL without version |
| `LOGINFLOW_COMPANY` | yes | - | Company ID (`CP-...`) |
| `LOGINFLOW_APPLICATION` | yes | - | Application ID (`APP-...`); expected `aud` of access tokens |
| `LOGINFLOW_ISSUER` | yes | - | Expected `iss` (`https://api.loginflow.dev`, dev `https://api-dev.loginflow.dev`) |
| `LOGINFLOW_VERSION` | no | `1` | API version |
| `LOGINFLOW_TIMEOUT` | no | `30` | Seconds; applies to every request, JWKS included |
| `LOGINFLOW_USER_AGENT` | no | - | Custom User-Agent |
| `LOGINFLOW_JWKS_URL` | no | `{LOGINFLOW_URL}/oauth2/jwks` | JWKS endpoint |
| `LOGINFLOW_JWKS_CACHE_TTL_SECS` | no | `600` | JWKS cache lifetime |
| `LOGINFLOW_RESOURCE_BASE_URL` | no | derived from the request | Public base URL of this resource server (e.g. `https://api.example.com`); the Actix extractors expect a DPoP proof's `htu` to be this + the request path. Set it behind a reverse proxy |

## Initialization

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};

let client = LoginFlowClient::from_env()?;

let client2 = LoginFlowClient::new(LoginFlowConfig {
    base_url: "https://api.loginflow.dev".into(),
    api_version: 1,
    company_id: "CP-<company>".into(),
    application_id: "APP-<application>".into(),
    timeout_secs: 30,
    user_agent: Some("my-service/1.0".into()),
    issuer: "https://api.loginflow.dev".into(),
    jwks_url: None,
    jwks_cache_ttl_secs: 600,
    resource_base_url: None,
})?;
```

A present but non-numeric `LOGINFLOW_TIMEOUT` or `LOGINFLOW_JWKS_CACHE_TTL_SECS` is a `ConfigError::InvalidValue`. `LoginFlowConfig::from_lookup(|name| ...)` reads the same variables from any source.

`LoginFlowClient::new` fails with `LoginFlowError::Config` when `issuer`, `application_id` or `base_url` is empty.

## Endpoint URLs

The SDK builds `{base_url}/v{api_version}/{endpoint}`. The JWKS lives outside the versioned API: `{base_url}/oauth2/jwks`.
