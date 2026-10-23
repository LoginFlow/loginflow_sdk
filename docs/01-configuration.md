# 01. Configuration

## Variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `LOGINFLOW_URL` | yes | - | Base URL without version |
| `LOGINFLOW_COMPANY` | yes | - | Company ID (`CP-...`); the only `company_id` an access token may carry |
| `LOGINFLOW_API` | yes | - | Audience of this API; expected `aud` of access tokens. Must not be the issuer |
| `LOGINFLOW_ISSUER` | yes | - | Expected `iss` (`https://api.loginflow.dev`, dev `https://api-dev.loginflow.dev`) |
| `LOGINFLOW_VERSION` | no | `1` | API version |
| `LOGINFLOW_TIMEOUT` | no | `30` | Seconds; applies to every request, JWKS included |
| `LOGINFLOW_USER_AGENT` | no | - | Custom User-Agent |
| `LOGINFLOW_JWKS_URL` | no | `{LOGINFLOW_URL}/oauth2/jwks` | JWKS endpoint |
| `LOGINFLOW_JWKS_CACHE_TTL_SECS` | no | `600` | JWKS cache lifetime |
| `LOGINFLOW_RESOURCE_BASE_URL` | no | derived from the request | Public base URL of this resource server (e.g. `https://api.example.com`); the verifier expects a DPoP proof's `htu` to be this + the request path. Set it behind a reverse proxy |

## Initialization

```rust
use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};

let client = LoginFlowClient::from_env()?;

let client2 = LoginFlowClient::new(LoginFlowConfig {
    base_url: "https://api.loginflow.dev".into(),
    api_version: 1,
    company_id: "CP-<company>".into(),
    api_audience: "https://api.<product>.example".into(),
    timeout_secs: 30,
    user_agent: Some("my-service/1.0".into()),
    issuer: "https://api.loginflow.dev".into(),
    jwks_url: None,
    jwks_cache_ttl_secs: 600,
    resource_base_url: None,
})?;
```

A present but non-numeric `LOGINFLOW_TIMEOUT` or `LOGINFLOW_JWKS_CACHE_TTL_SECS` is a `ConfigError::InvalidValue`. `LoginFlowConfig::from_lookup(|name| ...)` reads the same variables from any source.

`LoginFlowClient::new` (and every service client's `new`) fails with `LoginFlowError::Config` when `issuer`, `api_audience`, `company_id` or `base_url` is empty, or `api_audience` is the issuer.

The machine key of the API (`LOGINFLOW_CLIENT_ID` / `LOGINFLOW_CLIENT_SECRET`) is not part of `LoginFlowConfig`: pass it to the service clients and to the `IntrospectionClient` of the `TokenVerifier`.

## Endpoint URLs

The SDK builds `{base_url}/v{api_version}/{endpoint}`. The JWKS lives outside the versioned API: `{base_url}/oauth2/jwks`.
