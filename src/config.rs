//! Configuration for LoginFlow SDK
//!
//! Provides configuration via environment variables or programmatic setup.

use std::env;

use thiserror::Error;

/// Default lifetime of the cached JWKS, in seconds.
pub const DEFAULT_JWKS_CACHE_TTL_SECS: u64 = 600;

/// Default request timeout, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Read an optional numeric variable; present but not a number is an error.
fn parse_u64_var(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: u64,
) -> Result<u64, ConfigError> {
    match lookup(name) {
        Some(value) => value.trim().parse::<u64>().map_err(|_| {
            ConfigError::InvalidValue(format!("{name} must be a non-negative number"))
        }),
        None => Ok(default),
    }
}

/// Configuration for connecting to LoginFlow service
#[derive(Debug, Clone)]
pub struct LoginFlowConfig {
    /// Base URL without version path (e.g., "https://api.loginflow.dev")
    pub base_url: String,
    /// API version number (e.g., 1 for /v1)
    pub api_version: i32,
    /// Company ID from LoginFlow (e.g. `CP-...`)
    pub company_id: String,
    /// Audience of the API this resource server is (`app_apis.audience` in LoginFlow, env
    /// `LOGINFLOW_API`). Access tokens are only accepted when their `aud` claim equals this
    /// value: a token minted for another API of the same application, or LoginFlow's own token
    /// (`aud` = the issuer), is rejected.
    pub api_audience: String,
    /// Request timeout in seconds (default: 30)
    pub timeout_secs: u64,
    /// Optional custom User-Agent header
    pub user_agent: Option<String>,
    /// Expected `iss` claim of every token (e.g. "https://api.loginflow.dev").
    /// Required: tokens from any other issuer are rejected.
    pub issuer: String,
    /// JWKS endpoint. `None` means `{base_url}/oauth2/jwks`.
    pub jwks_url: Option<String>,
    /// How long a fetched JWKS stays fresh, in seconds (default: 600).
    pub jwks_cache_ttl_secs: u64,
    /// Public base URL of the resource server using this SDK (scheme + host, optionally a path
    /// prefix, e.g. `https://api.example.com`). [`crate::TokenVerifier`] builds a DPoP proof's
    /// expected `htu` (RFC 9449 §4.3) as this value followed by the request path. `None` derives
    /// it from the request's connection info (scheme + host), which honours `Forwarded` /
    /// `X-Forwarded-*` headers: set this explicitly behind a reverse proxy.
    pub resource_base_url: Option<String>,
}

impl LoginFlowConfig {
    /// Create configuration from environment variables
    ///
    /// Required: `LOGINFLOW_URL`, `LOGINFLOW_COMPANY`, `LOGINFLOW_API`, `LOGINFLOW_ISSUER`. Optional: `LOGINFLOW_VERSION`, `LOGINFLOW_TIMEOUT`,
    /// `LOGINFLOW_USER_AGENT`, `LOGINFLOW_JWKS_URL`, `LOGINFLOW_JWKS_CACHE_TTL_SECS`,
    /// `LOGINFLOW_RESOURCE_BASE_URL`.
    ///
    /// # Errors
    /// Returns error if required environment variables are not set or invalid
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    /// Same as [`from_env`](Self::from_env), reading each variable through
    /// `lookup` (e.g. a secrets store or a map in tests).
    ///
    /// # Errors
    /// Returns error if required variables are missing or a value is invalid
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let base_url = lookup("LOGINFLOW_URL")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGINFLOW_URL".into()))?;

        let api_version = lookup("LOGINFLOW_VERSION")
            .unwrap_or_else(|| "1".to_string())
            .parse::<i32>()
            .map_err(|_| ConfigError::InvalidValue("API version must be a number".into()))?;

        let company_id = lookup("LOGINFLOW_COMPANY")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGINFLOW_COMPANY".into()))?;

        let api_audience = lookup("LOGINFLOW_API")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGINFLOW_API".into()))?;

        let timeout_secs = parse_u64_var(&lookup, "LOGINFLOW_TIMEOUT", DEFAULT_TIMEOUT_SECS)?;

        let user_agent = lookup("LOGINFLOW_USER_AGENT");

        let issuer = lookup("LOGINFLOW_ISSUER")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGINFLOW_ISSUER".into()))?;

        let jwks_url = lookup("LOGINFLOW_JWKS_URL");

        let jwks_cache_ttl_secs = parse_u64_var(
            &lookup,
            "LOGINFLOW_JWKS_CACHE_TTL_SECS",
            DEFAULT_JWKS_CACHE_TTL_SECS,
        )?;

        let resource_base_url = lookup("LOGINFLOW_RESOURCE_BASE_URL");

        let config = Self {
            base_url,
            api_version,
            company_id,
            api_audience,
            timeout_secs,
            user_agent,
            issuer,
            jwks_url,
            jwks_cache_ttl_secs,
            resource_base_url,
        };
        config.validate()?;
        Ok(config)
    }

    /// Check the settings token verification depends on.
    ///
    /// # Errors
    /// `issuer`, `api_audience`, `company_id` and `base_url` must be non-empty, and
    /// `api_audience` must not be the issuer (that audience names LoginFlow's own token, never
    /// an API's). `company_id` is what every access token's `company_id` is checked against.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "issuer (LOGINFLOW_ISSUER)".into(),
            ));
        }
        if self.api_audience.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "api_audience (LOGINFLOW_API)".into(),
            ));
        }
        if self.api_audience.trim_end_matches('/') == self.issuer.trim_end_matches('/') {
            return Err(ConfigError::InvalidValue(
                "LOGINFLOW_API must be the audience of an API, not the issuer".into(),
            ));
        }
        if self.company_id.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "company_id (LOGINFLOW_COMPANY)".into(),
            ));
        }
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::MissingValue("base_url (LOGINFLOW_URL)".into()));
        }
        Ok(())
    }

    /// Build the versioned API URL for an endpoint
    ///
    /// # Example
    /// ```
    /// use loginflow_sdk::LoginFlowConfig;
    /// let mut config = LoginFlowConfig::default();
    /// config.base_url = "https://my-server.com".into();
    /// config.api_version = 1;
    ///
    /// let url = config.build_url("user/change-password");
    /// assert_eq!(url, "https://my-server.com/v1/user/change-password");
    /// ```
    pub fn build_url(&self, endpoint: &str) -> String {
        format!(
            "{}/v{}/{}",
            self.base_url.trim_end_matches('/'),
            self.api_version,
            endpoint
        )
    }

    /// The JWKS endpoint: `jwks_url` when set, otherwise `{base_url}/oauth2/jwks`.
    pub fn resolved_jwks_url(&self) -> String {
        match &self.jwks_url {
            Some(url) => url.clone(),
            None => format!("{}/oauth2/jwks", self.base_url.trim_end_matches('/')),
        }
    }
}

impl Default for LoginFlowConfig {
    /// Creates default config from environment variables.
    /// Falls back to empty strings if not set (the client rejects an empty
    /// `issuer`, `api_audience` or `company_id` when it is built).
    fn default() -> Self {
        Self {
            base_url: env::var("LOGINFLOW_URL").unwrap_or_default(),
            api_version: env::var("LOGINFLOW_VERSION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            company_id: env::var("LOGINFLOW_COMPANY").unwrap_or_default(),
            api_audience: env::var("LOGINFLOW_API").unwrap_or_default(),
            timeout_secs: env::var("LOGINFLOW_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_TIMEOUT_SECS),
            user_agent: env::var("LOGINFLOW_USER_AGENT").ok(),
            issuer: env::var("LOGINFLOW_ISSUER").unwrap_or_default(),
            jwks_url: env::var("LOGINFLOW_JWKS_URL").ok(),
            jwks_cache_ttl_secs: env::var("LOGINFLOW_JWKS_CACHE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_JWKS_CACHE_TTL_SECS),
            resource_base_url: env::var("LOGINFLOW_RESOURCE_BASE_URL").ok(),
        }
    }
}

/// Configuration errors
#[derive(Debug, Clone, Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Missing configuration value: {0}")]
    MissingValue(String),

    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}
