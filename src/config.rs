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
    /// Company UUID from LoginFlow
    pub company_id: String,
    /// Application UUID from LoginFlow. Access tokens are only accepted when
    /// their `aud` claim equals this value.
    pub application_id: String,
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
}

impl LoginFlowConfig {
    /// Create configuration from environment variables
    ///
    /// Supports two naming conventions for the connection settings:
    /// - Standard: `LOGIN_FLOW_URL`, `LOGIN_FLOW_VERSION`, `LOGIN_FLOW_COMPANY`, `LOGIN_FLOW_APPLICATION`
    /// - Short: `LOGIN_URL`, `LOGIN_VERSION`, `COMPANY`, `APPLICATION`
    ///
    /// Token verification settings: `LOGINFLOW_ISSUER` (required),
    /// `LOGINFLOW_JWKS_URL` and `LOGINFLOW_JWKS_CACHE_TTL_SECS` (optional).
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
        let either =
            |primary: &str, alternative: &str| lookup(primary).or_else(|| lookup(alternative));

        let base_url = either("LOGIN_FLOW_URL", "LOGIN_URL")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGIN_FLOW_URL or LOGIN_URL".into()))?;

        let api_version = either("LOGIN_FLOW_VERSION", "LOGIN_VERSION")
            .unwrap_or_else(|| "1".to_string())
            .parse::<i32>()
            .map_err(|_| ConfigError::InvalidValue("API version must be a number".into()))?;

        let company_id = either("LOGIN_FLOW_COMPANY", "COMPANY")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGIN_FLOW_COMPANY or COMPANY".into()))?;

        let application_id = either("LOGIN_FLOW_APPLICATION", "APPLICATION").ok_or_else(|| {
            ConfigError::MissingEnvVar("LOGIN_FLOW_APPLICATION or APPLICATION".into())
        })?;

        let timeout_secs = parse_u64_var(&lookup, "LOGIN_FLOW_TIMEOUT", DEFAULT_TIMEOUT_SECS)?;

        let user_agent = lookup("LOGINFLOW_USER_AGENT");

        let issuer = lookup("LOGINFLOW_ISSUER")
            .ok_or_else(|| ConfigError::MissingEnvVar("LOGINFLOW_ISSUER".into()))?;

        let jwks_url = lookup("LOGINFLOW_JWKS_URL");

        let jwks_cache_ttl_secs = parse_u64_var(
            &lookup,
            "LOGINFLOW_JWKS_CACHE_TTL_SECS",
            DEFAULT_JWKS_CACHE_TTL_SECS,
        )?;

        let config = Self {
            base_url,
            api_version,
            company_id,
            application_id,
            timeout_secs,
            user_agent,
            issuer,
            jwks_url,
            jwks_cache_ttl_secs,
        };
        config.validate()?;
        Ok(config)
    }

    /// Check the settings token verification depends on.
    ///
    /// # Errors
    /// `issuer`, `application_id` and `base_url` must be non-empty.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.issuer.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "issuer (LOGINFLOW_ISSUER)".into(),
            ));
        }
        if self.application_id.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "application_id (LOGIN_FLOW_APPLICATION)".into(),
            ));
        }
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::MissingValue(
                "base_url (LOGIN_FLOW_URL)".into(),
            ));
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
    /// let url = config.build_url("public/login-password");
    /// assert_eq!(url, "https://my-server.com/v1/public/login-password");
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
    /// `issuer` or `application_id` when it is built).
    fn default() -> Self {
        Self {
            base_url: env::var("LOGIN_FLOW_URL")
                .or_else(|_| env::var("LOGIN_URL"))
                .unwrap_or_default(),
            api_version: env::var("LOGIN_FLOW_VERSION")
                .or_else(|_| env::var("LOGIN_VERSION"))
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            company_id: env::var("LOGIN_FLOW_COMPANY")
                .or_else(|_| env::var("COMPANY"))
                .unwrap_or_default(),
            application_id: env::var("LOGIN_FLOW_APPLICATION")
                .or_else(|_| env::var("APPLICATION"))
                .unwrap_or_default(),
            timeout_secs: env::var("LOGIN_FLOW_TIMEOUT")
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
