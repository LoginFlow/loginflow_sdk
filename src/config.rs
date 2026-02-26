//! Configuration for LoginFlow SDK
//!
//! Provides flexible configuration via environment variables or programmatic setup.

use std::env;

/// Configuration for connecting to LoginFlow service
#[derive(Debug, Clone)]
pub struct LoginFlowConfig {
    /// Base URL without version path (e.g., "https://your-loginflow-server.com")
    pub base_url: String,
    /// API version number (e.g., 1 for /v1)
    pub api_version: i32,
    /// Company UUID from LoginFlow
    pub company_id: String,
    /// Application UUID from LoginFlow
    pub application_id: String,
    /// Request timeout in seconds (default: 30)
    pub timeout_secs: u64,
    /// Optional custom User-Agent header
    pub user_agent: Option<String>,
    /// Per-app signing secret for local JWT signature verification.
    /// Obtained from LoginFlow when creating the application (via API key with jwt:signing scope).
    /// When set, the SDK verifies JWT signatures locally instead of just decoding.
    pub signing_secret: Option<String>,
}

impl LoginFlowConfig {
    /// Create configuration from environment variables
    ///
    /// Supports two naming conventions:
    /// - Standard: `LOGINFLOW_URL`, `LOGINFLOW_VERSION`, `LOGINFLOW_COMPANY`, `LOGINFLOW_APPLICATION`
    /// - Legacy: `LOGIN_URL`, `LOGIN_VERSION`, `COMPANY`, `APPLICATION`
    ///
    /// # Errors
    /// Returns error if required environment variables are not set
    pub fn from_env() -> Result<Self, ConfigError> {
        let base_url = env::var("LOGINFLOW_URL")
            .or_else(|_| env::var("LOGIN_URL"))
            .map_err(|_| ConfigError::MissingEnvVar("LOGINFLOW_URL or LOGIN_URL".into()))?;

        let api_version = env::var("LOGINFLOW_VERSION")
            .or_else(|_| env::var("LOGIN_VERSION"))
            .unwrap_or_else(|_| "1".to_string())
            .parse::<i32>()
            .map_err(|_| ConfigError::InvalidValue("API version must be a number".into()))?;

        let company_id = env::var("LOGINFLOW_COMPANY")
            .or_else(|_| env::var("COMPANY"))
            .map_err(|_| ConfigError::MissingEnvVar("LOGINFLOW_COMPANY or COMPANY".into()))?;

        let application_id = env::var("LOGINFLOW_APPLICATION")
            .or_else(|_| env::var("APPLICATION"))
            .map_err(|_| ConfigError::MissingEnvVar("LOGINFLOW_APPLICATION or APPLICATION".into()))?;

        let timeout_secs = env::var("LOGINFLOW_TIMEOUT")
            .unwrap_or_else(|_| "30".to_string())
            .parse::<u64>()
            .unwrap_or(30);

        let user_agent = env::var("LOGINFLOW_USER_AGENT").ok();

        let signing_secret = env::var("LOGINFLOW_SIGNING_SECRET").ok();

        Ok(Self {
            base_url,
            api_version,
            company_id,
            application_id,
            timeout_secs,
            user_agent,
            signing_secret,
        })
    }

    /// Build the versioned API URL for an endpoint
    ///
    /// # Example
    /// ```
    /// use loginflow_sdk::LoginFlowConfig;
    /// // Config reads from environment, or use explicit values
    /// let mut config = LoginFlowConfig::default();
    /// config.base_url = "https://my-server.com".into();
    /// config.api_version = 1;
    ///
    /// let url = config.build_url("public/login");
    /// assert!(url.contains("/v1/public/login"));
    /// ```
    pub fn build_url(&self, endpoint: &str) -> String {
        format!("{}/v{}/{}", self.base_url, self.api_version, endpoint)
    }
}

impl Default for LoginFlowConfig {
    /// Creates default config from environment variables.
    /// Falls back to empty strings if not set.
    fn default() -> Self {
        Self {
            base_url: std::env::var("LOGINFLOW_URL")
                .or_else(|_| std::env::var("LOGIN_URL"))
                .unwrap_or_default(),
            api_version: std::env::var("LOGINFLOW_VERSION")
                .or_else(|_| std::env::var("LOGIN_VERSION"))
                .unwrap_or_else(|_| "1".to_string())
                .parse()
                .unwrap_or(1),
            company_id: std::env::var("LOGINFLOW_COMPANY")
                .or_else(|_| std::env::var("COMPANY"))
                .unwrap_or_default(),
            application_id: std::env::var("LOGINFLOW_APPLICATION")
                .or_else(|_| std::env::var("APPLICATION"))
                .unwrap_or_default(),
            timeout_secs: std::env::var("LOGINFLOW_TIMEOUT")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            user_agent: std::env::var("LOGINFLOW_USER_AGENT").ok(),
            signing_secret: std::env::var("LOGINFLOW_SIGNING_SECRET").ok(),
        }
    }
}

/// Configuration errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Invalid configuration value: {0}")]
    InvalidValue(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LoginFlowConfig {
        // Usa environment si está disponible, sino valores de test
        let base_url = std::env::var("LOGINFLOW_URL")
            .unwrap_or_else(|_| "https://test-server.example.com".into());

        LoginFlowConfig {
            base_url,
            api_version: 1,
            company_id: std::env::var("LOGINFLOW_COMPANY")
                .unwrap_or_else(|_| "test-company".into()),
            application_id: std::env::var("LOGINFLOW_APPLICATION")
                .unwrap_or_else(|_| "test-app".into()),
            timeout_secs: 30,
            user_agent: None,
            signing_secret: None,
        }
    }

    #[test]
    fn test_build_url() {
        let config = test_config();
        let url = config.build_url("public/login-password");

        // Verifica que la URL se construye correctamente
        assert!(url.contains("/v1/public/login-password"));
        assert!(url.starts_with(&config.base_url));
    }

    #[test]
    fn test_build_url_v2() {
        let mut config = test_config();
        config.api_version = 2;

        let url = config.build_url("public/users");

        assert!(url.contains("/v2/public/users"));
    }

    #[test]
    fn test_from_env() {
        // Solo corre si las variables están configuradas
        if std::env::var("LOGINFLOW_URL").is_ok() {
            let config = LoginFlowConfig::from_env();
            assert!(config.is_ok());
        }
    }
}
