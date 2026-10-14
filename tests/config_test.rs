//! Configuration loading: required values and strict numeric parsing.

use std::collections::HashMap;

use loginflow_sdk::config::{DEFAULT_JWKS_CACHE_TTL_SECS, DEFAULT_TIMEOUT_SECS};
use loginflow_sdk::{ConfigError, LoginFlowConfig};

fn vars(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = [
        ("LOGIN_FLOW_URL", "https://api.loginflow.test"),
        ("LOGIN_FLOW_COMPANY", "company-1"),
        ("LOGIN_FLOW_APPLICATION", "app-1"),
        ("LOGINFLOW_ISSUER", "https://api.loginflow.test"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        map.insert(k.to_string(), v.to_string());
    }
    map
}

fn load(map: &HashMap<String, String>) -> Result<LoginFlowConfig, ConfigError> {
    LoginFlowConfig::from_lookup(|name| map.get(name).cloned())
}

#[test]
fn defaults_apply_when_optional_values_are_absent() {
    let config = load(&vars(&[])).expect("config");
    assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
    assert_eq!(config.jwks_cache_ttl_secs, DEFAULT_JWKS_CACHE_TTL_SECS);
    assert_eq!(
        config.resolved_jwks_url(),
        "https://api.loginflow.test/oauth2/jwks"
    );
    assert_eq!(
        config.build_url("public/login-password"),
        "https://api.loginflow.test/v1/public/login-password"
    );
}

#[test]
fn invalid_timeout_is_a_configuration_error() {
    let result = load(&vars(&[("LOGIN_FLOW_TIMEOUT", "thirty")]));
    assert!(
        matches!(&result, Err(ConfigError::InvalidValue(msg)) if msg.contains("LOGIN_FLOW_TIMEOUT")),
        "{result:?}"
    );
}

#[test]
fn invalid_jwks_ttl_is_a_configuration_error() {
    let result = load(&vars(&[("LOGINFLOW_JWKS_CACHE_TTL_SECS", "-5")]));
    assert!(
        matches!(&result, Err(ConfigError::InvalidValue(_))),
        "{result:?}"
    );
}

#[test]
fn missing_issuer_is_a_configuration_error() {
    let mut map = vars(&[]);
    map.remove("LOGINFLOW_ISSUER");
    assert!(matches!(load(&map), Err(ConfigError::MissingEnvVar(_))));
}

#[test]
fn explicit_timeout_is_used() {
    assert_eq!(
        load(&vars(&[("LOGIN_FLOW_TIMEOUT", "5")]))
            .expect("config")
            .timeout_secs,
        5
    );
}
