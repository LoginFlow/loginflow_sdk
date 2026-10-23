//! Configuration loading: required values and strict numeric parsing.

use std::collections::HashMap;

use loginflow_sdk::config::{DEFAULT_JWKS_CACHE_TTL_SECS, DEFAULT_TIMEOUT_SECS};
use loginflow_sdk::{ConfigError, LoginFlowConfig};

fn vars(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = [
        ("LOGINFLOW_URL", "https://api.loginflow.test"),
        ("LOGINFLOW_COMPANY", "company-1"),
        ("LOGINFLOW_API", "https://drivers.api.test"),
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
    let result = load(&vars(&[("LOGINFLOW_TIMEOUT", "thirty")]));
    assert!(
        matches!(&result, Err(ConfigError::InvalidValue(msg)) if msg.contains("LOGINFLOW_TIMEOUT")),
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
        load(&vars(&[("LOGINFLOW_TIMEOUT", "5")]))
            .expect("config")
            .timeout_secs,
        5
    );
}

/// The API's audience is `LOGINFLOW_API`, and it is required.
#[test]
fn api_audience_comes_from_loginflow_api_and_is_required() {
    let config = load(&vars(&[])).expect("config");
    assert_eq!(config.api_audience, "https://drivers.api.test");

    let mut without = vars(&[]);
    without.remove("LOGINFLOW_API");
    assert!(
        matches!(load(&without), Err(ConfigError::MissingEnvVar(name)) if name == "LOGINFLOW_API")
    );
}

/// The issuer is the audience of LoginFlow's own token, never an API's: configuring it as the
/// API would accept tokens minted only for userinfo and organizations.
#[test]
fn api_audience_equal_to_the_issuer_is_refused() {
    let map = vars(&[("LOGINFLOW_API", "https://api.loginflow.test/")]);
    assert!(matches!(load(&map), Err(ConfigError::InvalidValue(_))));
}

/// The company is what the verifier checks every token's `company_id` against: an empty one
/// would compare against nothing meaningful, so it is refused when the configuration loads.
#[test]
fn an_empty_company_is_refused() {
    for value in ["", "   "] {
        let map = vars(&[("LOGINFLOW_COMPANY", value)]);
        assert!(
            matches!(load(&map), Err(ConfigError::MissingValue(name)) if name.contains("LOGINFLOW_COMPANY")),
            "{value:?}"
        );
    }
}
