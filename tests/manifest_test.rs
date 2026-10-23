//! `PermissionManifest`: the product's `permissions.yaml`, refused here with the same rules the
//! LoginFlow catalog applies (spec §2.1 / §6b), so a bad manifest never reaches a deploy.

mod common;

use common::{MANIFEST_YAML, manifest, temp_dir};
use loginflow_sdk::{ManifestError, PermissionLevel, PermissionManifest};
use serde_json::json;

fn invalid(yaml: &str) -> String {
    match PermissionManifest::from_yaml_str(yaml) {
        Err(ManifestError::Invalid(reason)) => reason,
        other => panic!("expected an invalid manifest, got {other:?}"),
    }
}

/// TEST_CHARTER
/// Requirement: a valid manifest yields one permission per action, keyed
/// `{app}.{resource}.{action}`, with its level; `contains` answers exactly those keys; the sync
/// body is the contract's `{app, resources[{key,description,sensitive}],
/// permissions[{key,level,description}]}`.
/// Oracle: `entries()`, `contains()` and the serialized `catalog_request()`.
/// Risk edge: a key built differently from the server's makes every route check miss.
/// Layer: unit.
/// Counterfactual: building the key without the app prefix fails the key assertions.
#[test]
fn a_valid_manifest_yields_prefixed_keys_levels_and_the_sync_body() {
    let manifest = manifest();

    let entries = manifest.entries();
    let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "rutafacil.drivers.list",
            "rutafacil.drivers.create",
            "rutafacil.drivers.issueCode",
            "rutafacil.fleet.read",
        ]
    );
    let levels: Vec<PermissionLevel> = entries.iter().map(|e| e.level).collect();
    assert_eq!(
        levels,
        [
            PermissionLevel::Read,
            PermissionLevel::Write,
            PermissionLevel::Special,
            PermissionLevel::Read
        ]
    );

    assert!(manifest.contains("rutafacil.drivers.create"));
    assert!(!manifest.contains("rutafacil.drivers.delete"));
    assert!(!manifest.contains("otherapp.drivers.create"));
    assert!(!manifest.contains("rutafacil.drivers"));
    assert!(!manifest.contains("rutafacil.drivers.create.extra"));

    let body = serde_json::to_value(manifest.catalog_request()).expect("body");
    assert_eq!(body["app"], json!("rutafacil"));
    assert_eq!(
        body["resources"],
        json!([
            { "key": "drivers", "description": "Drivers of the client company", "sensitive": true },
            { "key": "fleet", "description": "Buses", "sensitive": false },
        ])
    );
    assert_eq!(
        body["permissions"][0],
        json!({ "key": "rutafacil.drivers.list", "level": "read", "description": "List the drivers" })
    );
    assert_eq!(body["permissions"][2]["level"], json!("special"));
}

/// TEST_CHARTER
/// Requirement: `loginflow` is reserved for LoginFlow's own permissions: a product manifest
/// claiming it is refused before any sync.
/// Oracle: `from_yaml_str` returns `ManifestError::Invalid` naming the reservation.
/// Risk edge: a product catalog shadowing the control plane (`loginflow.users.write`).
/// Layer: unit.
/// Counterfactual: removing the reserved-prefix check accepts the manifest.
#[test]
fn the_loginflow_prefix_is_reserved() {
    let reason = invalid(&MANIFEST_YAML.replace("app: rutafacil", "app: loginflow"));
    assert!(reason.contains("reserved"), "{reason}");
}

#[test]
fn an_app_prefix_outside_the_catalog_pattern_is_refused() {
    for app in ["RutaFacil", "r", "ruta-facil", "1ruta", &"a".repeat(41)] {
        invalid(&MANIFEST_YAML.replace("app: rutafacil", &format!("app: \"{app}\"")));
    }
}

#[test]
fn resource_and_action_names_outside_the_catalog_pattern_are_refused() {
    invalid(&MANIFEST_YAML.replace("  fleet:", "  Fleet:"));
    invalid(&MANIFEST_YAML.replace("  fleet:", "  fleet.buses:"));
    invalid(&MANIFEST_YAML.replace("action: read,", "action: \"read.all\","));
    invalid(&MANIFEST_YAML.replace("action: read,", "action: Read,"));
    invalid(&MANIFEST_YAML.replace("  fleet:", &format!("  {}:", "f".repeat(61))));
}

#[test]
fn an_action_declared_twice_in_a_resource_is_refused() {
    let reason = invalid(&MANIFEST_YAML.replace("action: create,", "action: list,"));
    assert!(reason.contains("more than once"), "{reason}");
}

#[test]
fn an_empty_description_is_refused() {
    invalid(&MANIFEST_YAML.replace("description: Buses", "description: \" \""));
    invalid(&MANIFEST_YAML.replace("description: See the buses", "description: \"\""));
}

#[test]
fn an_empty_manifest_and_one_over_500_permissions_are_refused() {
    invalid("app: rutafacil\nresources: {}\n");

    let actions: String = (0..501)
        .map(|i| format!("      - {{ action: a{i}, description: d }}\n"))
        .collect();
    let big =
        format!("app: rutafacil\nresources:\n  drivers:\n    description: x\n    read:\n{actions}");
    let reason = invalid(&big);
    assert!(reason.contains("at most 500"), "{reason}");
}

#[test]
fn a_permission_key_over_150_characters_is_refused() {
    let long_action = format!("a{}", "b".repeat(140));
    invalid(&MANIFEST_YAML.replace("action: read,", &format!("action: {long_action},")));
}

/// A typo in a field name must fail loudly instead of silently dropping the actions.
#[test]
fn an_unknown_field_is_a_parse_error() {
    let yaml = MANIFEST_YAML.replace(
        "    read:\n      - { action: read",
        "    reads:\n      - { action: read",
    );
    assert!(matches!(
        PermissionManifest::from_yaml_str(&yaml),
        Err(ManifestError::Parse(_))
    ));
}

#[test]
fn load_reads_the_file_and_reports_a_missing_one() {
    let dir = temp_dir("manifest");
    let path = dir.join("permissions.yaml");
    std::fs::write(&path, MANIFEST_YAML).expect("write");

    assert_eq!(PermissionManifest::load(&path).expect("load"), manifest());
    assert!(matches!(
        PermissionManifest::load(&dir.join("missing.yaml")),
        Err(ManifestError::Io { .. })
    ));
    let _ = std::fs::remove_dir_all(dir);
}
