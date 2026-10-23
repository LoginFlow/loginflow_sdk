//! The product's permission manifest (`permissions.yaml`): the resources of one API and the
//! actions on each, the single source of the permissions the API checks and syncs to LoginFlow.
//!
//! ```yaml
//! app: rutafacil
//! resources:
//!   drivers:
//!     description: Drivers of the client company
//!     sensitive: true
//!     read:
//!       - { action: list, description: List the drivers }
//!     write:
//!       - { action: create, description: Register a driver }
//!     special:
//!       - { action: issueCode, description: Issue a driver's access code }
//! ```
//!
//! Every permission is `{app}.{resource}.{action}` (`rutafacil.drivers.create`), the shape the
//! LoginFlow catalog accepts: `app` is the application's own prefix (`loginflow` is reserved),
//! and a manifest that the server would refuse is refused here first.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::models::{CatalogPermission, CatalogResource, CatalogSyncRequest, PermissionLevel};

/// The prefix LoginFlow keeps for its own permissions.
pub const RESERVED_APP_PREFIX: &str = "loginflow";

/// Most permissions one API's catalog may hold.
pub const MAX_MANIFEST_PERMISSIONS: usize = 500;

/// Most resources one API's catalog may hold.
pub const MAX_MANIFEST_RESOURCES: usize = 200;

/// Longest description (of a resource or an action), in characters after trimming.
pub const MAX_DESCRIPTION_LEN: usize = 500;

/// Longest permission key the catalog stores.
pub const MAX_PERMISSION_KEY_LEN: usize = 150;

/// Longest resource key the catalog stores.
pub const MAX_RESOURCE_KEY_LEN: usize = 60;

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestError {
    /// The file could not be read.
    #[error("cannot read the permission manifest {path}: {reason}")]
    Io {
        /// The manifest's path.
        path: String,
        /// The I/O error.
        reason: String,
    },
    /// The text is not a manifest (YAML syntax, a missing or unknown field).
    #[error("the permission manifest is not valid YAML: {0}")]
    Parse(String),
    /// The manifest breaks a rule of [`PermissionManifest::validate`] (the first one found).
    #[error("invalid permission manifest: {0}")]
    Invalid(String),
}

/// The manifest of one API: its application prefix and its resources by key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionManifest {
    /// The application's permission prefix (`rutafacil`): `[a-z][a-z0-9]{1,39}`, never
    /// `loginflow`.
    pub app: String,
    /// Every resource of the API, by key.
    pub resources: BTreeMap<String, ResourceSpec>,
}

/// One resource and its actions, by level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    /// What the resource is, 1 to 500 characters.
    pub description: String,
    /// Personal or otherwise sensitive data: the panel's "Support" template leaves it out.
    #[serde(default)]
    pub sensitive: bool,
    /// Actions that read the resource.
    #[serde(default)]
    pub read: Vec<ActionSpec>,
    /// Actions that change the resource.
    #[serde(default)]
    pub write: Vec<ActionSpec>,
    /// Actions that are neither (e.g. issuing a code).
    #[serde(default)]
    pub special: Vec<ActionSpec>,
}

/// One action on a resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    /// The action segment of the permission key (`list`, `issueCode`).
    pub action: String,
    /// What the action allows, 1 to 500 characters.
    pub description: String,
}

/// One permission of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// `{app}.{resource}.{action}`
    pub key: String,
    /// The resource key.
    pub resource: String,
    /// The level the action is declared under.
    pub level: PermissionLevel,
    /// The action's description.
    pub description: String,
}

impl PermissionManifest {
    /// Read and validate the manifest at `path`.
    ///
    /// # Errors
    /// [`ManifestError::Io`] when the file cannot be read; otherwise as
    /// [`from_yaml_str`](Self::from_yaml_str).
    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let text = fs::read_to_string(path).map_err(|e| ManifestError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        Self::from_yaml_str(&text)
    }

    /// Parse and validate a manifest. Unknown fields are refused, so a typo never silently drops
    /// an action.
    ///
    /// # Errors
    /// [`ManifestError::Parse`] for YAML that is not a manifest; [`ManifestError::Invalid`] for
    /// one that breaks a rule of [`validate`](Self::validate).
    pub fn from_yaml_str(text: &str) -> Result<Self, ManifestError> {
        let manifest: Self =
            serde_yaml_ng::from_str(text).map_err(|e| ManifestError::Parse(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The rules the LoginFlow catalog enforces (`PUT /v1/service/catalog` answers `422` to a
    /// manifest that breaks one): `app` is `[a-z][a-z0-9]{1,39}` and not `loginflow`; resource
    /// keys and actions are `[a-z][a-zA-Z0-9_]*`, a resource key at most 60 characters and a
    /// permission key at most 150; every description is 1 to 500 characters after trimming; an
    /// action appears once per resource; the manifest has at most 200 resources and 1 to 500
    /// permissions.
    ///
    /// # Errors
    /// [`ManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if !is_app_prefix(&self.app) {
            return Err(invalid(format!(
                "app `{}` must be 2 to 40 characters of [a-z0-9], starting with a letter",
                self.app
            )));
        }
        if self.app == RESERVED_APP_PREFIX {
            return Err(invalid(format!(
                "app `{RESERVED_APP_PREFIX}` is reserved for LoginFlow's own permissions"
            )));
        }
        if self.resources.len() > MAX_MANIFEST_RESOURCES {
            return Err(invalid(format!(
                "the manifest declares {} resources; at most {MAX_MANIFEST_RESOURCES}",
                self.resources.len()
            )));
        }
        let mut count = 0usize;
        for (resource, spec) in &self.resources {
            if !is_segment(resource) || resource.len() > MAX_RESOURCE_KEY_LEN {
                return Err(invalid(format!(
                    "resource `{resource}` must be at most {MAX_RESOURCE_KEY_LEN} characters of \
                     [a-zA-Z0-9_], starting with a lowercase letter"
                )));
            }
            if !is_description(&spec.description) {
                return Err(invalid(format!(
                    "resource `{resource}` needs a description of 1 to {MAX_DESCRIPTION_LEN} characters"
                )));
            }
            let mut actions = BTreeSet::new();
            for (_, action) in spec.actions() {
                if !is_segment(&action.action) {
                    return Err(invalid(format!(
                        "action `{}` of `{resource}` must be [a-zA-Z0-9_], starting with a \
                         lowercase letter",
                        action.action
                    )));
                }
                if !is_description(&action.description) {
                    return Err(invalid(format!(
                        "action `{resource}.{}` needs a description of 1 to \
                         {MAX_DESCRIPTION_LEN} characters",
                        action.action
                    )));
                }
                if !actions.insert(action.action.as_str()) {
                    return Err(invalid(format!(
                        "action `{resource}.{}` is declared more than once",
                        action.action
                    )));
                }
                let key = self.key_of(resource, &action.action);
                if key.len() > MAX_PERMISSION_KEY_LEN {
                    return Err(invalid(format!(
                        "permission `{key}` is longer than {MAX_PERMISSION_KEY_LEN} characters"
                    )));
                }
                count += 1;
            }
        }
        if count == 0 {
            return Err(invalid("the manifest declares no permission".to_string()));
        }
        if count > MAX_MANIFEST_PERMISSIONS {
            return Err(invalid(format!(
                "the manifest declares {count} permissions; at most {MAX_MANIFEST_PERMISSIONS}"
            )));
        }
        Ok(())
    }

    /// Every permission, ordered by resource and then as declared (read, write, special).
    pub fn entries(&self) -> Vec<CatalogEntry> {
        self.resources
            .iter()
            .flat_map(|(resource, spec)| {
                spec.actions().map(move |(level, action)| CatalogEntry {
                    key: self.key_of(resource, &action.action),
                    resource: resource.clone(),
                    level,
                    description: action.description.clone(),
                })
            })
            .collect()
    }

    /// Whether `key` (`{app}.{resource}.{action}`) is a permission of this manifest.
    pub fn contains(&self, key: &str) -> bool {
        let mut segments = key.split('.');
        let (Some(app), Some(resource), Some(action), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return false;
        };
        app == self.app
            && self
                .resources
                .get(resource)
                .is_some_and(|spec| spec.actions().any(|(_, a)| a.action == action))
    }

    /// The `PUT /v1/service/catalog` body of this manifest.
    pub fn catalog_request(&self) -> CatalogSyncRequest {
        CatalogSyncRequest {
            app: self.app.clone(),
            resources: self
                .resources
                .iter()
                .map(|(key, spec)| CatalogResource {
                    key: key.clone(),
                    description: spec.description.clone(),
                    sensitive: spec.sensitive,
                })
                .collect(),
            permissions: self
                .entries()
                .into_iter()
                .map(|entry| CatalogPermission {
                    key: entry.key,
                    level: entry.level,
                    description: entry.description,
                })
                .collect(),
        }
    }

    fn key_of(&self, resource: &str, action: &str) -> String {
        format!("{}.{resource}.{action}", self.app)
    }
}

impl ResourceSpec {
    /// The resource's actions with their level, in declaration order.
    fn actions(&self) -> impl Iterator<Item = (PermissionLevel, &ActionSpec)> {
        let read = self.read.iter().map(|a| (PermissionLevel::Read, a));
        let write = self.write.iter().map(|a| (PermissionLevel::Write, a));
        let special = self.special.iter().map(|a| (PermissionLevel::Special, a));
        read.chain(write).chain(special)
    }
}

fn invalid(reason: String) -> ManifestError {
    ManifestError::Invalid(reason)
}

/// 1 to [`MAX_DESCRIPTION_LEN`] characters after trimming.
fn is_description(value: &str) -> bool {
    (1..=MAX_DESCRIPTION_LEN).contains(&value.trim().chars().count())
}

/// `^[a-z][a-z0-9]{1,39}$`
fn is_app_prefix(value: &str) -> bool {
    let mut chars = value.chars();
    (2..=40).contains(&value.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// `^[a-z][a-zA-Z0-9_]*$`
fn is_segment(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
