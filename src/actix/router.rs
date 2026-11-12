//! The route table of an API: every route with the permission it requires, signed-in only, or
//! public.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use actix_web::http::Method;
use actix_web::web::{self, ServiceConfig};
use actix_web::{FromRequest, Handler, Responder, Route};
use thiserror::Error;

use crate::actix::gate::PermissionGate;
use crate::authorization::manifest::PermissionManifest;
use crate::authorization::verifier::AccessVerifier;

/// What a route requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteAccess {
    /// No token at all (health checks, webhooks verified by other means).
    Public,
    /// A person's verified token whose permissions, in its active organization, include this
    /// one. A machine token is refused (`403 machine_not_allowed`).
    Permission(&'static str),
    /// A machine token ([`crate::models::AccessClaims::is_machine`]) whose permissions for this
    /// API include this one; no organization involved. A person's token is refused
    /// (`403 person_not_allowed`).
    Machine(&'static str),
    /// Either: a person's token with the permission in its active organization, or a machine
    /// token with the permission. The handler reads [`crate::actix::Caller`].
    PersonOrMachine(&'static str),
    /// A signed-in person's verified token, with no organization and no permission required
    /// (e.g. "create my company" before the person belongs to any organization). A machine
    /// token is refused (`403 machine_not_allowed`), and so is an access-code subject's (`403
    /// access_subject_not_allowed`). The handler reads [`crate::actix::SignedIn`].
    SignedIn,
}

impl RouteAccess {
    /// The permission the route requires; `None` for a public or a signed-in route.
    pub fn permission(&self) -> Option<&'static str> {
        match self {
            RouteAccess::Public | RouteAccess::SignedIn => None,
            RouteAccess::Permission(permission)
            | RouteAccess::Machine(permission)
            | RouteAccess::PersonOrMachine(permission) => Some(permission),
        }
    }

    /// Whether a person's token may call the route.
    pub fn admits_persons(&self) -> bool {
        matches!(
            self,
            RouteAccess::Permission(_) | RouteAccess::PersonOrMachine(_) | RouteAccess::SignedIn
        )
    }

    /// Whether a machine token may call the route.
    pub fn admits_machines(&self) -> bool {
        matches!(
            self,
            RouteAccess::Machine(_) | RouteAccess::PersonOrMachine(_)
        )
    }
}

/// Why a route table was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteMapError {
    /// A route requires a permission the manifest does not declare.
    #[error("{method} {path} requires `{permission}`, which the manifest does not declare")]
    UnknownPermission {
        /// The route's method.
        method: Method,
        /// The route's path pattern.
        path: &'static str,
        /// The undeclared permission.
        permission: &'static str,
    },
    /// The same method and path pattern are declared twice.
    #[error("{method} {path} is declared more than once")]
    DuplicateRoute {
        /// The route's method.
        method: Method,
        /// The route's path pattern.
        path: &'static str,
    },
    /// A path pattern that does not start with `/`.
    #[error("route path `{path}` must start with `/`")]
    InvalidPath {
        /// The offending path pattern.
        path: &'static str,
    },
}

/// Builds the actix `Route` of an entry; called once per worker by [`BuiltRouter::configure`].
type RouteFactory = Arc<dyn Fn() -> Route + Send + Sync>;

struct RouteEntry {
    method: Method,
    path: &'static str,
    access: RouteAccess,
    factory: RouteFactory,
}

/// Declares every route of the API with what it requires. A route is reachable only through
/// this table: [`BuiltRouter::configure`] registers the handlers, and [`BuiltRouter::gate`]
/// refuses any request whose route is not in it.
///
/// Register the router at the root of the `App` with full paths: the gate matches the request
/// against the pattern as written here, so a route mounted under a `scope` is not found and is
/// refused (`permission_unmapped`).
pub struct PermissionRouter {
    manifest: Arc<PermissionManifest>,
    entries: Vec<RouteEntry>,
}

impl PermissionRouter {
    /// An empty table whose permissions must all be in `manifest`.
    pub fn new(manifest: Arc<PermissionManifest>) -> Self {
        Self {
            manifest,
            entries: Vec::new(),
        }
    }

    /// A route that needs no token.
    pub fn public<F, Args>(self, method: Method, path: &'static str, handler: F) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        self.push(method, path, RouteAccess::Public, handler)
    }

    /// A route that needs `permission` (a key of the manifest) in the token's organization.
    pub fn route<F, Args>(
        self,
        method: Method,
        path: &'static str,
        permission: &'static str,
        handler: F,
    ) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        self.push(method, path, RouteAccess::Permission(permission), handler)
    }

    /// A route for machines only: a machine token (another system calling with a
    /// `client_credentials` token for this API) that holds `permission` (a key of the manifest).
    /// No organization is involved; a person's token is refused (`403 person_not_allowed`). The
    /// handler reads [`crate::actix::MachineAuthorized`] (or [`crate::actix::Caller`]).
    pub fn machine<F, Args>(
        self,
        method: Method,
        path: &'static str,
        permission: &'static str,
        handler: F,
    ) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        self.push(method, path, RouteAccess::Machine(permission), handler)
    }

    /// A route for any signed-in person: the token is verified exactly as on a permission route
    /// (signature, `iss`, `aud`, company, `exp`, DPoP binding and single-use proof), but no
    /// organization and no permission are required. Meant for what a person does before
    /// belonging to any organization (e.g. founding one). A machine token is refused (`403
    /// machine_not_allowed`), and so is an access-code subject's (`403
    /// access_subject_not_allowed`). The handler reads [`crate::actix::SignedIn`]; `Authorized`
    /// and `Caller` are not available there.
    pub fn signed_in<F, Args>(self, method: Method, path: &'static str, handler: F) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        self.push(method, path, RouteAccess::SignedIn, handler)
    }

    /// A route for both a person (with `permission` in the token's organization) and a machine
    /// (with `permission` for this API). The handler reads [`crate::actix::Caller`] and scopes
    /// what it does by which one called.
    pub fn person_or_machine<F, Args>(
        self,
        method: Method,
        path: &'static str,
        permission: &'static str,
        handler: F,
    ) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        self.push(
            method,
            path,
            RouteAccess::PersonOrMachine(permission),
            handler,
        )
    }

    fn push<F, Args>(
        mut self,
        method: Method,
        path: &'static str,
        access: RouteAccess,
        handler: F,
    ) -> Self
    where
        F: Handler<Args> + Send + Sync,
        Args: FromRequest + 'static,
        F::Output: Responder + 'static,
    {
        let route_method = method.clone();
        let factory: RouteFactory =
            Arc::new(move || web::method(route_method.clone()).to(handler.clone()));
        self.entries.push(RouteEntry {
            method,
            path,
            access,
            factory,
        });
        self
    }

    /// Check the table: every permission is in the manifest, no route is declared twice, and
    /// every path is absolute.
    ///
    /// # Errors
    /// The first [`RouteMapError`] found.
    pub fn build(self) -> Result<BuiltRouter, RouteMapError> {
        let mut table = HashMap::new();
        for entry in &self.entries {
            if !entry.path.starts_with('/') {
                return Err(RouteMapError::InvalidPath { path: entry.path });
            }
            if let Some(permission) = entry.access.permission()
                && !self.manifest.contains(permission)
            {
                return Err(RouteMapError::UnknownPermission {
                    method: entry.method.clone(),
                    path: entry.path,
                    permission,
                });
            }
            let key = (entry.method.clone(), entry.path.to_string());
            if table.insert(key, entry.access).is_some() {
                return Err(RouteMapError::DuplicateRoute {
                    method: entry.method.clone(),
                    path: entry.path,
                });
            }
        }
        Ok(BuiltRouter {
            table: Arc::new(table),
            entries: Arc::new(self.entries),
        })
    }
}

/// A checked route table. Cloning is cheap; build it once, outside `HttpServer::new`.
#[derive(Clone)]
pub struct BuiltRouter {
    table: Arc<HashMap<(Method, String), RouteAccess>>,
    entries: Arc<Vec<RouteEntry>>,
}

impl BuiltRouter {
    /// Register every route's handler (`App::configure(|cfg| router.configure(cfg))`).
    pub fn configure(&self, cfg: &mut ServiceConfig) {
        for entry in self.entries.iter() {
            cfg.route(entry.path, (entry.factory)());
        }
    }

    /// The middleware that enforces the table (`App::wrap(router.gate(verifier))`): wrap the
    /// whole `App`, so no route escapes it.
    pub fn gate(&self, verifier: Arc<dyn AccessVerifier>) -> PermissionGate {
        PermissionGate::new(Arc::clone(&self.table), verifier)
    }

    /// What the route `method` + `pattern` requires; `None` for a route not in the table.
    pub fn access(&self, method: &Method, pattern: &str) -> Option<RouteAccess> {
        self.table
            .get(&(method.clone(), pattern.to_string()))
            .copied()
    }

    /// Every permission some route requires.
    pub fn routed_permissions(&self) -> BTreeSet<&'static str> {
        self.table
            .values()
            .filter_map(RouteAccess::permission)
            .collect()
    }
}
