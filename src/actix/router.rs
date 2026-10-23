//! The route table of an API: every route with the permission it requires, or public.

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
    /// A verified token whose permissions, in its active organization, include this one.
    Permission(&'static str),
}

/// Why a route table was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RouteMapError {
    #[error("{method} {path} requires `{permission}`, which the manifest does not declare")]
    UnknownPermission {
        method: Method,
        path: &'static str,
        permission: &'static str,
    },
    #[error("{method} {path} is declared more than once")]
    DuplicateRoute { method: Method, path: &'static str },
    #[error("route path `{path}` must start with `/`")]
    InvalidPath { path: &'static str },
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
            if let RouteAccess::Permission(permission) = entry.access
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
            .filter_map(|access| match access {
                RouteAccess::Permission(permission) => Some(*permission),
                RouteAccess::Public => None,
            })
            .collect()
    }
}
