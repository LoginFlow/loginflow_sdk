//! The verified caller of a permission route, as the gate left it for the handler.

use std::collections::BTreeSet;
use std::future::{Ready, ready};

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

use crate::actix::router::RouteAccess;
use crate::authorization::verifier::VerifiedAccess;
use crate::error::LoginFlowError;
use crate::models::{AccessClaims, AccessSubjectClaims};

/// Why a verified caller may not do what it asked (`403`, the code is the body's `error`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AccessDenied {
    /// The route is not in the API's route table: denied by default.
    #[error("permission_unmapped")]
    PermissionUnmapped,
    /// The token has no active organization, so it grants nothing.
    #[error("organization_required")]
    OrganizationRequired,
    /// The token does not grant `permission` in its organization.
    #[error("permission_denied")]
    PermissionDenied {
        /// The permission that was required (logged, never sent).
        permission: String,
    },
    /// A machine token on a route declared for persons only.
    #[error("machine_not_allowed")]
    MachineNotAllowed,
    /// A person's token on a route declared for machines only.
    #[error("person_not_allowed")]
    PersonNotAllowed,
}

impl AccessDenied {
    /// The body's `error` code.
    pub fn code(&self) -> &'static str {
        match self {
            AccessDenied::PermissionUnmapped => "permission_unmapped",
            AccessDenied::OrganizationRequired => "organization_required",
            AccessDenied::PermissionDenied { .. } => "permission_denied",
            AccessDenied::MachineNotAllowed => "machine_not_allowed",
            AccessDenied::PersonNotAllowed => "person_not_allowed",
        }
    }
}

/// `403` with `{"error": <code>, "error_type": "Authorization"}`; the missing permission is not
/// disclosed.
impl ResponseError for AccessDenied {
    fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().json(json!({
            "error": self.code(),
            "error_type": "Authorization",
        }))
    }
}

/// The person calling a permission route: a person's verified token for this API, with an
/// active organization, granting the route's permission there. Only the gate builds it; a handler
/// of a public route (or of a route outside the gate) that asks for it gets a `500`, never an
/// unverified caller. A machine never gets one: a machine route's handler reads
/// [`MachineAuthorized`], and a route open to both reads [`Caller`].
///
/// Scope every query by [`org_id`](Self::org_id) (or [`org_external_id`](Self::org_external_id)),
/// never by an organization id taken from the request body or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    claims: AccessClaims,
    org_id: String,
    permissions: BTreeSet<String>,
    dpop_jkt: Option<String>,
}

impl Authorized {
    /// The caller of a verified token; a token without an organization grants nothing.
    pub(crate) fn from_verified(verified: VerifiedAccess) -> Result<Self, AccessDenied> {
        let org_id = verified
            .claims
            .org_id
            .clone()
            .ok_or(AccessDenied::OrganizationRequired)?;
        Ok(Self {
            claims: verified.claims,
            org_id,
            permissions: verified.permissions,
            dpop_jkt: verified.dpop_jkt,
        })
    }

    /// The token's `sub`: a `company_users` id or an access-code subject id.
    pub fn sub(&self) -> &str {
        &self.claims.sub
    }

    /// The active organization: the scope of everything this caller may touch.
    pub fn org_id(&self) -> &str {
        &self.org_id
    }

    /// The product's own id of the active organization, when it has one.
    pub fn org_external_id(&self) -> Option<&str> {
        self.claims.org_ext.as_deref()
    }

    /// Company ID (`CP-...`).
    pub fn company_id(&self) -> &str {
        &self.claims.company_id
    }

    /// What the token grants in [`org_id`](Self::org_id), for this API.
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    /// Whether the token grants `permission`.
    pub fn has(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// A finer check inside a handler (e.g. a field only some roles may change).
    ///
    /// # Errors
    /// [`AccessDenied::PermissionDenied`] when the token does not grant `permission`.
    pub fn require(&self, permission: &str) -> Result<(), AccessDenied> {
        require_in(&self.permissions, permission)
    }

    /// The access-code subject's claims, for a token minted for one.
    pub fn subject(&self) -> Option<&AccessSubjectClaims> {
        self.claims.access_subject.as_ref()
    }

    /// The thumbprint of the DPoP key the request proved, for a DPoP-bound token.
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }

    /// Every verified claim (session, authentication methods, `auth_time` for a step-up check).
    pub fn claims(&self) -> &AccessClaims {
        &self.claims
    }
}

/// The machine calling a machine route: a machine token for this API
/// ([`AccessClaims::is_machine`]) granting the route's permission. There is no person and no
/// organization: [`client_id`](Self::client_id) names the calling system. Only the gate builds
/// it; asking for it anywhere else is a `500`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineAuthorized {
    claims: AccessClaims,
    permissions: BTreeSet<String>,
    dpop_jkt: Option<String>,
}

impl MachineAuthorized {
    /// The caller of a verified machine token.
    pub(crate) fn from_verified(verified: VerifiedAccess) -> Self {
        Self {
            claims: verified.claims,
            permissions: verified.permissions,
            dpop_jkt: verified.dpop_jkt,
        }
    }

    /// The machine client that called (`client_id`, also the token's `sub`).
    pub fn client_id(&self) -> &str {
        &self.claims.client_id
    }

    /// Company ID (`CP-...`) of the client: the company that owns this API's application.
    pub fn company_id(&self) -> &str {
        &self.claims.company_id
    }

    /// Application ID (`APP-...`) of the client.
    pub fn app(&self) -> &str {
        &self.claims.app
    }

    /// What the token grants on this API.
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    /// Whether the token grants `permission`.
    pub fn has(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// A finer check inside a handler.
    ///
    /// # Errors
    /// [`AccessDenied::PermissionDenied`] when the token does not grant `permission`.
    pub fn require(&self, permission: &str) -> Result<(), AccessDenied> {
        require_in(&self.permissions, permission)
    }

    /// The thumbprint of the DPoP key the request proved, for a DPoP-bound token.
    pub fn dpop_jkt(&self) -> Option<&str> {
        self.dpop_jkt.as_deref()
    }

    /// Every verified claim.
    pub fn claims(&self) -> &AccessClaims {
        &self.claims
    }
}

/// Who called a permission route, as the gate verified it: a person ([`Authorized`]) or a
/// machine ([`MachineAuthorized`]). Available on every permission route; the one extractor for a
/// route declared with [`crate::actix::PermissionRouter::person_or_machine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// A person's token, with its active organization.
    Person(Authorized),
    /// A machine token: another system, no organization.
    Machine(MachineAuthorized),
}

impl Caller {
    /// Classify a verified token for a route that requires `access`: a machine token only where
    /// machines are admitted, a person's token only where persons are (and with an
    /// organization), and the route's permission in either case.
    pub(crate) fn admit(
        verified: VerifiedAccess,
        access: RouteAccess,
    ) -> Result<Self, AccessDenied> {
        let caller = if verified.claims.is_machine() {
            if !access.admits_machines() {
                return Err(AccessDenied::MachineNotAllowed);
            }
            Caller::Machine(MachineAuthorized::from_verified(verified))
        } else {
            if !access.admits_persons() {
                return Err(AccessDenied::PersonNotAllowed);
            }
            Caller::Person(Authorized::from_verified(verified)?)
        };
        if let Some(permission) = access.permission() {
            caller.require(permission)?;
        }
        Ok(caller)
    }

    /// Whether a machine called.
    pub fn is_machine(&self) -> bool {
        matches!(self, Caller::Machine(_))
    }

    /// The person, when a person called.
    pub fn person(&self) -> Option<&Authorized> {
        match self {
            Caller::Person(person) => Some(person),
            Caller::Machine(_) => None,
        }
    }

    /// The machine, when a machine called.
    pub fn machine(&self) -> Option<&MachineAuthorized> {
        match self {
            Caller::Person(_) => None,
            Caller::Machine(machine) => Some(machine),
        }
    }

    /// What the token grants: in the person's organization, or on this API for a machine.
    pub fn permissions(&self) -> &BTreeSet<String> {
        match self {
            Caller::Person(person) => person.permissions(),
            Caller::Machine(machine) => machine.permissions(),
        }
    }

    /// Whether the token grants `permission`.
    pub fn has(&self, permission: &str) -> bool {
        self.permissions().contains(permission)
    }

    /// A finer check inside a handler.
    ///
    /// # Errors
    /// [`AccessDenied::PermissionDenied`] when the token does not grant `permission`.
    pub fn require(&self, permission: &str) -> Result<(), AccessDenied> {
        require_in(self.permissions(), permission)
    }

    /// Every verified claim.
    pub fn claims(&self) -> &AccessClaims {
        match self {
            Caller::Person(person) => person.claims(),
            Caller::Machine(machine) => machine.claims(),
        }
    }

    /// The thumbprint of the DPoP key the request proved, for a DPoP-bound token.
    pub fn dpop_jkt(&self) -> Option<&str> {
        match self {
            Caller::Person(person) => person.dpop_jkt(),
            Caller::Machine(machine) => machine.dpop_jkt(),
        }
    }
}

/// `Ok` when `permissions` holds `permission`, `PermissionDenied` otherwise.
fn require_in(permissions: &BTreeSet<String>, permission: &str) -> Result<(), AccessDenied> {
    if permissions.contains(permission) {
        Ok(())
    } else {
        Err(AccessDenied::PermissionDenied {
            permission: permission.to_string(),
        })
    }
}

/// The value the gate left in the request's extensions, or a `500` naming `what`.
fn from_extensions<T: Clone + 'static>(req: &HttpRequest, what: &str) -> Result<T, Error> {
    req.extensions().get::<T>().cloned().ok_or_else(|| {
        Error::from(LoginFlowError::Config(format!(
            "{what} is only available on a route of the PermissionRouter that admits it"
        )))
    })
}

impl FromRequest for Authorized {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(from_extensions(req, "Authorized (a person)"))
    }
}

impl FromRequest for MachineAuthorized {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(from_extensions(req, "MachineAuthorized (a machine)"))
    }
}

impl FromRequest for Caller {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(from_extensions(req, "Caller"))
    }
}
