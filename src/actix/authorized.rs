//! The verified caller of a permission route, as the gate left it for the handler.

use std::collections::BTreeSet;
use std::future::{Ready, ready};

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

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
    PermissionDenied { permission: String },
}

impl AccessDenied {
    /// The body's `error` code.
    pub fn code(&self) -> &'static str {
        match self {
            AccessDenied::PermissionUnmapped => "permission_unmapped",
            AccessDenied::OrganizationRequired => "organization_required",
            AccessDenied::PermissionDenied { .. } => "permission_denied",
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

/// The caller of a permission route: a verified token for this API, with an active
/// organization, granting the route's permission there. Only the gate builds it; a handler of a
/// public route (or of a route outside the gate) that asks for it gets a `500`, never an
/// unverified caller.
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
        if self.has(permission) {
            Ok(())
        } else {
            Err(AccessDenied::PermissionDenied {
                permission: permission.to_string(),
            })
        }
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

impl FromRequest for Authorized {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<Authorized>()
                .cloned()
                .ok_or_else(|| {
                    Error::from(LoginFlowError::Config(
                        "Authorized is only available on a permission route of the PermissionRouter"
                            .to_string(),
                    ))
                }),
        )
    }
}
