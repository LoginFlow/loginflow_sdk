//! The middleware that enforces a [`crate::actix::BuiltRouter`]: deny by default.

use std::collections::HashMap;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use actix_web::http::{Method, StatusCode};
use actix_web::{Error, HttpMessage, HttpRequest, HttpResponse, ResponseError};
use log::{debug, error, warn};
use serde_json::json;

use crate::actix::authorized::{AccessDenied, Authorized};
use crate::actix::extractor::extract_authorization;
use crate::actix::router::RouteAccess;
use crate::authorization::verifier::{AccessVerifier, PresentedToken, VerifyError};

/// Request header carrying the RFC 9449 DPoP proof.
const DPOP_HEADER: &str = "DPoP";

type RouteTable = Arc<HashMap<(Method, String), RouteAccess>>;

/// Built by [`crate::actix::BuiltRouter::gate`]. For every request:
///
/// 1. its route (method + matched pattern) not in the table → `403 permission_unmapped`;
/// 2. a public route → the handler runs;
/// 3. otherwise the token is verified (`401 invalid_token`, `503` when the decision cannot be
///    made), the token must have an organization (`403 organization_required`) and the route's
///    permission in it (`403 permission_denied`); the handler then reads [`Authorized`].
#[derive(Clone)]
pub struct PermissionGate {
    table: RouteTable,
    verifier: Arc<dyn AccessVerifier>,
}

impl PermissionGate {
    pub(crate) fn new(table: RouteTable, verifier: Arc<dyn AccessVerifier>) -> Self {
        Self { table, verifier }
    }
}

impl<S, B> Transform<S, ServiceRequest> for PermissionGate
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = PermissionGateMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(PermissionGateMiddleware {
            service: Rc::new(service),
            table: Arc::clone(&self.table),
            verifier: Arc::clone(&self.verifier),
        }))
    }
}

/// The per-worker service of [`PermissionGate`].
pub struct PermissionGateMiddleware<S> {
    service: Rc<S>,
    table: RouteTable,
    verifier: Arc<dyn AccessVerifier>,
}

/// Why the gate answered instead of the handler.
enum Refusal {
    Denied(AccessDenied),
    Verify(VerifyError),
}

impl<S, B> Service<ServiceRequest> for PermissionGateMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let verifier = Arc::clone(&self.verifier);
        let access = req
            .match_pattern()
            .and_then(|pattern| self.table.get(&(req.method().clone(), pattern)).copied());

        Box::pin(async move {
            let permission = match access {
                None => {
                    debug!("{} {}: route not mapped", req.method(), req.path());
                    return Ok(refuse(
                        req,
                        Refusal::Denied(AccessDenied::PermissionUnmapped),
                    ));
                }
                Some(RouteAccess::Public) => {
                    return service
                        .call(req)
                        .await
                        .map(ServiceResponse::map_into_left_body);
                }
                Some(RouteAccess::Permission(permission)) => permission,
            };
            match authorize(req.request(), verifier.as_ref(), permission).await {
                Ok(authorized) => {
                    req.extensions_mut().insert(authorized);
                    service
                        .call(req)
                        .await
                        .map(ServiceResponse::map_into_left_body)
                }
                Err(refusal) => Ok(refuse(req, refusal)),
            }
        })
    }
}

/// Verify the request's token and check `permission` in its organization.
async fn authorize(
    req: &HttpRequest,
    verifier: &dyn AccessVerifier,
    permission: &'static str,
) -> Result<Authorized, Refusal> {
    let authorization = extract_authorization(req)
        .map_err(|e| Refusal::Verify(VerifyError::InvalidToken(e.to_string())))?;
    let dpop_proof = single_dpop_header(req.headers()).map_err(Refusal::Verify)?;
    let request_origin = {
        let info = req.connection_info();
        format!("{}://{}", info.scheme(), info.host())
    };
    let presented = PresentedToken {
        authorization: &authorization,
        dpop_proof,
        method: req.method().as_str(),
        request_origin: &request_origin,
        path: req.path(),
    };
    let verified = verifier.verify(presented).await.map_err(Refusal::Verify)?;
    let authorized = Authorized::from_verified(verified).map_err(Refusal::Denied)?;
    authorized.require(permission).map_err(Refusal::Denied)?;
    Ok(authorized)
}

/// The one `DPoP` header value, if any (RFC 9449 §4.3 check 1: not more than one).
fn single_dpop_header(headers: &HeaderMap) -> Result<Option<&str>, VerifyError> {
    let mut values = headers.get_all(DPOP_HEADER);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(VerifyError::InvalidToken(
            "more than one DPoP header".to_string(),
        ));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| VerifyError::InvalidToken("the DPoP header is not ASCII".to_string()))
}

fn refuse<B>(req: ServiceRequest, refusal: Refusal) -> ServiceResponse<EitherBody<B>> {
    let response = match refusal {
        Refusal::Denied(denied) => {
            debug!("{} {}: {}", req.method(), req.path(), denied);
            denied.error_response()
        }
        Refusal::Verify(failure) => {
            match &failure {
                VerifyError::InvalidToken(reason) => {
                    warn!(
                        "{} {}: access token refused: {reason}",
                        req.method(),
                        req.path()
                    );
                }
                VerifyError::Unavailable(reason) => {
                    error!(
                        "{} {}: authorization unavailable: {reason}",
                        req.method(),
                        req.path()
                    );
                }
            }
            failure.error_response()
        }
    };
    req.into_response(response).map_into_right_body()
}

/// Fixed bodies: the reason a token was refused is logged, never sent.
impl ResponseError for VerifyError {
    fn status_code(&self) -> StatusCode {
        match self {
            VerifyError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            VerifyError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status_code());
        let body = match self {
            VerifyError::InvalidToken(_) => {
                response.insert_header((
                    WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer error=\"invalid_token\""),
                ));
                json!({ "error": "invalid_token", "error_type": "Authentication" })
            }
            VerifyError::Unavailable(_) => {
                json!({ "error": "authorization_unavailable", "error_type": "ServiceUnavailable" })
            }
        };
        response.json(body)
    }
}
