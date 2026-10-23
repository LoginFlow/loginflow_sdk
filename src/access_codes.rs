//! Machine-to-machine access codes (`/v1/service/access-codes`, `/v1/service/access-subjects`).
//!
//! A tenant backend whose people or devices live in ITS OWN database (a driver, a student, a
//! kiosk) issues a one-time code for one of them; the person or device types it in the app and
//! gets a LoginFlow session. LoginFlow stores no PII for these subjects: their tokens carry
//! `sub` = the LoginFlow subject id plus the `ext_sub`, `subject_kind` and `ext_profile` claims
//! ([`crate::AccessSubjectClaims`]), so a resource server maps the token back to its own record.
//!
//! A confidential OAuth client holding the `client_credentials` grant and the
//! `loginflow.accessCodes.issue`, `.read` and `.revoke` permissions (each route checks its exact
//! one, in the token's `scope` and among the key's permissions) issues, lists and revokes codes for
//! its own company and application. The company and
//! application are never sent: the server takes them from the token.

use crate::error::LoginFlowResult;
use crate::http::{urlencoded, with_query};
use crate::models::{
    ACCESS_CODES_ISSUE_SCOPE, ACCESS_CODES_READ_SCOPE, ACCESS_CODES_REVOKE_SCOPE, AccessCodeInfo,
    IssueAccessCodeRequest, IssuedAccessCode, RevokeAccessSubjectRequest, RevokedSessions,
};
use crate::service_door::{ServiceDoor, service_door_client};

/// Versioned path of the access-code collection.
const ACCESS_CODES_PATH: &str = "service/access-codes";
/// Versioned path of the subject revocation.
const REVOKE_SUBJECT_PATH: &str = "service/access-subjects/revoke";

/// Client for `/v1/service/access-codes` and `/v1/service/access-subjects/revoke`,
/// authenticated with a cached `client_credentials` token requested with scope
/// `loginflow.accessCodes.issue loginflow.accessCodes.read loginflow.accessCodes.revoke` (issue,
/// list, revoke): the key must hold all three, and the application must have access codes
/// enabled.
///
/// Same token handling as [`crate::ServiceUsersClient`]: when the API rejects the cached token
/// (`401` with envelope code `UNAUTHORIZED`, or no envelope) it is dropped and the request is
/// retried exactly once with a fresh one; a second `401` is
/// [`crate::LoginFlowError::Authentication`].
///
/// Cloning is cheap: clones share the HTTP connection pool and the cached token.
///
/// # Example
/// ```rust,no_run
/// use loginflow_sdk::{
///     AccessCodesClient, IssueAccessCodeRequest, LoginFlowConfig, LoginFlowResult, SubjectKind,
/// };
///
/// async fn code_for_driver(config: LoginFlowConfig, driver_id: &str) -> LoginFlowResult<String> {
///     let codes = AccessCodesClient::new(config, "rutafacil-backend", "client-secret")?;
///     let issued = codes
///         .issue(IssueAccessCodeRequest {
///             subject_kind: SubjectKind::Person,
///             external_subject: format!("driver:{driver_id}"),
///             profile: "Driver".into(),
///             display_name: None,
///             ttl_minutes: None, // the application's default
///             revoke_existing_sessions: None,
///         })
///         .await?;
///     Ok(issued.code) // `XXXX-XXXX`, returned only this once
/// }
/// ```
#[derive(Clone)]
pub struct AccessCodesClient {
    door: ServiceDoor,
}

service_door_client!(
    AccessCodesClient,
    [
        ACCESS_CODES_ISSUE_SCOPE,
        ACCESS_CODES_READ_SCOPE,
        ACCESS_CODES_REVOKE_SCOPE
    ]
);

impl AccessCodesClient {
    /// `POST /v1/service/access-codes`: issue a one-time code for a subject of the token's
    /// application. The code is in the answer and never again; a code already live for the
    /// same `external_subject` is replaced.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::Conflict`] with `code: Some("access_codes_disabled")`
    /// ([`crate::ACCESS_CODES_DISABLED_CODE`]) when the application has access codes off;
    /// [`crate::LoginFlowError::Validation`] for an invalid subject, profile, display name,
    /// a `ttl_minutes` outside `420..=7200`, or a subject kind the application does not allow;
    /// [`crate::LoginFlowError::ServiceUnavailable`] when no unique code could be drawn (retry).
    pub async fn issue(
        &self,
        request: IssueAccessCodeRequest,
    ) -> LoginFlowResult<IssuedAccessCode> {
        let url = self.door.url(ACCESS_CODES_PATH);
        self.door
            .send_for_data("Issue access code", |token| {
                self.door
                    .http()
                    .post(&url)
                    .bearer_auth(token)
                    .json(&request)
            })
            .await
    }

    /// `GET /v1/service/access-codes[?external_subject=]`: the live codes of the token's
    /// application, optionally of one subject. Never the code values.
    pub async fn list(
        &self,
        external_subject: Option<&str>,
    ) -> LoginFlowResult<Vec<AccessCodeInfo>> {
        let url = with_query(
            self.door.url(ACCESS_CODES_PATH),
            &[("external_subject", external_subject.map(str::to_string))],
        );
        self.door
            .send_for_data("List access codes", |token| {
                self.door.http().get(&url).bearer_auth(token)
            })
            .await
    }

    /// `DELETE /v1/service/access-codes/{id}`: delete a live code (`204`).
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when `id` is not a live code of this application
    /// (unknown, already redeemed, revoked or expired); [`crate::LoginFlowError::Validation`]
    /// (`code` `BAD_REQUEST`) when `id` is not a code id at all. Sessions already opened with the
    /// code stay: end them with [`revoke_subject_sessions`](Self::revoke_subject_sessions).
    pub async fn revoke(&self, id: &str) -> LoginFlowResult<()> {
        let url = self
            .door
            .url(&format!("{ACCESS_CODES_PATH}/{}", urlencoded(id)));
        self.door
            .send_for_unit("Revoke access code", |token| {
                self.door.http().delete(&url).bearer_auth(token)
            })
            .await
    }

    /// `POST /v1/service/access-subjects/revoke`: end every active session of the subject,
    /// delete its passkeys and its live code. Its next refresh fails, its phone's passkey no
    /// longer signs in (a new code is needed); an access token already issued stops within its
    /// short lifetime.
    ///
    /// # Errors
    /// [`crate::LoginFlowError::NotFound`] when the application has no subject
    /// `external_subject` (no code was ever issued for it).
    pub async fn revoke_subject_sessions(
        &self,
        external_subject: &str,
    ) -> LoginFlowResult<RevokedSessions> {
        let url = self.door.url(REVOKE_SUBJECT_PATH);
        let body = RevokeAccessSubjectRequest {
            external_subject: external_subject.to_string(),
        };
        self.door
            .send_for_data("Revoke access subject sessions", |token| {
                self.door.http().post(&url).bearer_auth(token).json(&body)
            })
            .await
    }
}
