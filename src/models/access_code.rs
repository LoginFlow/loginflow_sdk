//! Models of the machine-to-machine access-code API (`/v1/service/access-codes`,
//! `/v1/service/access-subjects`), used by [`crate::AccessCodesClient`]. The company and
//! application are never part of a request: the server takes them from the
//! `client_credentials` token.

use std::fmt;

use serde::{Deserialize, Serialize};

/// `error.code` of the `409` answered when access codes are disabled for the token's
/// application ([`crate::LoginFlowError::Conflict`]).
pub const ACCESS_CODES_DISABLED_CODE: &str = "access_codes_disabled";

/// Who or what an access-code subject is. A `device` (a kiosk, a shared tablet) is still a
/// subject with its own sessions; the kind travels as the `subject_kind` token claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// A person (a driver, a student).
    Person,
    /// A device (a kiosk, a shared tablet).
    Device,
}

impl SubjectKind {
    /// The wire value (`person` / `device`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            SubjectKind::Person => "person",
            SubjectKind::Device => "device",
        }
    }

    /// Parse a wire value; `None` for anything else.
    pub fn parse(value: &str) -> Option<Self> {
        [SubjectKind::Person, SubjectKind::Device]
            .into_iter()
            .find(|kind| kind.as_str() == value)
    }
}

impl fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `POST /v1/service/access-codes` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueAccessCodeRequest {
    /// `person` or `device`; one of the application's allowed subject kinds.
    pub subject_kind: SubjectKind,
    /// The issuer's own id of the subject: at most 128 characters of `[A-Za-z0-9:._-]`. Comes
    /// back as the `ext_sub` claim of the subject's tokens.
    pub external_subject: String,
    /// Issuer-defined profile (e.g. `Driver`, `Kiosk`), at most 40 characters. Comes back as
    /// the `ext_profile` claim.
    pub profile: String,
    /// Optional label (at most 80 characters); no PII is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Validity in minutes, `420..=7200` (7 hours to 5 days); `None` uses the application's
    /// default. Out of range is a `422` ([`crate::LoginFlowError::Validation`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_minutes: Option<u32>,
    /// `Some(true)` also ends every active session of the subject and deletes its passkeys, so
    /// the new code starts over on a new phone. `None`/`Some(false)` keeps them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_existing_sessions: Option<bool>,
}

/// `201` answer of `POST /v1/service/access-codes`: the only time the code is ever returned.
/// Hand `code` to the person or device and drop it; `Debug` redacts it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedAccessCode {
    /// Id of the live code (for [`crate::AccessCodesClient::revoke`]).
    pub id: String,
    /// `XXXX-XXXX`: 8 characters of `23456789ABCDEFGHJKMNPQRSTUVWXYZ`. Typed back case- and
    /// dash-insensitively.
    pub code: String,
    /// UTC date-time, ISO 8601 WITHOUT an offset (the server's `NaiveDateTime`, e.g.
    /// `2026-10-21T09:00:00`). Append `Z` before parsing it as RFC 3339.
    pub expires_at: String,
    /// `person` or `device`; compare against [`SubjectKind`]'s `Display`.
    pub subject_kind: String,
    /// The issuer's own id of the subject, as sent.
    pub external_subject: String,
    /// The issuer-defined profile, as sent (trimmed).
    pub profile: String,
}

debug_redacted!(IssuedAccessCode {
    public: [id, expires_at, subject_kind, external_subject, profile],
    secret: [code]
});

/// A live code as listed by `GET /v1/service/access-codes`: never the code itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessCodeInfo {
    /// Id of the live code (for [`crate::AccessCodesClient::revoke`]).
    pub id: String,
    /// `person` or `device`. Kept as the server's string so an unexpected value never fails a
    /// whole listing; compare against [`SubjectKind`]'s `Display`.
    pub subject_kind: String,
    /// The issuer's own id of the subject.
    pub external_subject: String,
    /// The issuer-defined profile.
    pub profile: String,
    /// The optional label given at issue time.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The client_id (or panel admin) that issued the code.
    pub issued_by: String,
    /// Same format as [`IssuedAccessCode::expires_at`].
    pub issued_at: String,
    /// Same format as [`IssuedAccessCode::expires_at`].
    pub expires_at: String,
}

/// `POST /v1/service/access-subjects/revoke` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAccessSubjectRequest {
    /// The issuer's own id of the subject whose sessions end.
    pub external_subject: String,
}

/// Answer of `POST /v1/service/access-subjects/revoke`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokedSessions {
    /// How many active sessions of the subject were ended.
    pub revoked_sessions: u64,
}
