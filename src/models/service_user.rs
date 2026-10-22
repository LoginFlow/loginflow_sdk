//! Models of the machine-to-machine user management API (`/v1/service/users`), used by
//! [`crate::ServiceUsersClient`]. The company and application are never part of a request:
//! the server takes them from the `client_credentials` token.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The `client_credentials` scope `/v1/service/users` requires.
pub const USERS_MANAGE_SCOPE: &str = "users:manage";

/// Role a service-managed user can be given. `master` is never assignable through this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceUserRole {
    User,
    AppAdmin,
}

impl fmt::Display for ServiceUserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ServiceUserRole::User => "user",
            ServiceUserRole::AppAdmin => "app_admin",
        })
    }
}

/// A user of the token's company and application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUser {
    /// `company_users.id`: the same value as the `sub` of this person's access tokens.
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    /// `user` or `app_admin`. Kept as the server's string so an unexpected value never fails
    /// a whole listing; compare against [`ServiceUserRole`]'s `Display`.
    pub role: String,
    pub is_active: bool,
    pub email_verified: bool,
    /// UTC date-time, ISO 8601 WITHOUT an offset, as the server's `NaiveDateTime` serializes it
    /// (`2026-10-21T09:00:00` or `2026-10-21T09:00:00.123456`). Not RFC 3339: append `Z` before
    /// parsing it as one.
    pub created_at: String,
    /// Same format as `created_at`; `None` until the user first signs in.
    #[serde(default)]
    pub last_login_at: Option<String>,
    /// Only in the answer of [`crate::ServiceUsersClient::create`] with `send_invitation: true`:
    /// what happened to the invitation email. `None` everywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<InvitationStatus>,
}

/// Outcome of the invitation email of a create. The user is created whatever it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    /// Handed to the application's email server.
    Sent,
    /// Not sent: no email server configured for the application, or the delivery failed.
    Failed,
    /// Not sent: too many invitations to this email in this application recently.
    RateLimited,
    /// A status this SDK version does not know.
    #[serde(other)]
    Unknown,
}

/// `POST /v1/service/users` body. The account is created active; the user activates it by
/// signing in with an email OTP and then sets a password (`/v1/user/change-password`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateServiceUserRequest {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    pub role: ServiceUserRole,
    /// Email the application's invitation (the `account_invitation` template) once the user
    /// exists. Not sent on the wire when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub send_invitation: bool,
}

/// `PATCH /v1/service/users/{id}` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetServiceUserActiveRequest {
    pub is_active: bool,
}

/// `PATCH /v1/service/users/{id}` body with any of its fields; at least one must be set (the
/// server answers `422` to an empty one). Absent fields are left as they are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateServiceUserRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// The role of the membership in the token's application (`master` is never assignable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<ServiceUserRole>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// `POST /v1/service/users/{id}/email-change` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUserEmailChangeRequest {
    pub new_email: String,
}

/// `202` answer to an email-change request: a code was sent to the NEW address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailChangeRequested {
    /// When the code stops being accepted: UTC date-time, ISO 8601 WITHOUT an offset (same
    /// format as [`ServiceUser::created_at`]).
    pub expires_at: String,
}

/// `200` answer to `DELETE /v1/service/users/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceUserDeleted {
    /// The deleted membership's user id (`company_users.id`).
    pub id: String,
    /// Whether the person's profile went too: it was their last account anywhere and nothing
    /// else depended on it.
    pub profile_deleted: bool,
}

/// `POST /v1/service/users/{id}/email-change/confirm` body.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmServiceUserEmailChangeRequest {
    /// The code emailed to the new address.
    pub code: String,
}

debug_redacted!(ConfirmServiceUserEmailChangeRequest {
    public: [],
    secret: [code]
});
