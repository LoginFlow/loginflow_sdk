//! Models of the machine-to-machine user management API (`/v1/service/users`), used by
//! [`crate::ServiceUsersClient`]. The company and application are never part of a request:
//! the server takes them from the `client_credentials` token.

use serde::{Deserialize, Serialize};

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
    /// Not sent: the person already had an account in the application.
    NotNeeded,
    /// A status this SDK version does not know.
    #[serde(other)]
    Unknown,
}

/// `POST /v1/service/users` body. The account is created active; the user activates it by
/// signing in with an email OTP and then sets a password (`/v1/user/change-password`). What the
/// user may do in the application is not part of the account: grant it a role in an
/// organization with [`crate::MembersClient::grant`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateServiceUserRequest {
    pub email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Email the application's invitation (the `account_invitation` template) once the user
    /// exists. Not sent on the wire when `false`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub send_invitation: bool,
}

/// `PATCH /v1/service/users/{id}` body: `is_active` is the one field the route accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetServiceUserActiveRequest {
    pub is_active: bool,
}

fn is_false(value: &bool) -> bool {
    !value
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
