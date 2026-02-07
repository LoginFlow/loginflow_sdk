//! User profile models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// User profile response
///
/// Returned by `GET /user-profiles/{id}`, `GET /user-profiles/search?email=`,
/// and `PATCH /user-profiles/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
    pub is_deleted: bool,
}

/// Request DTO for updating a user profile
///
/// Used with `PATCH /user-profiles/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserProfileRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}
