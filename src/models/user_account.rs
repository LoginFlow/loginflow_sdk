//! User account models for LoginFlow SDK

use serde::{Deserialize, Serialize};

/// Full user account response (profile + account data)
///
/// Returned by `GET /user-accounts/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullUserAccountResponse {
    // From user_profiles
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    // From user_accounts
    pub user_id: String,
    pub company_id: String,
    pub application_id: String,
    pub auth_type: String,
    pub role: String,
    pub email_verified: bool,
    pub is_active: bool,
    pub failed_login_attempts: i32,
    pub last_login_at: Option<String>,
    pub last_successful_login: Option<String>,
    pub last_failed_attempt: Option<String>,
    pub lock_until: Option<String>,
    pub lock_level: Option<i32>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
    pub is_deleted: bool,
}

/// User account response (account-only fields)
///
/// Returned by `PATCH /user-accounts/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccountResponse {
    pub id: String,
    pub user_id: String,
    pub company_id: String,
    pub application_id: String,
    pub auth_type: String,
    pub role: String,
    pub email_verified: bool,
    pub is_active: bool,
    pub failed_login_attempts: i32,
    pub last_login_at: Option<String>,
    pub lock_until: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub lock_level: Option<i32>,
    pub last_failed_attempt: Option<String>,
    pub last_successful_login: Option<String>,
    pub deleted_at: Option<String>,
    pub is_deleted: bool,
}

/// Request DTO for updating a user account
///
/// Used with `PATCH /user-accounts/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserAccountRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Generic response for operations (soft-delete, restore, hard-delete)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResponse {
    pub success: bool,
    pub message: String,
}
