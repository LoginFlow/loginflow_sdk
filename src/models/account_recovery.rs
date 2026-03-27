//! Account recovery models for LoginFlow SDK
//!
//! Used when a user loses access to their email and needs to request
//! an account recovery through support.

use serde::{Deserialize, Serialize};

/// Request for account recovery
///
/// The SDK automatically adds `company_id` and `application_id` from config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecoveryRequest {
    /// Email the user lost access to
    pub old_email: String,
    /// New email the user wants to use
    pub new_email: String,
    /// Reason for losing access to the old email
    pub reason: String,
    /// Full name (optional, for identity verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    /// Contact phone number (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Additional information to help verify identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
    /// Email template language ("es", "en"). Defaults to "es" if not provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Internal request sent to the LoginFlow API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LoginFlowAccountRecoveryRequest {
    pub old_email: String,
    pub new_email: String,
    pub company_id: String,
    pub application_id: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Response from account recovery request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecoveryResponse {
    pub success: bool,
    pub message: String,
    /// Ticket/request ID created for tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_id: Option<String>,
    /// Support email where the request was sent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_contact: Option<String>,
}
