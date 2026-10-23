//! Account recovery models for LoginFlow SDK
//!
//! Used when a user loses access to their email and needs to request
//! an account recovery through support.

use serde::{Deserialize, Serialize};

/// Request for account recovery
///
/// The SDK adds `company_id` from config. `application_id` is the application the user signs
/// in to: a resource server's config names its API, not an application, so the caller says
/// which one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecoveryRequest {
    /// Application ID (`APP-...`) of the account to recover
    pub application_id: String,
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

/// Response from account recovery request.
///
/// Identical whether or not a ticket reached support (the old email has no
/// account, or the new email is taken): a fresh `ticket_id` is always returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecoveryResponse {
    pub success: bool,
    pub message: String,
    /// Ticket/request ID for tracking
    pub ticket_id: String,
    /// The company's support email
    pub support_contact: String,
}
