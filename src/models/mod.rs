//! Data models for LoginFlow SDK
//!
//! Contains request/response models for all LoginFlow API endpoints.

/// Placeholder printed instead of a secret by the redacting `Debug` impls.
pub const REDACTED: &str = "[REDACTED]";

/// Implement `Debug` printing `public` fields and `[REDACTED]` for `secret` ones.
///
/// Every field must be listed in one of the two groups: the struct is
/// destructured, so adding a field without classifying it does not compile.
macro_rules! debug_redacted {
    ($ty:ident { public: [$($field:ident),* $(,)?], secret: [$($secret:ident),* $(,)?] $(,)? }) => {
        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let $ty { $($field,)* $($secret: _,)* } = self;
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($field), $field))*
                    $(.field(stringify!($secret), &$crate::models::REDACTED))*
                    .finish()
            }
        }
    };
}
/// Re-exported for the multi-tenant models (models in this module see it by textual scope).
#[cfg(feature = "multi-tenant")]
pub(crate) use debug_redacted;

mod account_recovery;
mod auth;
mod delegated_auth;
mod jwt;
mod oauth;
mod password;
mod totp;
mod user_account;
mod user_profile;

pub use account_recovery::*;
pub use auth::*;
pub use delegated_auth::*;
pub use jwt::*;
pub use oauth::*;
pub use password::*;
pub use totp::*;
pub use user_account::*;
pub use user_profile::*;
