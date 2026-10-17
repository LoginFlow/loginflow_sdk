//! `Debug` output must never contain passwords, secrets or tokens.

use loginflow_sdk::{ChangePasswordRequest, VerifyTotpSetupRequest};

const SECRET: &str = "s3cr3t-value-XYZ";

fn assert_redacted(debug: String) {
    assert!(
        !debug.contains(SECRET),
        "secret leaked in Debug output: {debug}"
    );
    assert!(debug.contains("[REDACTED]"), "no redaction marker: {debug}");
}

#[test]
fn change_password_request_redacts_the_new_password() {
    assert_redacted(format!(
        "{:?}",
        ChangePasswordRequest {
            new_password: SECRET.into()
        }
    ));
}

#[test]
fn totp_setup_verification_redacts_the_code() {
    assert_redacted(format!(
        "{:?}",
        VerifyTotpSetupRequest {
            code: SECRET.into()
        }
    ));
}
