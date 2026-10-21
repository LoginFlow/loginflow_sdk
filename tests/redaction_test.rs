//! `Debug` output must never contain passwords, secrets or tokens.

use loginflow_sdk::{ChangePasswordRequest, IssuedAccessCode, VerifyTotpSetupRequest};

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

/// An issued access code is a bearer secret until redeemed: logging the answer of
/// `AccessCodesClient::issue` must not log the code.
#[test]
fn issued_access_code_redacts_the_code() {
    let debug = format!(
        "{:?}",
        IssuedAccessCode {
            id: "code-1".into(),
            code: SECRET.into(),
            expires_at: "2026-10-22T09:00:00".into(),
            subject_kind: "device".into(),
            external_subject: "kiosk:7".into(),
            profile: "Kiosk".into(),
        }
    );
    assert!(debug.contains("kiosk:7"), "public fields kept: {debug}");
    assert_redacted(debug);
}
