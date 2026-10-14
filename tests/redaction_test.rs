//! `Debug` output must never contain passwords or tokens.

use loginflow_sdk::{
    ApplicationInfo, ChangePasswordRequest, CompanyInfo, CompleteResetRequest, LoginRequest,
    LoginResponse, OtpLoginResponse, RefreshTokenResponse, RegisterRequest, SessionInfo, UserInfo,
    ValidateDelegatedTokenRequest,
};

const SECRET: &str = "s3cr3t-value-XYZ";

fn assert_redacted(debug: String) {
    assert!(
        !debug.contains(SECRET),
        "secret leaked in Debug output: {debug}"
    );
    assert!(debug.contains("[REDACTED]"), "no redaction marker: {debug}");
}

fn user() -> UserInfo {
    UserInfo {
        id: "u-1".into(),
        email: Some("u@example.com".into()),
        first_name: None,
        last_name: None,
        role: Some("user".into()),
        company_id: Some("c-1".into()),
    }
}

fn company() -> CompanyInfo {
    CompanyInfo {
        id: "c-1".into(),
        name: "C".into(),
        tax_id: None,
        email: None,
    }
}

fn session() -> SessionInfo {
    SessionInfo {
        id: "s-1".into(),
        device_info: None,
        ip_address: None,
        user_agent: None,
        location: None,
        created_at: "2026-10-15T00:00:00".into(),
        expires_at: "2026-10-15T00:15:00".into(),
        refresh_expires_at: None,
    }
}

fn application() -> ApplicationInfo {
    ApplicationInfo {
        id: "a-1".into(),
        name: "App".into(),
        status: "active".into(),
    }
}

#[test]
fn credential_requests_redact_passwords() {
    assert_redacted(format!(
        "{:?}",
        RegisterRequest {
            email: "u@example.com".into(),
            first_name: "U".into(),
            last_name: "T".into(),
            password: SECRET.into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        LoginRequest {
            email: "u@example.com".into(),
            password: SECRET.into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        ChangePasswordRequest {
            current_password: SECRET.into(),
            new_password: SECRET.into(),
            confirm_password: SECRET.into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        CompleteResetRequest {
            email: "u@example.com".into(),
            code: SECRET.into(),
            new_password: SECRET.into(),
            confirm_password: SECRET.into()
        }
    ));
}

#[test]
fn delegated_token_request_redacts_the_token_but_not_the_creator() {
    let debug = format!(
        "{:?}",
        ValidateDelegatedTokenRequest {
            code: SECRET.into(),
            email: "creator@example.com".into(),
        }
    );
    assert_redacted(debug.clone());
    assert!(debug.contains("creator@example.com"), "{debug}");
}

#[test]
fn session_responses_redact_tokens() {
    let login = LoginResponse {
        jwt: SECRET.into(),
        refresh_token: SECRET.into(),
        expires_in: 900,
        user: user(),
        company: company(),
        session: session(),
        application: application(),
    };
    assert_redacted(format!("{login:?}"));
    assert!(
        format!("{login:?}").contains("u@example.com"),
        "non-secret fields stay visible"
    );

    assert_redacted(format!(
        "{:?}",
        OtpLoginResponse {
            success: true,
            message: "ok".into(),
            jwt: SECRET.into(),
            refresh_token: SECRET.into(),
            expires_in: 900,
            user: user(),
            company: company(),
            session: session(),
            application: application(),
            metadata: None,
        }
    ));
    assert_redacted(format!(
        "{:?}",
        RefreshTokenResponse {
            access_token: SECRET.into(),
            refresh_token: SECRET.into(),
            expires_at: "2026-10-15T00:15:00".into(),
            refresh_expires_at: "2026-10-22T00:00:00".into(),
        }
    ));
}

#[cfg(feature = "multi-tenant")]
#[test]
fn multi_tenant_requests_redact_secrets() {
    use loginflow_sdk::multi_tenant::{
        MultiTenantCompleteResetRequest, MultiTenantCompleteResetWithTokenRequest,
        MultiTenantLoginRequest, MultiTenantRegisterRequest,
    };

    assert_redacted(format!(
        "{:?}",
        MultiTenantLoginRequest {
            email: "u@example.com".into(),
            password: SECRET.into(),
            company_id: "c".into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        MultiTenantRegisterRequest {
            email: "u@example.com".into(),
            first_name: "U".into(),
            last_name: "T".into(),
            password: SECRET.into(),
            company_id: "c".into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        MultiTenantCompleteResetRequest {
            email: "u@example.com".into(),
            code: SECRET.into(),
            new_password: SECRET.into(),
            confirm_password: SECRET.into(),
            company_id: "c".into()
        }
    ));
    assert_redacted(format!(
        "{:?}",
        MultiTenantCompleteResetWithTokenRequest {
            email: "u@example.com".into(),
            reset_token: SECRET.into(),
            new_password: SECRET.into(),
            confirm_password: SECRET.into(),
            company_id: "c".into()
        }
    ));
}
