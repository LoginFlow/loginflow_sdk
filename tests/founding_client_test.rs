//! `FoundingClient`: `POST /v1/service/organizations/founded` behind a token with
//! `loginflow.organizations.write loginflow.assignments.write`, FOR the person of an
//! `actor_token` — the contract body, the `201`/`200` answers and the typed refusals — while the
//! existing clients keep requesting only their own permissions.

mod common;

use common::{
    Reply, api_requests, config_for, envelope, error_body, service_door_server as server,
    token_request_scope,
};
use loginflow_sdk::{
    FoundOrganizationRequest, FoundingClient, FoundingError, LoginFlowError, MemberFilter,
    MembersClient, OrganizationKind, OrganizationsClient, Principal,
};
use serde_json::{Value, json};

/// The access token the person's request to the product carried.
const PERSON_TOKEN: &str = "eyJ.person.token";

const FOUNDED_PATH: &str = "/v1/service/organizations/founded";

/// A case: its name, the server's answer and the check of the error it must produce.
type Case<E> = (&'static str, Reply, fn(&E) -> bool);

/// The answer of the founding route, as the contract fixes it: the same `Organization` as
/// `ensure` and the same `Assignment` as `POST /v1/service/members`.
fn founded(created: bool) -> Value {
    json!({
        "organization": {
            "id": "org-9", "kind": "regular", "external_id": "tenant-9",
            "name": "Barbería Central", "created_at": "2026-11-13T09:00:00",
        },
        "assignment": {
            "id": "as-9", "organization_id": "org-9", "role_key": "owner",
            "principal": { "kind": "company_user", "id": "CU-1" },
            "granted_by": { "kind": "client", "id": "turnosqr-api" },
            "expires_at": null, "created_at": "2026-11-13T09:00:00",
        },
        "created": created,
    })
}

fn request() -> FoundOrganizationRequest {
    FoundOrganizationRequest {
        external_id: "tenant-9".into(),
        name: "Barbería Central".into(),
    }
}

fn client(server: &common::FakeServer) -> FoundingClient {
    FoundingClient::new(config_for(server), "turnosqr-api", "secret").expect("client")
}

/// TEST_CHARTER
/// Requirement: `found` POSTs `{external_id, name, actor_token}` to
/// `/v1/service/organizations/founded` with a token requested for exactly
/// `loginflow.organizations.write loginflow.assignments.write`, and parses the `201` answer into
/// `FoundedOrganization` (organization, founder assignment, `created: true`).
/// Oracle: the token scope, the recorded request and the returned value.
/// Risk edge: the person's token not reaching LoginFlow (`400 actor_token_required` on every
/// founding) or a scope the route refuses (`403 permission_denied`).
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: a body without `actor_token`, another path, or a token for other scopes fails
/// its assertion.
#[tokio::test]
async fn found_posts_the_contract_body_for_the_person() {
    let server = server(|req| match (req.method.as_str(), req.path()) {
        ("POST", FOUNDED_PATH) => Reply::status(201, envelope(founded(true))),
        _ => Reply::status(404, error_body("NOT_FOUND", "No route")),
    })
    .await;

    let result = client(&server).found(&request(), PERSON_TOKEN).await;

    let founded = result.expect("founded");
    assert_eq!(
        token_request_scope(&server),
        "loginflow.organizations.write loginflow.assignments.write"
    );
    let sent = api_requests(&server);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, "POST");
    assert_eq!(sent[0].path(), FOUNDED_PATH);
    assert_eq!(
        sent[0].json(),
        json!({ "external_id": "tenant-9", "name": "Barbería Central", "actor_token": PERSON_TOKEN })
    );
    assert!(founded.created);
    assert_eq!(founded.organization.id, "org-9");
    assert_eq!(founded.organization.kind, OrganizationKind::Regular);
    assert_eq!(
        founded.organization.external_id.as_deref(),
        Some("tenant-9")
    );
    assert_eq!(founded.assignment.organization_id, "org-9");
    assert_eq!(founded.assignment.role_key, "owner");
    assert_eq!(
        founded.assignment.principal,
        Principal::CompanyUser("CU-1".into())
    );
}

/// Requirement: a retry by the same founder is answered `200` with the same body and
/// `created: false`.
/// Oracle: `created` of the parsed answer.
#[tokio::test]
async fn a_retry_by_the_founder_is_not_created() {
    let server = server(|_| Reply::ok(envelope(founded(false)))).await;

    let founded = client(&server)
        .found(&request(), PERSON_TOKEN)
        .await
        .expect("retry answered");

    assert!(!founded.created);
    assert_eq!(founded.organization.id, "org-9");
}

/// TEST_CHARTER
/// Requirement: the four refusals a product answers differently are typed:
/// `409 organization_exists`, `409 founder_role_not_configured`, `429 founding_rate_limited`
/// (with the `Retry-After` seconds) and `403 key_role_not_grantable`.
/// Oracle: the `FoundingError` variant of each answer.
/// Risk edge: a product telling "pick another id" apart from "LoginFlow is misconfigured" or "try
/// tomorrow" by parsing messages, or retrying a rate limit at once.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: no classification leaves every refusal as `FoundingError::LoginFlow`; a
/// classification by status alone confuses the two `409`s.
#[tokio::test]
async fn the_founding_refusals_are_typed() {
    let cases: [Case<FoundingError>; 4] = [
        (
            "organization_exists",
            Reply::status(409, error_body("organization_exists", "Exists")),
            |e| matches!(e, FoundingError::OrganizationExists),
        ),
        (
            "founder_role_not_configured",
            Reply::status(409, error_body("founder_role_not_configured", "No role")),
            |e| matches!(e, FoundingError::FounderRoleNotConfigured),
        ),
        (
            "founding_rate_limited",
            Reply::status(429, error_body("founding_rate_limited", "Too many"))
                .with_header("Retry-After", "3600"),
            |e| {
                matches!(
                    e,
                    FoundingError::RateLimited {
                        retry_after_secs: Some(3600)
                    }
                )
            },
        ),
        (
            "key_role_not_grantable",
            Reply::status(403, error_body("key_role_not_grantable", "Not listed")),
            |e| matches!(e, FoundingError::KeyRoleNotGrantable),
        ),
    ];
    for (case, reply, expected) in cases {
        let server = server(move |_| reply.clone()).await;

        let result = client(&server).found(&request(), PERSON_TOKEN).await;

        match result {
            Err(error) => assert!(expected(&error), "{case}: {error:?}"),
            Ok(answer) => panic!("{case}: expected a refusal, got {answer:?}"),
        }
    }
}

/// Requirement: every other refusal keeps the server's code in `FoundingError::LoginFlow`:
/// `invalid_actor_token` (`401`, never retried as a rejected key token), `permission_denied`,
/// `member_not_found`, a validation `422` and a generic `429`.
/// Oracle: the inner `LoginFlowError` variant and `code`, and one API request for the `401`.
#[tokio::test]
async fn other_refusals_keep_the_server_code() {
    let cases: [Case<LoginFlowError>; 5] = [
        (
            "invalid_actor_token",
            Reply::status(401, error_body("invalid_actor_token", "Refused")),
            |e| matches!(e, LoginFlowError::Authentication { code: Some(c), .. } if c == "invalid_actor_token"),
        ),
        (
            "permission_denied",
            Reply::status(403, error_body("permission_denied", "Denied")),
            |e| matches!(e, LoginFlowError::Authorization { code: Some(c), .. } if c == "permission_denied"),
        ),
        (
            "member_not_found",
            Reply::status(404, error_body("member_not_found", "No member")),
            |e| matches!(e, LoginFlowError::NotFound { code: Some(c), .. } if c == "member_not_found"),
        ),
        (
            "VALIDATION_ERROR",
            Reply::status(422, error_body("VALIDATION_ERROR", "Bad name")),
            |e| matches!(e, LoginFlowError::Validation { code: Some(c), .. } if c == "VALIDATION_ERROR"),
        ),
        (
            "RATE_LIMITED",
            Reply::status(429, error_body("RATE_LIMITED", "Slow down")),
            |e| matches!(e, LoginFlowError::RateLimit { code: Some(c), .. } if c == "RATE_LIMITED"),
        ),
    ];
    for (case, reply, expected) in cases {
        let server = server(move |_| reply.clone()).await;

        let result = client(&server).found(&request(), PERSON_TOKEN).await;

        match result {
            Err(FoundingError::LoginFlow(error)) => assert!(expected(&error), "{case}: {error:?}"),
            other => panic!("{case}: expected FoundingError::LoginFlow, got {other:?}"),
        }
        assert_eq!(api_requests(&server).len(), 1, "{case}: sent once");
    }
}

/// TEST_CHARTER
/// Requirement: adding the founding call changes no scope an existing client requests: a key
/// without `loginflow.assignments.write` keeps working with `OrganizationsClient`, and
/// `MembersClient` still asks for its own two permissions only.
/// Oracle: the `scope` of each client's token request.
/// Risk edge: a key configured for organizations only refused at the token endpoint
/// (`invalid_scope`) after an SDK upgrade.
/// Layer: integration against the in-process `FakeServer`.
/// Counterfactual: putting `found` on `OrganizationsClient` (and its scopes) fails the first
/// assertion.
#[tokio::test]
async fn the_existing_clients_keep_their_scopes() {
    let organizations_server =
        server(|_| Reply::ok(envelope(json!({ "items": [], "total": 0 })))).await;
    OrganizationsClient::new(config_for(&organizations_server), "turnosqr-api", "secret")
        .expect("client")
        .find_by_external_id("tenant-9")
        .await
        .expect("find");
    let members_server = server(|_| Reply::ok(envelope(json!({ "items": [], "total": 0 })))).await;
    MembersClient::new(config_for(&members_server), "turnosqr-api", "secret")
        .expect("client")
        .list(&MemberFilter::default())
        .await
        .expect("list");

    assert_eq!(
        token_request_scope(&organizations_server),
        "loginflow.organizations.read loginflow.organizations.write"
    );
    assert_eq!(
        token_request_scope(&members_server),
        "loginflow.assignments.read loginflow.assignments.write"
    );
}

/// Requirement: the client's `Debug` shows no secret.
#[test]
fn the_client_debug_shows_no_secret() {
    let config = loginflow_sdk::LoginFlowConfig {
        base_url: "https://api.loginflow.test".into(),
        api_version: 1,
        company_id: common::COMPANY_ID.into(),
        api_audience: common::API_AUDIENCE.into(),
        timeout_secs: 5,
        user_agent: None,
        issuer: common::ISSUER.into(),
        jwks_url: None,
        jwks_cache_ttl_secs: 600,
        resource_base_url: None,
    };
    let founding = FoundingClient::new(config, "turnosqr-api", "very-secret").expect("client");

    let printed = format!("{founding:?}");

    assert!(printed.starts_with("FoundingClient"), "{printed}");
    assert!(!printed.contains("very-secret"), "{printed}");
}
