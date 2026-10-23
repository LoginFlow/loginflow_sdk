//! `LoginFlowErrorResponse`: the API's error envelope exactly as `loginflow_api` writes it —
//! `details` is text for a validation error and a JSON object for a coded refusal, and the `meta`
//! of an error a handler returned with `?` has `request_id` and `path` set to `null`.

use loginflow_sdk::LoginFlowErrorResponse;
use serde_json::json;

/// TEST_CHARTER
/// Requirement: every error envelope of the API parses into `LoginFlowErrorResponse`: `details`
/// absent, text (`VALIDATION_ERROR`) or an object (`409 CONFLICT` with its `blockers`, a coded
/// refusal), and a `meta` whose `request_id`/`path` are `null` (`AppResponse::error_response`,
/// `docs/api/response-contracts.md`).
/// Oracle: `serde_json::from_value` succeeds and keeps `code`, `message`, `details` and the
/// `meta` values.
/// Risk edge: a product that parses an error body with the SDK's own model fails on the very
/// errors it needs to explain (a blocked delete, a refused grant).
/// Layer: the public model's serde contract, with the API's bodies byte for byte.
/// Counterfactual: `details: Option<String>` fails the object case; `request_id: String` fails
/// the `null` meta.
#[test]
fn every_error_envelope_of_the_api_parses() {
    let blocked = json!({
        "error": {
            "code": "CONFLICT",
            "message": "The account cannot be permanently deleted because other data depends on it",
            "details": { "allowed": false, "blockers": [{ "kind": "company_owner", "count": 1 }] },
        },
        "meta": { "status": 409, "timestamp": "2026-10-24T09:00:00Z", "request_id": null, "path": null },
    });
    let invalid = json!({
        "error": { "code": "VALIDATION_ERROR", "message": "Some fields are invalid.", "details": "The passwords do not match" },
        "meta": { "status": 422, "timestamp": "2026-10-24T09:00:00Z", "request_id": "req-1", "path": "/v1/user/change-password" },
    });
    let not_found = json!({
        "error": { "code": "NOT_FOUND", "message": "User not found" },
        "meta": { "status": 404, "timestamp": "2026-10-24T09:00:00Z", "request_id": "req-2", "path": "/v1/service/users/x" },
    });

    for body in [blocked, invalid, not_found] {
        let parsed: LoginFlowErrorResponse = serde_json::from_value(body.clone())
            .unwrap_or_else(|e| panic!("{body} does not parse: {e}"));
        assert_eq!(
            serde_json::to_value(&parsed).expect("serialize"),
            body,
            "every field kept"
        );
    }
}
