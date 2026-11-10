//! `MachineTokens`: the calling side of machine access — `client_credentials` with `resource` =
//! the receiving API's audience, cached until shortly before expiry, single-flight refresh, the
//! secret never printed.

mod common;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{FakeServer, RecordedRequest, Reply};
use loginflow_sdk::{ClientSecret, LoginFlowError, MachineTokens};
use reqwest::Client;
use serde_json::json;

const TOKEN_PATH: &str = "/oauth2/token";
const RESOURCE: &str = "https://api.keel.example";
const CLIENT_ID: &str = "payments-caller-1a2b3c4d";
const SECRET: &str = "lfsk_test-secret-value";

fn tokens(server: &FakeServer) -> MachineTokens {
    MachineTokens::new(
        Client::new(),
        format!("{}{TOKEN_PATH}", server.base_url),
        CLIENT_ID,
        ClientSecret::from(SECRET),
        RESOURCE,
    )
}

fn issued(expires_in: i64) -> Reply {
    Reply::ok(
        json!({ "access_token": "machine-token-1", "token_type": "Bearer", "expires_in": expires_in })
            .to_string(),
    )
}

/// The decoded form fields of a recorded `application/x-www-form-urlencoded` body.
fn form(request: &RecordedRequest) -> Vec<(String, String)> {
    url_decoded_pairs(&request.body)
}

fn url_decoded_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).expect("utf8")
}

/// TEST_CHARTER
/// Requirement: `MachineTokens::access_token` asks `POST /oauth2/token` with
/// `grant_type=client_credentials` and `resource` = the receiving API's audience, authenticated
/// with `client_secret_basic`, and caches the token: three calls, one request.
/// Oracle: the form fields and `Authorization` header the fake token endpoint recorded, and its
/// hit count.
/// Risk edge: a token for LoginFlow itself (no `resource`) that the receiving API refuses, or a
/// token request on every outgoing call.
/// Layer: real HTTP over loopback against the in-process `FakeServer`.
/// Counterfactual: dropping `resource` or the cache fails the field or the `hits == 1` assertion.
#[tokio::test]
async fn machine_tokens_ask_for_the_api_audience_and_are_cached() {
    let server = FakeServer::start(|_| issued(600)).await;
    let tokens = tokens(&server);

    let first = tokens.access_token().await.expect("first");
    let second = tokens.access_token().await.expect("second");
    let header = tokens.authorization_header().await.expect("header");

    assert_eq!(first, "machine-token-1");
    assert_eq!(second, "machine-token-1");
    assert_eq!(header, "Bearer machine-token-1");
    assert_eq!(server.hits(TOKEN_PATH), 1, "three calls share one token");
    let request = server.last();
    let fields = form(&request);
    assert!(fields.contains(&("grant_type".into(), "client_credentials".into())));
    assert!(
        fields.contains(&("resource".into(), RESOURCE.into())),
        "{fields:?}"
    );
    let expected_basic = format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:{SECRET}")));
    assert_eq!(
        request.header("authorization"),
        Some(expected_basic.as_str())
    );
}

/// Requirement: a token at its expiry margin (30 s) is fetched again.
/// Oracle: two token requests for two calls when `expires_in` is 30.
/// Counterfactual: a cache that ignores `expires_in` serves the first token twice (`hits == 1`).
#[tokio::test]
async fn machine_tokens_refresh_a_token_about_to_expire() {
    let server = FakeServer::start(|_| issued(30)).await;
    let tokens = tokens(&server);

    tokens.access_token().await.expect("first");
    tokens.access_token().await.expect("second");

    assert_eq!(server.hits(TOKEN_PATH), 2);
}

/// Requirement: concurrent callers past an empty cache share ONE token request (single-flight).
/// Oracle: the fake token endpoint's hit count after eight concurrent calls on a slow answer.
/// Counterfactual: no shared lock around the fetch makes eight requests.
#[tokio::test]
async fn machine_tokens_refresh_is_single_flight() {
    let server = FakeServer::start(|_| issued(600).delayed(Duration::from_millis(150))).await;
    let tokens = tokens(&server);

    let calls: Vec<_> = (0..8)
        .map(|_| {
            let tokens = tokens.clone();
            tokio::spawn(async move { tokens.access_token().await })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.expect("join").expect("token"), "machine-token-1");
    }

    assert_eq!(server.hits(TOKEN_PATH), 1);
}

/// Requirement: `scope` narrows the token when set.
/// Oracle: the `scope` form field.
#[tokio::test]
async fn machine_tokens_send_the_scope_when_set() {
    let server = FakeServer::start(|_| issued(600)).await;
    let tokens = tokens(&server).with_scope("keel.notifications.send");

    tokens.access_token().await.expect("token");

    let fields = form(&server.last());
    assert!(fields.contains(&("scope".into(), "keel.notifications.send".into())));
    assert!(fields.contains(&("resource".into(), RESOURCE.into())));
}

/// TEST_CHARTER
/// Requirement: the refusals LoginFlow documents for a machine token request keep their RFC 6749
/// `error` code: `400 invalid_target` (no grant on that API), `401 invalid_client`.
/// Oracle: the `code` of the returned `LoginFlowError`.
/// Risk edge: a caller that cannot tell "not granted" from "wrong secret".
/// Layer: real HTTP against the `FakeServer`.
/// Counterfactual: reading only the LoginFlow envelope (`error.code`) leaves `code` `None`.
#[tokio::test]
async fn machine_token_refusals_keep_the_oauth_error_code() {
    let server = FakeServer::start(|_| {
        Reply::status(
            400,
            json!({ "error": "invalid_target", "error_description": "the resource is not an API this client may request tokens for" })
                .to_string(),
        )
    })
    .await;

    let refused = tokens(&server).access_token().await;

    match refused {
        Err(LoginFlowError::Validation { code, message }) => {
            assert_eq!(code.as_deref(), Some("invalid_target"));
            assert!(message.contains("not an API"), "{message}");
        }
        other => panic!("expected a validation error, got {other:?}"),
    }

    server.set_responder(|_| Reply::status(401, json!({ "error": "invalid_client" }).to_string()));
    match tokens(&server).access_token().await {
        Err(LoginFlowError::Authentication { code, .. }) => {
            assert_eq!(code.as_deref(), Some("invalid_client"));
        }
        other => panic!("expected an authentication error, got {other:?}"),
    }
}

/// Requirement: neither `MachineTokens` nor `ClientSecret` ever prints the secret.
/// Oracle: their `Debug` output.
#[tokio::test]
async fn the_secret_is_never_printed() {
    let server = FakeServer::start(|_| issued(600)).await;
    let tokens = tokens(&server);

    let printed = format!("{tokens:?} {:?}", ClientSecret::from(SECRET));

    assert!(!printed.contains(SECRET), "{printed}");
    assert!(printed.contains(CLIENT_ID));
    assert!(printed.contains(RESOURCE));
    assert!(printed.contains("[redacted]"));
}
