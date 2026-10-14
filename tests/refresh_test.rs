//! Refresh is single-flight per session and refresh token: the server revokes
//! a session when a rotated refresh token is presented again, so concurrent
//! callers holding the same token must share one request.

mod common;

use std::time::Duration;

use common::{FakeServer, Reply, client_for, envelope};
use loginflow_sdk::RefreshTokenRequest;
use serde_json::json;

const REFRESH_PATH: &str = "/v1/public/refresh-token";

fn rotated(refresh_token: &str) -> String {
    envelope(json!({
        "access_token": "access.new",
        "refresh_token": refresh_token,
        "expires_at": "2026-10-15T00:15:00",
        "refresh_expires_at": "2026-10-22T00:00:00"
    }))
}

fn request(refresh_token: &str) -> RefreshTokenRequest {
    RefreshTokenRequest {
        refresh_token: refresh_token.into(),
        session_id: "s-1".into(),
    }
}

#[tokio::test]
async fn concurrent_refreshes_of_one_token_share_one_request() {
    let server = FakeServer::start(|_| {
        Reply::ok(rotated("refresh.new")).delayed(Duration::from_millis(200))
    })
    .await;
    let client = client_for(&server);

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let client = client.clone();
            tokio::spawn(async move { client.refresh_token(request("refresh.old")).await })
        })
        .collect();
    let mut results = Vec::new();
    for call in calls {
        results.push(call.await.expect("task"));
    }

    assert_eq!(server.hits(REFRESH_PATH), 1);
    for result in results {
        assert_eq!(result.expect("refresh").refresh_token, "refresh.new");
    }
}

#[tokio::test]
async fn different_refresh_tokens_are_never_shared() {
    let server = FakeServer::start(|req| {
        let presented = req.json()["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        Reply::ok(rotated(&format!("{presented}.next"))).delayed(Duration::from_millis(200))
    })
    .await;
    let client = client_for(&server);

    let (first, second) = tokio::join!(
        client.refresh_token(request("refresh.a")),
        client.refresh_token(request("refresh.b")),
    );

    assert_eq!(server.hits(REFRESH_PATH), 2);
    assert_eq!(first.expect("first").refresh_token, "refresh.a.next");
    assert_eq!(second.expect("second").refresh_token, "refresh.b.next");
}

#[tokio::test]
async fn a_finished_refresh_is_not_cached() {
    let server = FakeServer::start(|_| Reply::ok(rotated("refresh.new"))).await;
    let client = client_for(&server);

    client
        .refresh_token(request("refresh.old"))
        .await
        .expect("first refresh");
    client
        .refresh_token(request("refresh.old"))
        .await
        .expect("second refresh");

    assert_eq!(server.hits(REFRESH_PATH), 2);
}
