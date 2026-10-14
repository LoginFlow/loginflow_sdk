//! Shared test harness: a tiny HTTP/1.1 server on a random local port.
//!
//! It records every request it receives and answers each one through a
//! caller-supplied responder, so tests can play the LoginFlow API (or only its
//! JWKS endpoint) without any network access.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use loginflow_sdk::{LoginFlowClient, LoginFlowConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request as seen by the fake server.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    /// Path including the query string, e.g. `/v1/master/user-profiles/search?email=a%40b.c`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RecordedRequest {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("request body is not JSON")
    }
}

/// What the server answers to a request.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
    /// Send the body without `Content-Length` (delimited by closing the connection).
    pub omit_content_length: bool,
    /// Extra response headers.
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn ok(body: impl Into<String>) -> Self {
        Self::status(200, body)
    }

    pub fn status(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            delay: Duration::ZERO,
            omit_content_length: false,
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    pub fn without_content_length(mut self) -> Self {
        self.omit_content_length = true;
        self
    }
}

type Responder = dyn Fn(&RecordedRequest) -> Reply + Send + Sync;

pub struct FakeServer {
    pub base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responder: Arc<Mutex<Arc<Responder>>>,
}

impl FakeServer {
    pub async fn start(
        responder: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake server");
        let addr = listener.local_addr().expect("local addr");
        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Mutex<Arc<Responder>>> = Arc::new(Mutex::new(Arc::new(responder)));

        let task_requests = requests.clone();
        let task_responder = responder.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let requests = task_requests.clone();
                let responder = task_responder.lock().expect("responder lock").clone();
                tokio::spawn(async move {
                    handle(stream, requests, responder).await;
                });
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            requests,
            responder,
        }
    }

    /// Replaces the responder (e.g. to simulate a key rotation on the server).
    pub fn set_responder(
        &self,
        responder: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
    ) {
        *self.responder.lock().expect("responder lock") = Arc::new(responder);
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("requests lock").clone()
    }

    pub fn hits(&self, path: &str) -> usize {
        self.requests().iter().filter(|r| r.path() == path).count()
    }

    pub fn last(&self) -> RecordedRequest {
        self.requests()
            .last()
            .cloned()
            .expect("no request recorded")
    }
}

async fn handle(
    mut stream: TcpStream,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    responder: Arc<Responder>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let Ok(n) = stream.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let Ok(n) = stream.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let request = RecordedRequest {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    requests
        .lock()
        .expect("requests lock")
        .push(request.clone());

    let reply = responder(&request);
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let length_header = if reply.omit_content_length {
        String::new()
    } else {
        format!("Content-Length: {}\r\n", reply.body.len())
    };
    let extra_headers: String = reply
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let response = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\n{}{}Connection: close\r\n\r\n{}",
        reply.status, length_header, extra_headers, reply.body
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Standard LoginFlow success envelope.
pub fn envelope(data: serde_json::Value) -> String {
    serde_json::json!({
        "data": data,
        "meta": { "status": 200, "timestamp": "2026-10-15T00:00:00Z", "request_id": "req-1", "path": "/" }
    })
    .to_string()
}

// ============================================================================
// Signing keys and tokens
// ============================================================================

pub const ISSUER: &str = "https://api.loginflow.test";
pub const APP_ID: &str = "33333333-3333-3333-3333-333333333333";
pub const COMPANY_ID: &str = "22222222-2222-2222-2222-222222222222";
pub const USER_ID: &str = "11111111-1111-1111-1111-111111111111";
pub const JWKS_PATH: &str = "/oauth2/jwks";

/// Throwaway P-256 keys (PKCS#8 DER, hex), generated for these tests only.
const KEY_A_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420a4860bb240e417acb446967bd393d621eda2fe4554c39fb6de7496088dbef287a1440342000488e06363cbac10d82283dc9b42987841a1511ea2938338ff9166f6ab76c4b08cf130966be3433cf459b0ae6f9aec9213165342fc5bda713dc3774eeaaf5f1b88";
const KEY_B_HEX: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420c4184682826be5f17c3bf6af6a2f1af22fb9b14f42e83bdc5a667f034c028497a14403420004d1b15c875c20fdb34e727fc76584ba282b95e77ebfc83a868676a4396227e36e064462fa4931d96476734de83cf1536092d288dd5f62facd930cfabd0257e3a9";

pub struct TestKey {
    pub kid: String,
    pub encoding: EncodingKey,
    x: String,
    y: String,
}

impl TestKey {
    pub fn a() -> Self {
        Self::from_hex("kid-a", KEY_A_HEX)
    }

    pub fn b() -> Self {
        Self::from_hex("kid-b", KEY_B_HEX)
    }

    fn from_hex(kid: &str, hex: &str) -> Self {
        let der: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        let encoding = EncodingKey::from_ec_der(&der);
        let jwk = Jwk::from_encoding_key(&encoding, Algorithm::ES256).expect("jwk");
        let AlgorithmParameters::EllipticCurve(params) = jwk.algorithm else {
            panic!("not an EC key")
        };
        Self {
            kid: kid.to_string(),
            encoding,
            x: params.x,
            y: params.y,
        }
    }

    /// Same key material published under another `kid`.
    pub fn with_kid(&self, kid: &str) -> serde_json::Value {
        serde_json::json!({ "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid, "x": self.x, "y": self.y })
    }

    /// Public JWK as LoginFlow publishes it.
    pub fn public_jwk(&self) -> serde_json::Value {
        self.with_kid(&self.kid)
    }

    /// ES256 token with this key's `kid`.
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding).expect("sign")
    }
}

pub fn jwks(keys: &[serde_json::Value]) -> String {
    serde_json::json!({ "keys": keys }).to_string()
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Claims of a valid access token, as LoginFlow issues them after Phase 2.
pub fn access_claims() -> serde_json::Value {
    let now = now();
    serde_json::json!({
        "jti": "jti-1",
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": APP_ID,
        "exp": now + 900,
        "iat": now,
        "user_id": USER_ID,
        "company_id": COMPANY_ID,
        "application_id": APP_ID,
        "email": "user@example.com",
        "role": "user",
        "status": "active",
        "token_type": "access",
        "created_at": "2026-10-15T00:00:00",
        "expires_in": "2026-10-15T00:15:00"
    })
}

/// Same claims with one field replaced.
pub fn claims_with(field: &str, value: serde_json::Value) -> serde_json::Value {
    let mut claims = access_claims();
    claims[field] = value;
    claims
}

/// Fake LoginFlow that only serves the given JWKS document.
pub async fn jwks_server(document: String) -> FakeServer {
    FakeServer::start(move |req| {
        if req.path() == JWKS_PATH {
            Reply::ok(document.clone())
        } else {
            Reply::status(404, "{}")
        }
    })
    .await
}

/// Client configured against `server` with the test issuer and audience.
pub fn client_for(server: &FakeServer) -> LoginFlowClient {
    LoginFlowClient::new(config_for(server)).expect("client")
}

pub fn config_for(server: &FakeServer) -> LoginFlowConfig {
    LoginFlowConfig {
        base_url: server.base_url.clone(),
        api_version: 1,
        company_id: COMPANY_ID.to_string(),
        application_id: APP_ID.to_string(),
        timeout_secs: 5,
        user_agent: None,
        issuer: ISSUER.to_string(),
        jwks_url: None,
        jwks_cache_ttl_secs: 600,
    }
}
