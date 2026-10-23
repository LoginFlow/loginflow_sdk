//! Shared test harness: a tiny HTTP/1.1 server on a random local port.
//!
//! It records every request it receives and answers each one through a
//! caller-supplied responder, so tests can play the LoginFlow API (or only its
//! JWKS endpoint) without any network access.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use loginflow_sdk::authorization::header::{AuthScheme, AuthorizationHeader};
use loginflow_sdk::{
    InMemoryJtiReplayCache, IntrospectionClient, LoginFlowClient, LoginFlowConfig, PresentedToken,
    TokenVerifier, VerifiedAccess, VerifyError,
};
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

/// Path of the discovery document, as the SDK requests it
/// (`crate::discovery::fetch`) and the server's own `discovery_document.rs` serves it.
pub const DISCOVERY_PATH: &str = "/.well-known/openid-configuration";

/// A discovery document pointing every endpoint back at `base_url` — enough for any test whose
/// SDK call resolves its URL through [`loginflow_sdk::LoginFlowClient::discovery`].
pub fn discovery_document(base_url: &str) -> String {
    serde_json::json!({
        "issuer": ISSUER,
        "jwks_uri": format!("{base_url}/oauth2/jwks"),
        "authorization_endpoint": format!("{base_url}/oauth2/authorize"),
        "token_endpoint": format!("{base_url}/oauth2/token"),
        "userinfo_endpoint": format!("{base_url}/oauth2/userinfo"),
        "introspection_endpoint": format!("{base_url}/oauth2/introspect"),
        "revocation_endpoint": format!("{base_url}/oauth2/revoke"),
        "end_session_endpoint": format!("{base_url}/oauth2/end-session"),
    })
    .to_string()
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
pub const APP_ID: &str = "APP-TEST";
/// Audience of the API under test (`LOGINFLOW_API`).
pub const API_AUDIENCE: &str = "https://drivers.api.test";
/// Audience of another API of the same application.
pub const OTHER_API_AUDIENCE: &str = "https://billing.api.test";
pub const ORG_ID: &str = "44444444-4444-4444-4444-444444444444";
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

    /// RFC 9068 access token (`typ: at+jwt`) with this key's `kid`.
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        self.sign_with_typ(claims, Some("at+jwt"))
    }

    /// Same as [`sign`](Self::sign), with an explicit (or absent) header `typ`, for tests of the
    /// `typ` check itself.
    pub fn sign_with_typ(&self, claims: &serde_json::Value, typ: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.kid.clone());
        header.typ = typ.map(str::to_string);
        encode(&header, claims, &self.encoding).expect("sign")
    }
}

/// RFC 9449 DPoP proof signed by `key`, with `key`'s public JWK embedded in the header.
pub fn build_dpop_proof(
    key: &TestKey,
    htm: &str,
    htu: &str,
    jti: &str,
    ath: Option<&str>,
    iat: i64,
) -> String {
    let jwk = Jwk::from_encoding_key(&key.encoding, Algorithm::ES256).expect("jwk");
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk);
    let mut claims = serde_json::json!({ "htm": htm, "htu": htu, "iat": iat, "jti": jti });
    if let Some(ath) = ath {
        claims["ath"] = serde_json::json!(ath);
    }
    encode(&header, &claims, &key.encoding).expect("sign proof")
}

/// RFC 7638 thumbprint of `key`, computed independently of the SDK (the value a DPoP-bound
/// token's `cnf.jkt` carries).
pub fn jwk_thumbprint(key: &TestKey) -> String {
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        key.x, key.y
    );
    URL_SAFE_NO_PAD.encode(digest(&SHA256, canonical.as_bytes()).as_ref())
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

/// Claims of a valid RFC 9068 access token for the API under test, as LoginFlow issues them: no
/// email, no account status — `sub` is the `company_users` id; `aud` the API, `app` the
/// application, one active organization and the permissions there.
pub fn access_claims() -> serde_json::Value {
    let now = now();
    serde_json::json!({
        "jti": "jti-1",
        "iss": ISSUER,
        "sub": USER_ID,
        "aud": API_AUDIENCE,
        "exp": now + 600,
        "iat": now,
        "client_id": "test-client",
        "scope": "openid profile",
        "sid": "sid-1",
        "auth_time": now,
        "amr": ["pwd"],
        "company_id": COMPANY_ID,
        "app": APP_ID,
        "org_id": ORG_ID,
        "org_ext": "client-7",
        "permissions": ["rutafacil.drivers.list"],
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
        api_audience: API_AUDIENCE.to_string(),
        timeout_secs: 5,
        user_agent: None,
        issuer: ISSUER.to_string(),
        jwks_url: None,
        jwks_cache_ttl_secs: 600,
        resource_base_url: None,
    }
}

/// Path of the introspection endpoint the test verifiers call.
pub const INTROSPECT_PATH: &str = "/oauth2/introspect";

/// A [`TokenVerifier`] against `server` (JWKS and introspection), with its own replay cache.
pub fn verifier_for(server: &FakeServer) -> TokenVerifier {
    verifier_with(client_for(server), server)
}

/// A [`TokenVerifier`] with `client`, introspecting against `server`.
pub fn verifier_with(client: LoginFlowClient, server: &FakeServer) -> TokenVerifier {
    let introspection = IntrospectionClient::new(
        reqwest::Client::new(),
        format!("{}{INTROSPECT_PATH}", server.base_url),
        "drivers-api",
        "drivers-api-secret",
    );
    TokenVerifier::new(
        client,
        Arc::new(InMemoryJtiReplayCache::new()),
        introspection,
    )
}

/// Verify `token` presented as `Authorization: Bearer <token>` with no DPoP proof.
pub async fn verify_bearer(
    verifier: &TokenVerifier,
    token: &str,
) -> Result<VerifiedAccess, VerifyError> {
    let authorization = AuthorizationHeader {
        scheme: AuthScheme::Bearer,
        token: token.to_string(),
    };
    verifier
        .verify_presented(&PresentedToken {
            authorization: &authorization,
            dpop_proof: None,
            method: "GET",
            request_origin: "http://localhost",
            path: "/drivers",
        })
        .await
}

// ============================================================================
// The machine door (`/v1/service/*` clients)
// ============================================================================

pub const TOKEN_PATH: &str = "/oauth2/token";

/// Token endpoint answer whose `access_token` is `token-<n>`, `n` counting from 1.
pub fn token_reply(issued: &AtomicUsize) -> Reply {
    let n = issued.fetch_add(1, Ordering::SeqCst) + 1;
    Reply::ok(
        serde_json::json!({ "access_token": format!("token-{n}"), "token_type": "Bearer", "expires_in": 900 })
            .to_string(),
    )
}

/// The LoginFlow error envelope.
pub fn error_body(code: &str, message: &str) -> String {
    serde_json::json!({
        "error": { "code": code, "message": message },
        "meta": { "status": 0, "timestamp": "2026-10-21T09:00:00Z", "request_id": "r", "path": "/" }
    })
    .to_string()
}

/// Fake LoginFlow: the token endpoint issues `token-1`, `token-2`, ...; every other request is
/// answered by `api`.
pub async fn service_door_server(
    api: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
) -> FakeServer {
    let issued = Arc::new(AtomicUsize::new(0));
    FakeServer::start(move |req| {
        if req.path() == TOKEN_PATH {
            token_reply(&issued)
        } else {
            api(req)
        }
    })
    .await
}

/// Every request but the token requests.
pub fn api_requests(server: &FakeServer) -> Vec<RecordedRequest> {
    server
        .requests()
        .into_iter()
        .filter(|req| req.path() != TOKEN_PATH)
        .collect()
}

/// The form body of the first `client_credentials` token request, asserting the grant and
/// `client_secret_basic`.
pub fn token_request_body(server: &FakeServer) -> String {
    let token_request = server
        .requests()
        .into_iter()
        .find(|req| req.path() == TOKEN_PATH)
        .expect("token requested");
    assert!(
        token_request.body.contains("grant_type=client_credentials"),
        "{}",
        token_request.body
    );
    assert!(
        token_request
            .header("authorization")
            .is_some_and(|value| value.starts_with("Basic ")),
    );
    token_request.body
}

// ============================================================================
// Permission manifest
// ============================================================================

/// The manifest of the API under test: two resources, every level.
pub const MANIFEST_YAML: &str = r#"
app: rutafacil
resources:
  drivers:
    description: Drivers of the client company
    sensitive: true
    read:
      - { action: list, description: List the drivers }
    write:
      - { action: create, description: Register a driver }
    special:
      - { action: issueCode, description: Issue a driver's access code }
  fleet:
    description: Buses
    read:
      - { action: read, description: See the buses }
"#;

pub fn manifest() -> loginflow_sdk::PermissionManifest {
    loginflow_sdk::PermissionManifest::from_yaml_str(MANIFEST_YAML).expect("test manifest")
}

/// A fresh, empty directory under the system temp dir (removed by the caller).
pub fn temp_dir(label: &str) -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "loginflow-sdk-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}
