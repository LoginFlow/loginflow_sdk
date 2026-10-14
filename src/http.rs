//! Shared HTTP plumbing: bounded body reads and the LoginFlow response envelope.
//!
//! Every response body the SDK reads without parsing it as a known model is
//! read through [`read_capped`], so a misbehaving or hostile server cannot make
//! the SDK buffer an unbounded amount of memory.

use log::{debug, error, warn};
use reqwest::{RequestBuilder, Response};
use serde::de::DeserializeOwned;

use crate::error::{LoginFlowError, LoginFlowResult};
use crate::models::LoginFlowResponseWrapper;

/// Maximum number of bytes read from an error response body.
pub(crate) const ERROR_BODY_LIMIT: usize = 4 * 1024;

/// A response body read up to a byte cap.
pub(crate) struct CappedBody {
    pub bytes: Vec<u8>,
    /// `true` when the body was longer than the cap (`bytes` holds the first `cap` bytes).
    pub exceeded: bool,
}

/// Read at most `cap` bytes of the response body.
pub(crate) async fn read_capped(
    mut response: Response,
    cap: usize,
) -> Result<CappedBody, reqwest::Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let remaining = cap.saturating_sub(bytes.len());
        if chunk.len() > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            return Ok(CappedBody {
                bytes,
                exceeded: true,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(CappedBody {
        bytes,
        exceeded: false,
    })
}

/// Read a bounded error body (at most [`ERROR_BODY_LIMIT`] bytes) as text.
pub(crate) async fn read_error_body(response: Response) -> String {
    match read_capped(response, ERROR_BODY_LIMIT).await {
        Ok(body) => String::from_utf8_lossy(&body.bytes).into_owned(),
        Err(err) => {
            warn!("Could not read error response body: {}", err);
            String::new()
        }
    }
}

/// Turn a non-success response into a typed error.
///
/// Only the status and the server's error code are logged at `error`; the
/// (bounded) body can contain personal data and is logged at `debug`.
pub(crate) async fn error_from_response(response: Response, context: &str) -> LoginFlowError {
    let status = response.status();
    let body = read_error_body(response).await;
    let (code, _) = LoginFlowError::extract_error_fields(&body);
    error!(
        "{} failed ({}, code {})",
        context,
        status,
        code.as_deref().unwrap_or("none")
    );
    debug!("{} error body: {}", context, body);
    LoginFlowError::from_status(status.as_u16(), &body)
}

/// Pass a success response through; convert anything else into an error.
pub(crate) async fn expect_success(response: Response, context: &str) -> LoginFlowResult<Response> {
    if response.status().is_success() {
        Ok(response)
    } else {
        Err(error_from_response(response, context).await)
    }
}

/// Send the request and return the `data` of the LoginFlow envelope.
pub(crate) async fn send_for_data<T: DeserializeOwned>(
    request: RequestBuilder,
    context: &str,
) -> LoginFlowResult<T> {
    let response = expect_success(request.send().await?, context).await?;
    let wrapped: LoginFlowResponseWrapper<T> = response.json().await?;
    Ok(wrapped.data)
}

/// Send the request and only check that it succeeded.
pub(crate) async fn send_for_unit(request: RequestBuilder, context: &str) -> LoginFlowResult<()> {
    expect_success(request.send().await?, context)
        .await
        .map(|_| ())
}

/// Send the request and report success as `true`, any non-success status as `false`.
/// Transport errors are still returned as errors.
pub(crate) async fn send_for_flag(request: RequestBuilder, context: &str) -> LoginFlowResult<bool> {
    let response = request.send().await?;
    if response.status().is_success() {
        return Ok(true);
    }
    let status = response.status();
    let body = read_error_body(response).await;
    warn!("{} failed ({})", context, status);
    debug!("{} error body: {}", context, body);
    Ok(false)
}
