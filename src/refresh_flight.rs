//! Single-flight refresh: concurrent refreshes of one refresh token share one request.
//!
//! LoginFlow rotates the refresh token on every refresh and revokes the session
//! when a rotated token is presented again. Two callers refreshing with the same
//! token at the same time would therefore race: one wins, the other is rejected
//! or ends the session. Here the first caller sends the request and every caller
//! that arrives with the same session and token while it is in flight awaits
//! that request's result. Callers holding a different token are never joined to
//! it, so nobody receives tokens for a refresh token they did not present.
//!
//! Nothing is cached: once the request finished and its callers returned, the
//! next call with the same token sends a new request.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::OnceCell;

use crate::error::LoginFlowResult;
use crate::models::RefreshTokenResponse;

type Outcome = LoginFlowResult<RefreshTokenResponse>;
type Flight = Arc<OnceCell<Outcome>>;

/// `(session_id, refresh_token)` of one refresh.
#[derive(Clone, PartialEq, Eq, Hash)]
struct FlightKey {
    session_id: String,
    refresh_token: String,
}

/// The refreshes in flight, shared by every clone of a client.
#[derive(Default)]
pub(crate) struct RefreshFlights {
    in_flight: Mutex<HashMap<FlightKey, Flight>>,
}

impl RefreshFlights {
    /// Runs `refresh` unless a refresh of the same session and token is in
    /// flight, in which case its result is returned instead.
    pub(crate) async fn run<F, Fut>(
        &self,
        session_id: &str,
        refresh_token: &str,
        refresh: F,
    ) -> Outcome
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Outcome>,
    {
        let key = FlightKey {
            session_id: session_id.to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let flight = Arc::clone(self.lock().entry(key.clone()).or_default());
        let guard = FlightGuard {
            flights: self,
            key,
            flight,
        };
        // If the caller sending the request is cancelled, a waiting caller sends it.
        guard.flight.get_or_init(refresh).await.clone()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<FlightKey, Flight>> {
        // The map is consistent after every operation, so a poisoned lock is still usable.
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Removes the flight from the map once it is finished, or once its last caller left.
struct FlightGuard<'a> {
    flights: &'a RefreshFlights,
    key: FlightKey,
    flight: Flight,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        let mut in_flight = self.flights.lock();
        let current = in_flight
            .get(&self.key)
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight));
        // Two references left means the map's and this caller's: nobody else awaits it.
        let abandoned = Arc::strong_count(&self.flight) <= 2;
        if current && (self.flight.initialized() || abandoned) {
            in_flight.remove(&self.key);
        }
    }
}
