//! Background relay loop that periodically POSTs buffered audit events to Stacker.
//!
//! The Stacker endpoint `POST /api/v1/agent/audit` is expected to exist on the
//! remote Stacker service. Until it does, failures are logged as warnings and
//! the events remain in the buffer for the next retry cycle.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::task::store::TaskStore;

const RELAY_INTERVAL_SECS: u64 = 30;
const RELAY_BATCH_SIZE: usize = 50;

/// Spawn a background task that relays buffered audit events to Stacker every
/// [`RELAY_INTERVAL_SECS`] seconds.
///
/// If `STACKER_URL` is not set in the environment, the loop runs but skips the
/// HTTP call on every tick (events accumulate until the env var is populated and
/// the service is restarted, or until a future dynamic-config mechanism is added).
pub fn spawn_audit_relay(store: Arc<TaskStore>) {
    tokio::spawn(async move {
        let client = match Client::builder().timeout(Duration::from_secs(10)).build() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to build HTTP client for audit relay — relay disabled");
                return;
            }
        };

        let mut ticker = tokio::time::interval(Duration::from_secs(RELAY_INTERVAL_SECS));
        ticker.tick().await; // skip the first immediate tick

        loop {
            ticker.tick().await;
            relay_once(&client, &store).await;
        }
    });
}

async fn relay_once(client: &Client, store: &TaskStore) {
    let stacker_url = match std::env::var("STACKER_URL") {
        Ok(u) => u,
        Err(_) => {
            debug!("STACKER_URL not set — skipping audit relay tick");
            return;
        }
    };

    let installation_hash =
        std::env::var("INSTALLATION_HASH").unwrap_or_else(|_| "default".to_string());
    let internal_key = std::env::var("INTERNAL_SERVICES_ACCESS_KEY").unwrap_or_default();

    let events = match store.fetch_unrelayed_events(RELAY_BATCH_SIZE) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "failed to fetch unrelayed audit events");
            return;
        }
    };

    if events.is_empty() {
        return;
    }

    let ids: Vec<i64> = events.iter().map(|(id, _, _, _)| *id).collect();

    let events_json: Vec<_> = events
        .iter()
        .map(|(id, event_type, payload, created_at)| {
            let payload_value: serde_json::Value = serde_json::from_str(payload)
                .unwrap_or_else(|_| serde_json::Value::String(payload.clone()));
            json!({
                "id": id,
                "event_type": event_type,
                "payload": payload_value,
                "created_at": created_at,
            })
        })
        .collect();

    let body = json!({
        "installation_hash": installation_hash,
        "events": events_json,
    });

    let url = format!("{stacker_url}/api/v1/agent/audit");

    debug!(
        url = %url,
        count = ids.len(),
        "relaying audit events to Stacker"
    );

    let response = client
        .post(&url)
        .header("X-Internal-Key", &internal_key)
        .json(&body)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            info!(count = ids.len(), "audit events relayed to Stacker");
            if let Err(e) = store.mark_events_relayed(&ids) {
                warn!(error = %e, "failed to mark audit events as relayed");
            }
        }
        Ok(resp) => {
            warn!(
                status = %resp.status(),
                count = ids.len(),
                "Stacker audit relay returned non-success status — will retry"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                count = ids.len(),
                "failed to POST audit events to Stacker — will retry next cycle"
            );
        }
    }
}
