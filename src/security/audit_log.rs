use std::sync::Arc;
use tracing::{error, info, warn};

use crate::task::store::TaskStore;

// ── AuditEvent enum ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum AuditEvent {
    AgentTaskCreated {
        task_id: String,
        parent_id: Option<String>,
        installation_id: String,
        depth: u32,
        /// Compact summary, e.g. `"ssh:2,http_allow:3,ops:1"`.
        scopes_summary: String,
    },
    AgentTaskRevoked {
        task_id: String,
        /// `task_id` of the caller that triggered the revocation.
        revoked_by: String,
        cascade_count: u32,
    },
    AgentTokenVerified {
        task_id: String,
        /// Context, e.g. `"task/delegate"`, `"proxy"`, `"mcp/tool_name"`.
        method: String,
        success: bool,
        failure_reason: Option<String>,
    },
    AgentProxyRequest {
        task_id: String,
        /// HTTP method of the proxied request.
        method: String,
        /// Hostname only (no path, no credentials).
        url_host: String,
        /// HTTP response status, or `0` when the request was blocked before sending.
        status: u16,
        blocked: bool,
        block_reason: Option<String>,
    },
    AgentDelegation {
        parent_task_id: String,
        child_task_id: String,
        child_depth: u32,
        /// Compact diff, e.g. `"ssh:-1,http_allow:-2"`.
        scope_reduction: String,
    },
}

impl AuditEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            AuditEvent::AgentTaskCreated { .. } => "AgentTaskCreated",
            AuditEvent::AgentTaskRevoked { .. } => "AgentTaskRevoked",
            AuditEvent::AgentTokenVerified { .. } => "AgentTokenVerified",
            AuditEvent::AgentProxyRequest { .. } => "AgentProxyRequest",
            AuditEvent::AgentDelegation { .. } => "AgentDelegation",
        }
    }
}

// ── AuditLogger ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AuditLogger {
    task_store: Option<Arc<TaskStore>>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { task_store: None }
    }

    /// Create an `AuditLogger` that also buffers agent events to the SQLite task store.
    pub fn with_store(store: Arc<TaskStore>) -> Self {
        Self {
            task_store: Some(store),
        }
    }

    // ── Existing event methods ────────────────────────────────────────────────

    pub fn auth_success(&self, agent_id: &str, request_id: Option<&str>, action: &str) {
        info!(target: "audit", event = "auth_success", agent_id, request_id = request_id.unwrap_or(""), action);
    }

    pub fn auth_failure(&self, agent_id: Option<&str>, request_id: Option<&str>, reason: &str) {
        warn!(target: "audit", event = "auth_failure", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""), reason);
    }

    pub fn signature_invalid(&self, agent_id: Option<&str>, request_id: Option<&str>) {
        warn!(target: "audit", event = "signature_invalid", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""));
    }

    pub fn rate_limited(&self, agent_id: &str, request_id: Option<&str>) {
        warn!(target: "audit", event = "rate_limited", agent_id, request_id = request_id.unwrap_or(""));
    }

    pub fn replay_detected(&self, agent_id: Option<&str>, request_id: Option<&str>) {
        warn!(target: "audit", event = "replay_detected", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""));
    }

    pub fn scope_denied(&self, agent_id: &str, request_id: Option<&str>, scope: &str) {
        warn!(target: "audit", event = "scope_denied", agent_id, request_id = request_id.unwrap_or(""), scope);
    }

    pub fn command_executed(
        &self,
        agent_id: &str,
        request_id: Option<&str>,
        command_id: &str,
        name: &str,
    ) {
        info!(target: "audit", event = "command_executed", agent_id, request_id = request_id.unwrap_or(""), command_id, name);
    }

    pub fn token_rotated(&self, agent_id: &str, request_id: Option<&str>) {
        info!(target: "audit", event = "token_rotated", agent_id, request_id = request_id.unwrap_or(""));
    }

    pub fn internal_error(
        &self,
        agent_id: Option<&str>,
        request_id: Option<&str>,
        error_msg: &str,
    ) {
        error!(target: "audit", event = "internal_error", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""), error = error_msg);
    }

    // ── Agent broker events ───────────────────────────────────────────────────

    /// Log an agent-broker audit event.
    ///
    /// The event is emitted via `tracing` and, when a `TaskStore` is attached,
    /// also buffered to the `agent_audit_buffer` SQLite table for periodic relay
    /// to Stacker.
    pub fn log_agent_event(&self, event: AuditEvent) {
        let event_type = event.event_type();
        match serde_json::to_string(&event) {
            Ok(payload) => {
                info!(
                    target: "audit",
                    event = event_type,
                    payload = %payload,
                    "agent broker event"
                );
                if let Some(store) = &self.task_store {
                    if let Err(e) = store.buffer_audit_event(event_type, &payload) {
                        warn!(
                            target: "audit",
                            error = %e,
                            event_type,
                            "failed to buffer agent audit event"
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    target: "audit",
                    error = %e,
                    event_type,
                    "failed to serialize agent audit event"
                );
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::store::{TaskScopes, TaskStore};
    use tempfile::NamedTempFile;

    fn open_store() -> (Arc<TaskStore>, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = Arc::new(TaskStore::new(f.path().to_str().unwrap()).unwrap());
        (store, f)
    }

    fn default_scopes() -> TaskScopes {
        TaskScopes {
            ssh_targets: vec!["10.0.0.1".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec![],
            trydirect_ops: vec!["read".into()],
            max_sub_agents: 2,
            max_depth: 3,
        }
    }

    #[test]
    fn test_audit_log_agent_task_created() {
        let (store, _f) = open_store();
        let logger = AuditLogger::with_store(store.clone());

        logger.log_agent_event(AuditEvent::AgentTaskCreated {
            task_id: "task-abc".to_string(),
            parent_id: None,
            installation_id: "install-1".to_string(),
            depth: 0,
            scopes_summary: "ssh:1,http_allow:1,ops:1".to_string(),
        });

        let events = store.fetch_unrelayed_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, "AgentTaskCreated");

        let payload: serde_json::Value = serde_json::from_str(&events[0].2).unwrap();
        assert_eq!(payload["task_id"], "task-abc");
        assert_eq!(payload["installation_id"], "install-1");
        assert_eq!(payload["depth"], 0);
    }

    #[test]
    fn test_audit_log_proxy_request() {
        let (store, _f) = open_store();
        let logger = AuditLogger::with_store(store.clone());

        logger.log_agent_event(AuditEvent::AgentProxyRequest {
            task_id: "task-xyz".to_string(),
            method: "GET".to_string(),
            url_host: "api.example.com".to_string(),
            status: 403,
            blocked: true,
            block_reason: Some("host not in http_allow".to_string()),
        });

        let events = store.fetch_unrelayed_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1, "AgentProxyRequest");

        let payload: serde_json::Value = serde_json::from_str(&events[0].2).unwrap();
        assert_eq!(payload["task_id"], "task-xyz");
        assert_eq!(payload["method"], "GET");
        assert_eq!(payload["url_host"], "api.example.com");
        assert_eq!(payload["status"], 403);
        assert_eq!(payload["blocked"], true);
    }

    #[test]
    fn test_audit_logger_without_store_does_not_panic() {
        // Ensure logging without a store is a no-op (no buffering, no crash).
        let logger = AuditLogger::new();
        logger.log_agent_event(AuditEvent::AgentTaskRevoked {
            task_id: "t1".to_string(),
            revoked_by: "t0".to_string(),
            cascade_count: 3,
        });
    }

    #[test]
    fn test_existing_methods_still_work() {
        let logger = AuditLogger::new();
        logger.auth_success("agent-1", Some("req-1"), "deploy");
        logger.auth_failure(None, None, "bad token");
        logger.signature_invalid(Some("agent-2"), None);
        logger.rate_limited("agent-3", Some("req-2"));
        logger.scope_denied("agent-4", None, "ssh");
    }
}
