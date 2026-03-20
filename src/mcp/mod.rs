//! MCP (Model Context Protocol) server — WebSocket JSON-RPC 2.0 endpoint.
//!
//! Exposed at `ws://127.0.0.1:8090/mcp` (Docker internal network only).
//! Each message is a JSON-RPC 2.0 request; each reply is a JSON-RPC 2.0 response.

pub mod tools;
pub mod types;

use std::sync::Arc;

use axum::{
    extract::{ws::Message, ws::WebSocket, State, WebSocketUpgrade},
    response::IntoResponse,
};
use serde_json::Value;
use tracing::{debug, warn};

use crate::comms::local_api::AppState;
use types::{
    JsonRpcRequest, JsonRpcResponse, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE,
};

type SharedState = Arc<AppState>;

// ── Public handler (wired into the Axum router) ───────────────────────────────

pub async fn mcp_ws_handler(
    State(state): State<SharedState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

// ── Per-connection loop ───────────────────────────────────────────────────────

async fn handle_socket(mut socket: WebSocket, state: SharedState) {
    debug!("MCP WebSocket client connected");

    while let Some(Ok(msg)) = socket.recv().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(data) => {
                let _ = socket.send(Message::Pong(data)).await;
                continue;
            }
            _ => continue,
        };

        let response = dispatch(text.as_str(), &state).await;

        match serde_json::to_string(&response) {
            Ok(json) => {
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!("MCP: failed to serialize response: {e}");
                break;
            }
        }
    }

    debug!("MCP WebSocket client disconnected");
}

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────────

async fn dispatch(raw: &str, state: &SharedState) -> JsonRpcResponse {
    let req: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(e) => return JsonRpcResponse::error(None, ERR_PARSE, format!("parse error: {e}")),
    };

    let id = req.id.clone();

    if req.jsonrpc != "2.0" {
        return JsonRpcResponse::error(
            id,
            ERR_INVALID_REQUEST,
            "invalid request: jsonrpc must be \"2.0\"",
        );
    }

    let params = req.params.unwrap_or(Value::Null);

    let installation_id = std::env::var("INSTALLATION_HASH").unwrap_or_default();

    let result: Result<Value, (i32, String)> = match req.method.as_str() {
        "task/delegate" => tools::task_delegate(
            &params,
            &state.task_store,
            &state.broker_secret,
            &installation_id,
        ),
        "task/info" => tools::task_info(&params, &state.task_store, &state.broker_secret),
        "task/revoke" => tools::task_revoke(&params, &state.task_store, &state.broker_secret),
        "policy/get" => tools::policy_get(&state.policy_engine).await,
        "ssh/request_cert" => tools::ssh_request_cert(&params),
        _ => Err((
            ERR_METHOD_NOT_FOUND,
            format!("method not found: {}", req.method),
        )),
    };

    match result {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err((code, message)) => JsonRpcResponse::error(id, code, message),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::types::ERR_APPLICATION;
    use crate::task::store::{TaskScopes, TaskStore};
    use crate::task::token;
    use serde_json::json;
    use tempfile::NamedTempFile;

    const SECRET: &[u8] = b"test-broker-secret-32-bytes-xxxx";

    fn open_store() -> (Arc<TaskStore>, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = TaskStore::new(f.path().to_str().unwrap()).unwrap();
        (Arc::new(store), f)
    }

    fn full_scopes() -> TaskScopes {
        TaskScopes {
            ssh_targets: vec!["10.0.0.1".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec![],
            trydirect_ops: vec!["read".into()],
            max_sub_agents: 4,
            max_depth: 3,
        }
    }

    // ── JSON-RPC parsing tests ────────────────────────────────────────────────

    #[test]
    fn test_jsonrpc_parse_valid() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"task/info","params":{"token":"x"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "task/info");
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, Some(json!(1)));
    }

    #[tokio::test]
    async fn test_jsonrpc_method_not_found() {
        let (store, _f) = open_store();
        let state = make_state(store);
        let raw = r#"{"jsonrpc":"2.0","id":42,"method":"unknown/method","params":{}}"#;
        let resp = dispatch(raw, &state).await;
        let err = resp.error.expect("expected error");
        assert_eq!(err.code, ERR_METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_jsonrpc_parse_error() {
        let (store, _f) = open_store();
        let state = make_state(store);
        let resp = dispatch("not json {{{", &state).await;
        let err = resp.error.expect("expected error");
        assert_eq!(err.code, ERR_PARSE);
    }

    #[tokio::test]
    async fn test_jsonrpc_invalid_version() {
        let (store, _f) = open_store();
        let state = make_state(store);
        let raw = r#"{"jsonrpc":"1.0","id":1,"method":"task/info","params":{}}"#;
        let resp = dispatch(raw, &state).await;
        let err = resp.error.expect("expected error");
        assert_eq!(err.code, ERR_INVALID_REQUEST);
    }

    // ── Tool tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_task_info_valid_token() {
        let (store, _f) = open_store();
        let record = store.insert_root("install-test", full_scopes()).unwrap();
        let tok = token::mint(&record, SECRET).unwrap();

        let params = json!({ "token": tok });
        let result = tools::task_info(&params, &store, SECRET).unwrap();

        assert_eq!(result["task_id"], record.task_id);
        assert_eq!(result["depth"], 0);
        assert_eq!(result["status"], "active");
    }

    #[test]
    fn test_task_info_invalid_token() {
        let (store, _f) = open_store();
        let params = json!({ "token": "badtoken.badsig" });
        let err = tools::task_info(&params, &store, SECRET).unwrap_err();
        assert_eq!(err.0, ERR_APPLICATION);
    }

    #[test]
    fn test_task_info_missing_param() {
        let (store, _f) = open_store();
        let params = json!({});
        let err = tools::task_info(&params, &store, SECRET).unwrap_err();
        assert_eq!(err.0, -32602);
    }

    #[test]
    fn test_task_delegate_depth_exceeded() {
        let (store, _f) = open_store();
        // max_depth = 1: only one delegation level allowed
        let shallow = TaskScopes {
            max_depth: 1,
            ..full_scopes()
        };
        let root = store.insert_root("install-depth", shallow.clone()).unwrap();
        let root_token = token::mint(&root, SECRET).unwrap();

        // First delegation: depth 0 → 1, should succeed
        let child_token = token::delegate(
            &root_token,
            &shallow,
            "install-depth",
            None,
            SECRET,
            &store,
            unix_now(),
        )
        .unwrap();

        // Second delegation: depth 1 = max_depth 1, must fail
        let params = json!({
            "parent_token": child_token,
            "requested_scopes": shallow,
            "ttl_secs": 3600,
        });
        let err = tools::task_delegate(&params, &store, SECRET, "install-depth").unwrap_err();
        assert_eq!(err.0, ERR_APPLICATION);
        assert!(err.1.contains("depth"), "error message: {}", err.1);
    }

    #[test]
    fn test_task_delegate_success() {
        let (store, _f) = open_store();
        let root = store
            .insert_root("install-delegate", full_scopes())
            .unwrap();
        let root_token = token::mint(&root, SECRET).unwrap();

        let params = json!({
            "parent_token": root_token,
            "requested_scopes": full_scopes(),
            "ttl_secs": 3600,
        });
        let result = tools::task_delegate(&params, &store, SECRET, "install-delegate").unwrap();
        assert!(result["task_token"].is_string());
        assert!(result["task_id"].is_string());
    }

    #[test]
    fn test_task_revoke_not_parent() {
        let (store, _f) = open_store();
        let root = store.insert_root("install-rev", full_scopes()).unwrap();
        let root_token = token::mint(&root, SECRET).unwrap();
        // root cannot revoke itself via the revoke tool (it has no parent)
        let params = json!({
            "token": root_token,
            "target_task_id": root.task_id,
        });
        let err = tools::task_revoke(&params, &store, SECRET).unwrap_err();
        assert_eq!(err.0, ERR_APPLICATION);
    }

    #[test]
    fn test_ssh_request_cert_stub() {
        let params = json!({ "token": "tok", "public_key": "ssh-ed25519 AAAA..." });
        let result = tools::ssh_request_cert(&params).unwrap();
        assert_eq!(result["status"], "not_implemented");
    }

    // ── Helper to build a minimal SharedState for dispatch tests ─────────────

    fn unix_now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn make_state(store: Arc<TaskStore>) -> SharedState {
        // Build an AppState with just enough fields populated for MCP dispatch.
        // We use `Default` trick via a thin wrapper — but AppState has no Default,
        // so we call AppState::new() with a minimal config.
        use crate::agent::config::{Config, ReqData};

        let config = Arc::new(Config {
            domain: None,
            subdomains: None,
            apps_info: None,
            reqdata: ReqData {
                email: "test@example.com".to_string(),
            },
            ssl: None,
            compose_agent_enabled: false,
            control_plane: None,
            firewall: None,
        });

        Arc::new(AppState::new_with_task_store(
            config,
            false,
            None,
            store,
            SECRET.to_vec(),
        ))
    }
}
