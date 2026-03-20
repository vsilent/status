use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security::scopes::PolicyEngine;
use crate::task::store::{TaskScopes, TaskStore};
use crate::task::token;

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs() as i64
}

/// `task/delegate` — create a child task token from a parent token.
pub fn task_delegate(
    params: &Value,
    store: &Arc<TaskStore>,
    secret: &[u8],
    installation_id: &str,
) -> Result<Value, (i32, String)> {
    let parent_token = params["parent_token"]
        .as_str()
        .ok_or((-32602, "missing parent_token".to_string()))?;

    let requested_scopes: TaskScopes =
        serde_json::from_value(params["requested_scopes"].clone())
            .map_err(|e| (-32602, format!("invalid requested_scopes: {e}")))?;

    let ttl_secs = params["ttl_secs"].as_u64();

    let child_token = token::delegate(
        parent_token,
        &requested_scopes,
        installation_id,
        ttl_secs,
        secret,
        store,
        unix_now(),
    )
    .map_err(|e| (-32000, e.to_string()))?;

    // Decode the child claims to extract the task_id for the response.
    let child_claims = token::verify(&child_token, secret, store, unix_now())
        .map_err(|e| (-32000, e.to_string()))?;

    Ok(json!({
        "task_token": child_token,
        "task_id": child_claims.task_id,
    }))
}

/// `task/info` — return metadata about the task bound to a token.
pub fn task_info(
    params: &Value,
    store: &Arc<TaskStore>,
    secret: &[u8],
) -> Result<Value, (i32, String)> {
    let token_str = params["token"]
        .as_str()
        .ok_or((-32602, "missing token".to_string()))?;

    let claims =
        token::verify(token_str, secret, store, unix_now()).map_err(|e| (-32000, e.to_string()))?;

    Ok(json!({
        "task_id": claims.task_id,
        "depth": claims.depth,
        "scopes": claims.scopes,
        "expires_at": claims.exp,
        "status": "active",
    }))
}

/// `task/revoke` — revoke a task and its descendants (caller must be the direct parent).
pub fn task_revoke(
    params: &Value,
    store: &Arc<TaskStore>,
    secret: &[u8],
) -> Result<Value, (i32, String)> {
    let caller_token = params["token"]
        .as_str()
        .ok_or((-32602, "missing token".to_string()))?;

    let target_task_id = params["target_task_id"]
        .as_str()
        .ok_or((-32602, "missing target_task_id".to_string()))?;

    let caller_claims = token::verify(caller_token, secret, store, unix_now())
        .map_err(|e| (-32000, e.to_string()))?;

    let target = store
        .get_by_id(target_task_id)
        .map_err(|e| (-32000, e.to_string()))?
        .ok_or((-32000, format!("task '{target_task_id}' not found")))?;

    match &target.parent_id {
        Some(pid) if pid == &caller_claims.task_id => {}
        _ => {
            return Err((
                -32000,
                "caller is not the parent of the target task".to_string(),
            ));
        }
    }

    let revoked_count = store
        .revoke_cascade(target_task_id)
        .map_err(|e| (-32000, e.to_string()))?;

    Ok(json!({ "revoked_count": revoked_count }))
}

/// `policy/get` — return the current stack policy from the policy engine.
pub async fn policy_get(
    policy_engine: &Arc<tokio::sync::RwLock<Option<PolicyEngine>>>,
) -> Result<Value, (i32, String)> {
    let guard = policy_engine.read().await;
    match &*guard {
        Some(engine) => serde_json::to_value(&engine.stack_policy)
            .map_err(|e| (-32000, format!("serialize policy: {e}"))),
        None => Err((
            -32000,
            "policy engine not available (STACKER_URL not configured)".to_string(),
        )),
    }
}

/// `ssh/request_cert` — stub; Vault SSH integration is a future milestone.
pub fn ssh_request_cert(_params: &Value) -> Result<Value, (i32, String)> {
    Ok(json!({
        "status": "not_implemented",
        "message": "Vault SSH integration coming in sp-vault-ssh",
    }))
}
