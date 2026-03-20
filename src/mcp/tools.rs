use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security::scopes::PolicyEngine;
use crate::security::vault_client::VaultClient;
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

/// `ssh/request_cert` — sign an ephemeral SSH public key via Vault SSH Secrets Engine.
///
/// # Request Parameters
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `token` | string | Task token authorizing the request |
/// | `public_key` | string | SSH public key to sign (e.g. `"ssh-ed25519 AAAA..."`) |
/// | `principals` | `[string]` | SSH principals to embed in the certificate |
/// | `ttl_secs` | u64 | Certificate TTL in seconds (default: 3600) |
///
/// # Validation
///
/// 1. `public_key` must not be empty.
/// 2. Task token must be valid and non-expired.
/// 3. Every requested principal must appear in `claims.scopes.ssh_targets`
///    (exact match), or `ssh_targets` must contain `"*"` (wildcard).
/// 4. Vault must be configured (`VAULT_SSH_MOUNT`, `VAULT_SSH_ROLE`).
pub async fn ssh_request_cert(
    params: &Value,
    vault_client: &Option<VaultClient>,
    store: &Arc<TaskStore>,
    secret: &[u8],
) -> Result<Value, (i32, String)> {
    let token_str = params["token"]
        .as_str()
        .ok_or((-32602, "missing token".to_string()))?;

    let public_key = params["public_key"]
        .as_str()
        .ok_or((-32602, "missing public_key".to_string()))?;

    if public_key.is_empty() {
        return Err((-32602, "public_key must not be empty".to_string()));
    }

    let principals: Vec<String> = params["principals"]
        .as_array()
        .ok_or((-32602, "missing principals".to_string()))?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let ttl_secs = params["ttl_secs"].as_u64().unwrap_or(3600);

    // 1. Verify task token.
    let claims = token::verify(token_str, secret, store, unix_now())
        .map_err(|e| (-32000, format!("token verification failed: {e}")))?;

    // 2. Check each requested principal against the token's ssh_targets scope.
    for principal in &principals {
        if !ssh_principal_allowed(&claims.scopes.ssh_targets, principal) {
            return Err((
                -32000,
                format!("principal '{}' is not in allowed ssh_targets", principal),
            ));
        }
    }

    // 3. Sign via Vault SSH Secrets Engine.
    let vc = vault_client
        .as_ref()
        .ok_or((-32000, "Vault SSH is not configured".to_string()))?;

    let cert = vc
        .sign_ssh_key(public_key, &principals, ttl_secs)
        .await
        .map_err(|e| (-32000, format!("Vault SSH sign failed: {e}")))?;

    Ok(json!({
        "signed_key": cert.signed_key,
        "serial_number": cert.serial_number,
        "lease_duration": cert.lease_duration,
    }))
}

/// Returns `true` if `principal` is permitted by the `ssh_targets` list.
///
/// Rules:
/// - `"*"` in the list grants access to any principal.
/// - Otherwise only exact string matches are accepted.
fn ssh_principal_allowed(ssh_targets: &[String], principal: &str) -> bool {
    for target in ssh_targets {
        if target == "*" || target == principal {
            return true;
        }
    }
    false
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_principal_allowed_exact_match() {
        let targets = vec!["ubuntu".to_string(), "deploy".to_string()];
        assert!(ssh_principal_allowed(&targets, "ubuntu"));
        assert!(ssh_principal_allowed(&targets, "deploy"));
        assert!(!ssh_principal_allowed(&targets, "root"));
    }

    #[test]
    fn test_ssh_principal_allowed_wildcard() {
        let targets = vec!["*".to_string()];
        assert!(ssh_principal_allowed(&targets, "root"));
        assert!(ssh_principal_allowed(&targets, "ubuntu"));
        assert!(ssh_principal_allowed(&targets, "any-principal"));
    }

    #[test]
    fn test_ssh_principal_allowed_empty_targets() {
        let targets: Vec<String> = vec![];
        assert!(!ssh_principal_allowed(&targets, "ubuntu"));
    }
}
