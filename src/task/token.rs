//! Task Token Engine — mint, verify, and delegate capability tokens.
//!
//! Token format: `<base64url(payload_json)>.<base64url(hmac_sha256(secret, payload_b64))>`
//! where `payload_b64` is the base64url-encoded JSON (i.e. HMAC is over the first segment,
//! not the raw JSON, to avoid double-encoding edge-cases).

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::store::{attenuate, TaskRecord, TaskScopes, TaskStore};

type HmacSha256 = Hmac<Sha256>;

// ── Claims ────────────────────────────────────────────────────────────────────

/// Signed payload embedded in every task token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskTokenClaims {
    /// ULID of the task this token is bound to.
    pub task_id: String,
    pub installation_id: String,
    pub parent_id: Option<String>,
    pub scopes: TaskScopes,
    pub depth: u32,
    /// Must match `epoch` in the DB row — incremented on revocation.
    pub epoch: i64,
    /// Unix timestamp at which the token was issued.
    pub iat: i64,
    /// Optional expiry (unix timestamp). `None` means no expiry.
    pub exp: Option<i64>,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs() as i64
}

fn sign(secret: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().to_vec()
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Mint a new token for an already-persisted [`TaskRecord`].
///
/// `secret` is the broker secret (32-byte random, from env `BROKER_SECRET`).
pub fn mint(record: &TaskRecord, secret: &[u8]) -> Result<String> {
    let claims = TaskTokenClaims {
        task_id: record.task_id.clone(),
        installation_id: record.installation_id.clone(),
        parent_id: record.parent_id.clone(),
        scopes: record.scopes.clone(),
        depth: record.depth as u32,
        epoch: record.epoch,
        iat: unix_now(),
        exp: record.expires_at,
    };

    let payload_json = serde_json::to_vec(&claims).context("serialize token claims")?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    let sig_bytes = sign(secret, payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Verify a token: check HMAC signature, expiry, and epoch against the live DB record.
///
/// Returns the decoded claims when every check passes.
pub fn verify(token: &str, secret: &[u8], store: &TaskStore, now: i64) -> Result<TaskTokenClaims> {
    // 1. Split on the single dot separator.
    let dot = token
        .find('.')
        .ok_or_else(|| anyhow!("invalid token format: missing '.'"))?;
    let payload_b64 = &token[..dot];
    let sig_b64 = &token[dot + 1..];

    // Guard: no second dot allowed (would indicate JWT or other formats).
    if sig_b64.contains('.') {
        return Err(anyhow!("invalid token format: too many '.' separators"));
    }

    // 2. Verify HMAC with constant-time comparison.
    let expected_sig = sign(secret, payload_b64.as_bytes());
    let actual_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .context("base64url-decode token signature")?;

    if !bool::from(expected_sig.as_slice().ct_eq(actual_sig.as_slice())) {
        return Err(anyhow!("token signature invalid"));
    }

    // 3. Decode payload.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("base64url-decode token payload")?;
    let claims: TaskTokenClaims =
        serde_json::from_slice(&payload_bytes).context("deserialize token claims")?;

    // 4. Check expiry.
    if let Some(exp) = claims.exp {
        if exp <= now {
            return Err(anyhow!("token expired (exp={exp}, now={now})"));
        }
    }

    // 5. Load the live DB record and check status.
    let record = store
        .get_by_id(&claims.task_id)
        .context("look up task record")?
        .ok_or_else(|| anyhow!("task '{}' not found in store", claims.task_id))?;

    if record.status != "active" {
        return Err(anyhow!(
            "task '{}' is not active (status={})",
            claims.task_id,
            record.status
        ));
    }

    // 6. Epoch check — mismatch means the token has been revoked.
    if claims.epoch != record.epoch {
        return Err(anyhow!(
            "token revoked: epoch mismatch (token={}, db={})",
            claims.epoch,
            record.epoch
        ));
    }

    Ok(claims)
}

/// Delegate: verify `parent_token`, attenuate scopes, persist a child task, and return
/// a freshly minted child token.
///
/// Enforces depth limit: `parent.depth < parent.scopes.max_depth`.
pub fn delegate(
    parent_token: &str,
    requested_scopes: &TaskScopes,
    installation_id: &str,
    ttl_secs: Option<u64>,
    secret: &[u8],
    store: &TaskStore,
    now: i64,
) -> Result<String> {
    // 1. Verify parent token.
    let parent_claims = verify(parent_token, secret, store, now)?;

    // Validate installation_id matches the token's claim.
    if parent_claims.installation_id != installation_id {
        return Err(anyhow!(
            "installation_id mismatch: token has '{}', requested '{}'",
            parent_claims.installation_id,
            installation_id
        ));
    }

    // 2. Enforce delegation depth limit before attempting the insert.
    if parent_claims.depth >= parent_claims.scopes.max_depth {
        return Err(anyhow!(
            "delegation depth limit reached: depth {} >= max_depth {}",
            parent_claims.depth,
            parent_claims.scopes.max_depth
        ));
    }

    // 3. Compute attenuated child scopes.
    let child_scopes = attenuate(&parent_claims.scopes, requested_scopes);

    // 4. Load parent record and persist child task.
    let parent_record = store
        .get_by_id(&parent_claims.task_id)
        .context("load parent record for delegation")?
        .ok_or_else(|| anyhow!("parent task '{}' not found", parent_claims.task_id))?;

    let child_record = store
        .insert_child(&parent_record, child_scopes, ttl_secs)
        .context("persist child task")?;

    // 5. Mint and return the child token.
    mint(&child_record, secret)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // ── Helpers ───────────────────────────────────────────────────────────────

    const SECRET: &[u8] = b"super-secret-32-byte-broker-key!";
    const WRONG_SECRET: &[u8] = b"wrong-secret-32-byte-broker-key!";

    fn open_store() -> (TaskStore, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = TaskStore::new(f.path().to_str().unwrap()).unwrap();
        (store, f)
    }

    fn full_scopes() -> TaskScopes {
        TaskScopes {
            ssh_targets: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec![],
            trydirect_ops: vec!["read".into(), "deploy".into()],
            max_sub_agents: 4,
            max_depth: 3,
        }
    }

    fn now() -> i64 {
        unix_now()
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_mint_verify_roundtrip() {
        let (store, _f) = open_store();
        let record = store.insert_root("install-1", full_scopes()).unwrap();

        let token = mint(&record, SECRET).unwrap();
        let claims = verify(&token, SECRET, &store, now()).unwrap();

        assert_eq!(claims.task_id, record.task_id);
        assert_eq!(claims.installation_id, "install-1");
        assert_eq!(claims.depth, 0);
        assert_eq!(claims.epoch, record.epoch);
        assert!(claims.parent_id.is_none());
        assert!(claims.exp.is_none());
    }

    #[test]
    fn test_verify_wrong_secret_fails() {
        let (store, _f) = open_store();
        let record = store.insert_root("install-2", full_scopes()).unwrap();
        let token = mint(&record, SECRET).unwrap();

        let err = verify(&token, WRONG_SECRET, &store, now()).unwrap_err();
        assert!(
            err.to_string().contains("signature invalid"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_expired_fails() {
        let (store, _f) = open_store();
        // expires_at = 1 second in the past
        let mut record = store.insert_root("install-3", full_scopes()).unwrap();
        record.expires_at = Some(now() - 1);

        let token = mint(&record, SECRET).unwrap();
        // Verify with `now` set past the expiry.
        let err = verify(&token, SECRET, &store, now()).unwrap_err();
        assert!(
            err.to_string().contains("expired"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_verify_revoked_fails() {
        let (store, _f) = open_store();
        let record = store.insert_root("install-4", full_scopes()).unwrap();
        let token = mint(&record, SECRET).unwrap();

        // Revoke increments epoch in DB — the token still carries the old epoch.
        store.revoke_cascade(&record.task_id).unwrap();

        let err = verify(&token, SECRET, &store, now()).unwrap_err();
        // Either status != active or epoch mismatch — both are acceptable.
        let msg = err.to_string();
        assert!(
            msg.contains("revoked") || msg.contains("not active") || msg.contains("epoch"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_delegate_depth_limit() {
        let (store, _f) = open_store();
        // max_depth = 1: only one level of delegation allowed.
        let shallow = TaskScopes {
            max_depth: 1,
            ..full_scopes()
        };
        let root = store.insert_root("install-5", shallow.clone()).unwrap();
        let root_token = mint(&root, SECRET).unwrap();

        // First delegation: depth 0 → 1, succeeds (0 < 1).
        let child_token = delegate(
            &root_token,
            &shallow,
            "install-5",
            None,
            SECRET,
            &store,
            now(),
        )
        .unwrap();

        // Second delegation: depth 1 = max_depth 1, must fail.
        let err = delegate(
            &child_token,
            &shallow,
            "install-5",
            None,
            SECRET,
            &store,
            now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("depth"), "unexpected error: {err}");
    }

    #[test]
    fn test_delegate_scope_attenuation() {
        let (store, _f) = open_store();
        let parent_scopes = full_scopes(); // ssh_targets: ["10.0.0.1", "10.0.0.2"]
        let root = store.insert_root("install-6", parent_scopes).unwrap();
        let root_token = mint(&root, SECRET).unwrap();

        // Request scopes that are a subset plus an extra target the parent doesn't have.
        let requested = TaskScopes {
            ssh_targets: vec!["10.0.0.1".into(), "192.168.99.1".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec!["https://evil.example.com".into()],
            trydirect_ops: vec!["read".into()],
            max_sub_agents: 2,
            max_depth: 3,
        };

        let child_token = delegate(
            &root_token,
            &requested,
            "install-6",
            Some(3600),
            SECRET,
            &store,
            now(),
        )
        .unwrap();

        let child_claims = verify(&child_token, SECRET, &store, now()).unwrap();

        // Intersection: "192.168.99.1" is not in parent → removed.
        assert_eq!(child_claims.scopes.ssh_targets, vec!["10.0.0.1"]);
        // http_deny: union of parent [] and requested ["https://evil.example.com"].
        assert!(child_claims
            .scopes
            .http_deny
            .contains(&"https://evil.example.com".to_string()));
        // max_sub_agents: min(4, 2) = 2.
        assert_eq!(child_claims.scopes.max_sub_agents, 2);
        // Only "read" is in both parent and requested trydirect_ops.
        assert_eq!(child_claims.scopes.trydirect_ops, vec!["read"]);
        // Child must have an expiry set.
        assert!(child_claims.exp.is_some());
        // Depth increases.
        assert_eq!(child_claims.depth, 1);
    }
}
