//! Integration tests for `status_panel::task::store`.
//!
//! These tests run against a real (temp-file) SQLite database and exercise the
//! full public API of `TaskStore`, including multi-step workflows that combine
//! several operations.

use status_panel::task::store::{attenuate, TaskScopes, TaskStore};
use std::sync::Arc;
use std::thread;
use tempfile::NamedTempFile;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn temp_store() -> (TaskStore, NamedTempFile) {
    let f = NamedTempFile::new().expect("create temp file");
    let store = TaskStore::new(f.path().to_str().unwrap()).expect("open store");
    (store, f)
}

fn root_scopes() -> TaskScopes {
    TaskScopes {
        ssh_targets: vec!["10.0.0.1".into(), "10.0.0.2".into(), "10.0.0.3".into()],
        http_allow: vec![
            "https://api.example.com".into(),
            "https://cdn.example.com".into(),
        ],
        http_deny: vec![],
        trydirect_ops: vec!["read".into(), "deploy".into()],
        max_sub_agents: 8,
        max_depth: 4,
    }
}

// ── Schema / open ─────────────────────────────────────────────────────────────

#[test]
fn opening_same_db_twice_is_idempotent() {
    let f = NamedTempFile::new().unwrap();
    let path = f.path().to_str().unwrap();

    let s1 = TaskStore::new(path).unwrap();
    s1.insert_root("install-idem", root_scopes()).unwrap();

    // Second open on the same file must succeed and see the existing row.
    let s2 = TaskStore::new(path).unwrap();
    assert_eq!(s2.get_active_count("install-idem").unwrap(), 1);
}

// ── Root task ─────────────────────────────────────────────────────────────────

#[test]
fn root_task_has_correct_defaults() {
    let (store, _f) = temp_store();
    let rec = store.insert_root("install-root", root_scopes()).unwrap();

    assert_eq!(rec.depth, 0);
    assert_eq!(rec.epoch, 0);
    assert_eq!(rec.status, "active");
    assert!(rec.parent_id.is_none());
    assert!(rec.expires_at.is_none());
    assert!(!rec.task_id.is_empty());
    assert_eq!(rec.installation_id, "install-root");
}

#[test]
fn root_task_is_retrievable_by_id() {
    let (store, _f) = temp_store();
    let rec = store.insert_root("install-get", root_scopes()).unwrap();
    let fetched = store.get_by_id(&rec.task_id).unwrap().unwrap();

    assert_eq!(fetched.task_id, rec.task_id);
    assert_eq!(fetched.depth, rec.depth);
    assert_eq!(fetched.installation_id, rec.installation_id);
    assert_eq!(fetched.scopes.ssh_targets, rec.scopes.ssh_targets);
}

#[test]
fn get_by_id_returns_none_for_missing() {
    let (store, _f) = temp_store();
    let result = store.get_by_id("nonexistent-id").unwrap();
    assert!(result.is_none());
}

// ── Child tasks ───────────────────────────────────────────────────────────────

#[test]
fn child_task_inherits_parent_installation_and_epoch() {
    let (store, _f) = temp_store();
    let parent = store.insert_root("install-child", root_scopes()).unwrap();
    let child = store.insert_child(&parent, root_scopes(), None).unwrap();

    assert_eq!(child.installation_id, parent.installation_id);
    assert_eq!(child.epoch, parent.epoch);
    assert_eq!(child.depth, 1);
    assert_eq!(child.parent_id.as_deref(), Some(parent.task_id.as_str()));
}

#[test]
fn child_with_ttl_has_expires_at_set() {
    let (store, _f) = temp_store();
    let parent = store.insert_root("install-ttl", root_scopes()).unwrap();
    let child = store
        .insert_child(&parent, root_scopes(), Some(3600))
        .unwrap();

    let expires = child.expires_at.expect("expires_at should be set");
    assert!(expires > child.created_at);
    assert!(expires <= child.created_at + 3600 + 2); // small clock tolerance
}

#[test]
fn child_without_ttl_has_no_expiry() {
    let (store, _f) = temp_store();
    let parent = store.insert_root("install-nottl", root_scopes()).unwrap();
    let child = store.insert_child(&parent, root_scopes(), None).unwrap();
    assert!(child.expires_at.is_none());
}

// ── Scope attenuation ─────────────────────────────────────────────────────────

#[test]
fn child_ssh_targets_are_intersection_of_parent() {
    let (store, _f) = temp_store();
    let parent = store.insert_root("install-ssh", root_scopes()).unwrap();

    let requested = TaskScopes {
        ssh_targets: vec!["10.0.0.1".into(), "192.168.99.1".into()], // 192.168 not in parent
        ..root_scopes()
    };
    let child = store.insert_child(&parent, requested, None).unwrap();

    assert_eq!(child.scopes.ssh_targets, vec!["10.0.0.1"]);
}

#[test]
fn child_http_allow_is_intersection_of_parent() {
    let (store, _f) = temp_store();
    let parent = store
        .insert_root("install-http-allow", root_scopes())
        .unwrap();

    let requested = TaskScopes {
        http_allow: vec![
            "https://api.example.com".into(),
            "https://extra.not-allowed.com".into(),
        ],
        ..root_scopes()
    };
    let child = store.insert_child(&parent, requested, None).unwrap();

    assert_eq!(child.scopes.http_allow, vec!["https://api.example.com"]);
}

#[test]
fn child_http_deny_is_union_of_parent_and_requested() {
    let (store, _f) = temp_store();
    let mut scopes = root_scopes();
    scopes.http_deny = vec!["https://blocked.example.com".into()];
    let parent = store.insert_root("install-http-deny", scopes).unwrap();

    let requested = TaskScopes {
        http_deny: vec!["https://also-blocked.example.com".into()],
        ..root_scopes()
    };
    let child = store.insert_child(&parent, requested, None).unwrap();

    assert!(child
        .scopes
        .http_deny
        .contains(&"https://blocked.example.com".to_string()));
    assert!(child
        .scopes
        .http_deny
        .contains(&"https://also-blocked.example.com".to_string()));
}

#[test]
fn child_trydirect_ops_is_intersection_of_parent() {
    let (store, _f) = temp_store();
    let parent = store.insert_root("install-ops", root_scopes()).unwrap();

    let requested = TaskScopes {
        trydirect_ops: vec!["read".into(), "admin".into()], // "admin" not in parent
        ..root_scopes()
    };
    let child = store.insert_child(&parent, requested, None).unwrap();

    assert_eq!(child.scopes.trydirect_ops, vec!["read"]);
    assert!(!child.scopes.trydirect_ops.contains(&"admin".to_string()));
}

#[test]
fn child_max_sub_agents_is_min_of_parent_and_requested() {
    let (store, _f) = temp_store();
    let parent = store
        .insert_root("install-max-agents", root_scopes())
        .unwrap();

    let requested = TaskScopes {
        max_sub_agents: 2, // less than parent's 8
        ..root_scopes()
    };
    let child = store.insert_child(&parent, requested, None).unwrap();
    assert_eq!(child.scopes.max_sub_agents, 2);

    let requested_more = TaskScopes {
        max_sub_agents: 100, // more than parent's 8 — capped
        ..root_scopes()
    };
    let child2 = store.insert_child(&parent, requested_more, None).unwrap();
    assert_eq!(child2.scopes.max_sub_agents, 8);
}

// ── Depth limiting ────────────────────────────────────────────────────────────

#[test]
fn insert_child_at_max_depth_succeeds() {
    let (store, _f) = temp_store();
    let scopes = TaskScopes {
        max_depth: 2,
        ..root_scopes()
    };
    let root = store
        .insert_root("install-depth-ok", scopes.clone())
        .unwrap();
    let c1 = store.insert_child(&root, scopes.clone(), None).unwrap();
    let c2 = store.insert_child(&c1, scopes.clone(), None).unwrap();
    assert_eq!(c2.depth, 2);
}

#[test]
fn insert_child_beyond_max_depth_is_rejected() {
    let (store, _f) = temp_store();
    let scopes = TaskScopes {
        max_depth: 1,
        ..root_scopes()
    };
    let root = store
        .insert_root("install-depth-err", scopes.clone())
        .unwrap();
    let c1 = store.insert_child(&root, scopes.clone(), None).unwrap();

    let err = store
        .insert_child(&c1, scopes, None)
        .expect_err("should reject depth > max_depth");
    assert!(
        err.to_string().contains("depth limit exceeded"),
        "unexpected error: {err}"
    );
}

// ── Revoke cascade ────────────────────────────────────────────────────────────

#[test]
fn revoke_cascade_marks_all_descendants_revoked() {
    let (store, _f) = temp_store();
    let root = store.insert_root("install-cascade", root_scopes()).unwrap();
    let c1 = store.insert_child(&root, root_scopes(), None).unwrap();
    let c2 = store.insert_child(&c1, root_scopes(), None).unwrap();
    let c3 = store.insert_child(&c2, root_scopes(), None).unwrap();

    let count = store.revoke_cascade(&root.task_id).unwrap();
    assert_eq!(count, 4); // root + 3 children

    for id in [&root.task_id, &c1.task_id, &c2.task_id, &c3.task_id] {
        let rec = store.get_by_id(id).unwrap().unwrap();
        assert_eq!(rec.status, "revoked", "task {id} should be revoked");
        assert_eq!(rec.epoch, 1, "task {id} epoch should be incremented");
    }
}

#[test]
fn revoke_cascade_on_leaf_only_revokes_leaf() {
    let (store, _f) = temp_store();
    let root = store
        .insert_root("install-leaf-revoke", root_scopes())
        .unwrap();
    let child = store.insert_child(&root, root_scopes(), None).unwrap();

    let count = store.revoke_cascade(&child.task_id).unwrap();
    assert_eq!(count, 1);

    assert_eq!(
        store.get_by_id(&root.task_id).unwrap().unwrap().status,
        "active"
    );
    assert_eq!(
        store.get_by_id(&child.task_id).unwrap().unwrap().status,
        "revoked"
    );
}

#[test]
fn revoke_cascade_on_nonexistent_id_returns_zero() {
    let (store, _f) = temp_store();
    let count = store.revoke_cascade("no-such-id").unwrap();
    assert_eq!(count, 0);
}

// ── Active count ──────────────────────────────────────────────────────────────

#[test]
fn active_count_reflects_inserts_and_revocations() {
    let (store, _f) = temp_store();
    assert_eq!(store.get_active_count("install-count").unwrap(), 0);

    let root = store.insert_root("install-count", root_scopes()).unwrap();
    store.insert_child(&root, root_scopes(), None).unwrap();
    assert_eq!(store.get_active_count("install-count").unwrap(), 2);

    store.revoke_cascade(&root.task_id).unwrap();
    assert_eq!(store.get_active_count("install-count").unwrap(), 0);
}

#[test]
fn active_count_is_scoped_to_installation() {
    let (store, _f) = temp_store();
    store.insert_root("install-A", root_scopes()).unwrap();
    store.insert_root("install-A", root_scopes()).unwrap();
    store.insert_root("install-B", root_scopes()).unwrap();

    assert_eq!(store.get_active_count("install-A").unwrap(), 2);
    assert_eq!(store.get_active_count("install-B").unwrap(), 1);
    assert_eq!(store.get_active_count("install-C").unwrap(), 0);
}

// ── `attenuate` free function ─────────────────────────────────────────────────

#[test]
fn attenuate_empty_parent_yields_empty_child() {
    let parent = TaskScopes {
        ssh_targets: vec![],
        http_allow: vec![],
        http_deny: vec![],
        trydirect_ops: vec![],
        max_sub_agents: 0,
        max_depth: 0,
    };
    let requested = root_scopes();
    let result = attenuate(&parent, &requested);

    assert!(result.ssh_targets.is_empty());
    assert!(result.http_allow.is_empty());
    assert!(result.trydirect_ops.is_empty());
    assert_eq!(result.max_sub_agents, 0);
    assert_eq!(result.max_depth, 0);
}

#[test]
fn attenuate_deny_list_accumulates() {
    let parent = TaskScopes {
        http_deny: vec!["https://bad.example.com".into()],
        ..root_scopes()
    };
    let requested = TaskScopes {
        http_deny: vec![
            "https://bad.example.com".into(),
            "https://also-bad.example.com".into(),
        ],
        ..root_scopes()
    };
    let result = attenuate(&parent, &requested);

    // Union — deduplicated
    assert_eq!(result.http_deny.len(), 2);
    assert!(result
        .http_deny
        .contains(&"https://bad.example.com".to_string()));
    assert!(result
        .http_deny
        .contains(&"https://also-bad.example.com".to_string()));
}

// ── Thread safety ─────────────────────────────────────────────────────────────

#[test]
fn concurrent_inserts_from_multiple_threads() {
    let f = NamedTempFile::new().unwrap();
    let store = Arc::new(TaskStore::new(f.path().to_str().unwrap()).unwrap());

    // Insert a shared root then insert children from many threads simultaneously.
    let root = store.insert_root("install-threads", root_scopes()).unwrap();
    let root = Arc::new(root);

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = Arc::clone(&store);
            let root = Arc::clone(&root);
            thread::spawn(move || {
                store
                    .insert_child(&root, root_scopes(), None)
                    .expect("child insert should succeed")
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    // root + 8 children
    assert_eq!(store.get_active_count("install-threads").unwrap(), 9);
}
