use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};
use ulid::Ulid;

// ── Schema ────────────────────────────────────────────────────────────────────

const CREATE_TABLE: &str = "
CREATE TABLE IF NOT EXISTS agent_task (
    task_id         TEXT PRIMARY KEY,
    parent_id       TEXT,
    installation_id TEXT NOT NULL,
    scopes          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active',
    epoch           INTEGER NOT NULL DEFAULT 0,
    depth           INTEGER NOT NULL DEFAULT 0,
    expires_at      INTEGER,
    created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent_task_parent ON agent_task(parent_id);
CREATE INDEX IF NOT EXISTS idx_agent_task_installation ON agent_task(installation_id);
";

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskScopes {
    pub ssh_targets: Vec<String>,
    pub http_allow: Vec<String>,
    pub http_deny: Vec<String>,
    pub trydirect_ops: Vec<String>,
    pub max_sub_agents: u32,
    pub max_depth: u32,
}

#[derive(Debug, Clone)]
pub struct TaskRecord {
    pub task_id: String,
    pub parent_id: Option<String>,
    pub installation_id: String,
    pub scopes: TaskScopes,
    pub status: String,
    pub epoch: i64,
    pub depth: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

// ── Scope attenuation ─────────────────────────────────────────────────────────

/// Returns a new `TaskScopes` that is at most as permissive as the parent.
///
/// - `ssh_targets`, `http_allow`, `trydirect_ops`: intersection (child can only keep
///   what parent already allows).
/// - `http_deny`: union (child inherits all parent denials plus its own).
/// - `max_sub_agents`, `max_depth`: minimum of parent and requested.
pub fn attenuate(parent: &TaskScopes, requested: &TaskScopes) -> TaskScopes {
    let intersect = |a: &[String], b: &[String]| -> Vec<String> {
        a.iter().filter(|x| b.contains(x)).cloned().collect()
    };
    let union = |a: &[String], b: &[String]| -> Vec<String> {
        let mut v = a.to_vec();
        for x in b {
            if !v.contains(x) {
                v.push(x.clone());
            }
        }
        v
    };

    TaskScopes {
        ssh_targets: intersect(&parent.ssh_targets, &requested.ssh_targets),
        http_allow: intersect(&parent.http_allow, &requested.http_allow),
        http_deny: union(&parent.http_deny, &requested.http_deny),
        trydirect_ops: intersect(&parent.trydirect_ops, &requested.trydirect_ops),
        max_sub_agents: parent.max_sub_agents.min(requested.max_sub_agents),
        max_depth: parent.max_depth.min(requested.max_depth),
    }
}

// ── Store ─────────────────────────────────────────────────────────────────────

pub struct TaskStore {
    conn: Mutex<Connection>,
}

impl TaskStore {
    /// Open (or create) the SQLite database at `db_path` and run the schema migration.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)
            .with_context(|| format!("failed to open task DB at {db_path}"))?;

        conn.execute_batch(CREATE_TABLE)
            .context("failed to create agent_task schema")?;

        info!(db_path, "TaskStore opened");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create a root task (depth 0, no parent).
    pub fn insert_root(&self, installation_id: &str, scopes: TaskScopes) -> Result<TaskRecord> {
        let task_id = Ulid::new().to_string();
        let scopes_json = serde_json::to_string(&scopes).context("serialize scopes")?;
        let now = unix_now();

        let record = TaskRecord {
            task_id: task_id.clone(),
            parent_id: None,
            installation_id: installation_id.to_string(),
            scopes,
            status: "active".to_string(),
            epoch: 0,
            depth: 0,
            expires_at: None,
            created_at: now,
        };

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_task \
             (task_id, parent_id, installation_id, scopes, status, epoch, depth, expires_at, created_at) \
             VALUES (?1, NULL, ?2, ?3, 'active', 0, 0, NULL, ?4)",
            params![task_id, installation_id, scopes_json, now],
        )
        .context("insert root task")?;

        debug!(task_id = %record.task_id, "inserted root task");
        Ok(record)
    }

    /// Create a child task derived from `parent` with attenuated scopes.
    ///
    /// Returns an error if the resulting depth would exceed `scopes.max_depth`.
    pub fn insert_child(
        &self,
        parent: &TaskRecord,
        scopes: TaskScopes,
        ttl_seconds: Option<u64>,
    ) -> Result<TaskRecord> {
        let child_depth = parent.depth + 1;
        let attenuated = attenuate(&parent.scopes, &scopes);

        if child_depth as u32 > attenuated.max_depth {
            return Err(anyhow!(
                "depth limit exceeded: child depth {} > max_depth {}",
                child_depth,
                attenuated.max_depth
            ));
        }

        let task_id = Ulid::new().to_string();
        let scopes_json = serde_json::to_string(&attenuated).context("serialize scopes")?;
        let now = unix_now();
        let expires_at = ttl_seconds.map(|ttl| now + ttl as i64);

        let record = TaskRecord {
            task_id: task_id.clone(),
            parent_id: Some(parent.task_id.clone()),
            installation_id: parent.installation_id.clone(),
            scopes: attenuated,
            status: "active".to_string(),
            epoch: parent.epoch,
            depth: child_depth,
            expires_at,
            created_at: now,
        };

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_task \
             (task_id, parent_id, installation_id, scopes, status, epoch, depth, expires_at, created_at) \
             VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8)",
            params![
                task_id,
                parent.task_id,
                parent.installation_id,
                scopes_json,
                parent.epoch,
                child_depth,
                expires_at,
                now,
            ],
        )
        .context("insert child task")?;

        debug!(
            task_id = %record.task_id,
            parent_id = %parent.task_id,
            depth = child_depth,
            "inserted child task"
        );
        Ok(record)
    }

    /// Fetch a single task by ID.
    pub fn get_by_id(&self, task_id: &str) -> Result<Option<TaskRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT task_id, parent_id, installation_id, scopes, status, \
                 epoch, depth, expires_at, created_at \
                 FROM agent_task WHERE task_id = ?1",
            )
            .context("prepare get_by_id")?;

        let mut rows = stmt
            .query_map(params![task_id], row_to_record)
            .context("query get_by_id")?;

        match rows.next() {
            Some(r) => Ok(Some(r.context("parse task row")?)),
            None => Ok(None),
        }
    }

    /// Revoke a task and all its descendants, incrementing their epoch.
    ///
    /// Returns the total number of rows updated.
    pub fn revoke_cascade(&self, task_id: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();

        // Collect the full subtree (including the root) via a recursive CTE.
        let mut stmt = conn
            .prepare(
                "WITH RECURSIVE subtree(id) AS (
                    SELECT task_id FROM agent_task WHERE task_id = ?1
                    UNION ALL
                    SELECT a.task_id FROM agent_task a
                    INNER JOIN subtree s ON a.parent_id = s.id
                )
                SELECT id FROM subtree",
            )
            .context("prepare subtree query")?;

        let ids: Vec<String> = stmt
            .query_map(params![task_id], |row| row.get(0))
            .context("query subtree")?
            .collect::<rusqlite::Result<_>>()
            .context("collect subtree ids")?;

        let mut count = 0u64;
        for id in &ids {
            let updated = conn
                .execute(
                    "UPDATE agent_task SET status = 'revoked', epoch = epoch + 1 WHERE task_id = ?1",
                    params![id],
                )
                .with_context(|| format!("revoke task {id}"))?;
            count += updated as u64;
        }

        info!(task_id, revoked = count, "revoke_cascade completed");
        Ok(count)
    }

    /// Count active tasks for a given installation.
    pub fn get_active_count(&self, installation_id: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agent_task WHERE installation_id = ?1 AND status = 'active'",
                params![installation_id],
                |row| row.get(0),
            )
            .context("get_active_count")?;
        Ok(count as u64)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs() as i64
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRecord> {
    let scopes_json: String = row.get(3)?;
    let scopes: TaskScopes = serde_json::from_str(&scopes_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(TaskRecord {
        task_id: row.get(0)?,
        parent_id: row.get(1)?,
        installation_id: row.get(2)?,
        scopes,
        status: row.get(4)?,
        epoch: row.get(5)?,
        depth: row.get(6)?,
        expires_at: row.get(7)?,
        created_at: row.get(8)?,
    })
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn open_store() -> (TaskStore, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let store = TaskStore::new(f.path().to_str().unwrap()).unwrap();
        (store, f)
    }

    fn default_scopes() -> TaskScopes {
        TaskScopes {
            ssh_targets: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec![],
            trydirect_ops: vec!["read".into(), "deploy".into()],
            max_sub_agents: 4,
            max_depth: 3,
        }
    }

    #[test]
    fn test_insert_root() {
        let (store, _f) = open_store();
        let scopes = default_scopes();
        let rec = store.insert_root("install-1", scopes).unwrap();

        assert_eq!(rec.depth, 0);
        assert!(rec.parent_id.is_none());
        assert_eq!(rec.status, "active");
        assert_eq!(rec.epoch, 0);
        assert_eq!(rec.installation_id, "install-1");
        assert!(!rec.task_id.is_empty());

        // Round-trip through DB
        let fetched = store.get_by_id(&rec.task_id).unwrap().unwrap();
        assert_eq!(fetched.task_id, rec.task_id);
        assert_eq!(fetched.depth, 0);
    }

    #[test]
    fn test_insert_child() {
        let (store, _f) = open_store();
        let parent = store.insert_root("install-2", default_scopes()).unwrap();

        let child_scopes = TaskScopes {
            ssh_targets: vec!["10.0.0.1".into()],
            http_allow: vec!["https://api.example.com".into()],
            http_deny: vec!["https://evil.example.com".into()],
            trydirect_ops: vec!["read".into()],
            max_sub_agents: 2,
            max_depth: 3,
        };
        let child = store
            .insert_child(&parent, child_scopes, Some(3600))
            .unwrap();

        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id.as_deref(), Some(parent.task_id.as_str()));
        assert_eq!(child.epoch, parent.epoch);

        // Scope attenuation: ssh_targets is intersection of parent ["10.0.0.1","10.0.0.2"]
        // and requested ["10.0.0.1"] → ["10.0.0.1"]
        assert_eq!(child.scopes.ssh_targets, vec!["10.0.0.1"]);
        // http_deny: union of parent [] and child ["https://evil.example.com"]
        assert!(child
            .scopes
            .http_deny
            .contains(&"https://evil.example.com".to_string()));
        // max_sub_agents: min(4, 2) = 2
        assert_eq!(child.scopes.max_sub_agents, 2);

        assert!(child.expires_at.is_some());
    }

    #[test]
    fn test_child_cannot_exceed_parent_scope() {
        let (store, _f) = open_store();
        let parent = store.insert_root("install-3", default_scopes()).unwrap();

        // Child requests a target the parent doesn't allow
        let child_scopes = TaskScopes {
            ssh_targets: vec!["10.0.0.1".into(), "192.168.1.1".into()],
            http_allow: vec![
                "https://api.example.com".into(),
                "https://extra.example.com".into(),
            ],
            http_deny: vec![],
            trydirect_ops: vec!["read".into(), "deploy".into(), "admin".into()],
            max_sub_agents: 99,
            max_depth: 99,
        };
        let child = store.insert_child(&parent, child_scopes, None).unwrap();

        // Only intersection with parent is kept
        assert_eq!(child.scopes.ssh_targets, vec!["10.0.0.1"]);
        assert_eq!(child.scopes.http_allow, vec!["https://api.example.com"]);
        assert!(!child.scopes.trydirect_ops.contains(&"admin".to_string()));
        assert_eq!(child.scopes.max_sub_agents, 4); // min(4, 99)
        assert_eq!(child.scopes.max_depth, 3); // min(3, 99)
    }

    #[test]
    fn test_revoke_cascade() {
        let (store, _f) = open_store();
        let root = store.insert_root("install-4", default_scopes()).unwrap();
        let child = store.insert_child(&root, default_scopes(), None).unwrap();

        let count = store.revoke_cascade(&root.task_id).unwrap();
        assert_eq!(count, 2);

        let root_after = store.get_by_id(&root.task_id).unwrap().unwrap();
        let child_after = store.get_by_id(&child.task_id).unwrap().unwrap();

        assert_eq!(root_after.status, "revoked");
        assert_eq!(child_after.status, "revoked");
        assert_eq!(root_after.epoch, root.epoch + 1);
        assert_eq!(child_after.epoch, child.epoch + 1);
    }

    #[test]
    fn test_depth_limit() {
        let (store, _f) = open_store();
        let shallow_scopes = TaskScopes {
            max_depth: 1,
            ..default_scopes()
        };
        let root = store
            .insert_root("install-5", shallow_scopes.clone())
            .unwrap();
        let child = store
            .insert_child(&root, shallow_scopes.clone(), None)
            .unwrap();

        // depth=2 exceeds max_depth=1 → error
        let err = store
            .insert_child(&child, shallow_scopes, None)
            .unwrap_err();
        assert!(err.to_string().contains("depth limit exceeded"), "{err}");
    }

    #[test]
    fn test_get_active_count() {
        let (store, _f) = open_store();
        let root = store.insert_root("install-6", default_scopes()).unwrap();
        store.insert_child(&root, default_scopes(), None).unwrap();

        assert_eq!(store.get_active_count("install-6").unwrap(), 2);

        store.revoke_cascade(&root.task_id).unwrap();
        assert_eq!(store.get_active_count("install-6").unwrap(), 0);
    }
}
