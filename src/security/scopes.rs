use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::info;

use crate::task::store::TaskScopes;

// ── Legacy flat scopes (kept for backward compatibility) ──────────────────────

#[derive(Debug, Clone, Default)]
pub struct Scopes {
    allowed: HashSet<String>,
}

impl Scopes {
    pub fn from_env() -> Self {
        let mut s = Self {
            allowed: HashSet::new(),
        };
        if let Ok(val) = std::env::var("AGENT_SCOPES") {
            for item in val.split(',') {
                let scope = item.trim();
                if !scope.is_empty() {
                    s.allowed.insert(scope.to_string());
                }
            }
        }
        s
    }

    pub fn is_allowed(&self, scope: &str) -> bool {
        if self.allowed.is_empty() {
            return true;
        }
        self.allowed.contains(scope)
    }
}

// ── Structured stack policy (fetched from Stacker) ────────────────────────────

/// The policy fetched from Stacker at startup and periodically refreshed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackPolicy {
    pub stack_code: String,
    pub max_depth: u32,
    pub max_sub_agents: u32,
    pub policy_version: i64,
    pub allowed_scopes: PolicyScopes,
    pub require_human_approval_above_depth: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyScopes {
    /// Glob patterns for allowed SSH targets.
    pub ssh_targets: Vec<String>,
    /// Glob patterns for allowed outbound HTTP URLs.
    pub http_allow: Vec<String>,
    /// Glob patterns for denied outbound HTTP URLs.
    pub http_deny: Vec<String>,
    /// Exact strings for allowed TryDirect operations.
    pub trydirect_ops: Vec<String>,
}

/// The live policy engine, held in `Arc<RwLock<Option<PolicyEngine>>>` in app state.
#[derive(Debug)]
pub struct PolicyEngine {
    pub stack_policy: StackPolicy,
    pub stack_code: String,
    /// Base URL of Stacker service (from `STACKER_URL` env var).
    pub stacker_url: String,
    /// Unique installation hash (from `INSTALLATION_HASH` env var).
    pub installation_hash: String,
}

impl PolicyEngine {
    /// Load policy from Stacker API on startup.
    ///
    /// `GET {stacker_url}/stacks/{stack_code}/agent_policy`
    /// with `X-Internal-Key: {INTERNAL_SERVICES_ACCESS_KEY}` header.
    pub async fn load(
        stack_code: &str,
        stacker_url: &str,
        installation_hash: &str,
    ) -> Result<Self> {
        let internal_key = std::env::var("INTERNAL_SERVICES_ACCESS_KEY")
            .map_err(|_| anyhow!("INTERNAL_SERVICES_ACCESS_KEY env var not set"))?;

        let policy = Self::fetch_policy(stack_code, stacker_url, &internal_key).await?;

        info!(
            "Loaded stack policy for '{}' (version {})",
            policy.stack_code, policy.policy_version
        );

        Ok(Self {
            stack_policy: policy,
            stack_code: stack_code.to_string(),
            stacker_url: stacker_url.to_string(),
            installation_hash: installation_hash.to_string(),
        })
    }

    /// Refresh policy from Stacker (call periodically, every 5 minutes).
    pub async fn refresh(&mut self) -> Result<()> {
        let internal_key = std::env::var("INTERNAL_SERVICES_ACCESS_KEY")
            .map_err(|_| anyhow!("INTERNAL_SERVICES_ACCESS_KEY env var not set"))?;

        let policy = Self::fetch_policy(&self.stack_code, &self.stacker_url, &internal_key).await?;

        info!(
            "Refreshed stack policy for '{}' (version {})",
            policy.stack_code, policy.policy_version
        );
        self.stack_policy = policy;
        Ok(())
    }

    async fn fetch_policy(
        stack_code: &str,
        stacker_url: &str,
        internal_key: &str,
    ) -> Result<StackPolicy> {
        let url = format!("{}/stacks/{}/agent_policy", stacker_url, stack_code);
        info!("Fetching stack policy from {}", url);

        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("X-Internal-Key", internal_key)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to reach Stacker for policy: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Stacker returned HTTP {} for policy fetch",
                response.status()
            ));
        }

        response
            .json::<StackPolicy>()
            .await
            .map_err(|e| anyhow!("Failed to parse policy JSON from Stacker: {}", e))
    }

    /// Check if a requested [`TaskScopes`] is within this stack's policy bounds.
    ///
    /// Returns `Err` with a descriptive reason if any scope exceeds the policy.
    pub fn validate_scopes(&self, requested: &TaskScopes) -> Result<()> {
        let policy = &self.stack_policy;

        if requested.max_depth > policy.max_depth {
            return Err(anyhow!(
                "Requested max_depth {} exceeds stack policy limit of {}",
                requested.max_depth,
                policy.max_depth
            ));
        }

        if requested.max_sub_agents > policy.max_sub_agents {
            return Err(anyhow!(
                "Requested max_sub_agents {} exceeds stack policy limit of {}",
                requested.max_sub_agents,
                policy.max_sub_agents
            ));
        }

        // Every requested SSH target must match at least one policy pattern.
        for target in &requested.ssh_targets {
            if !Self::glob_match(&policy.allowed_scopes.ssh_targets, target) {
                return Err(anyhow!(
                    "SSH target '{}' is not allowed by stack policy",
                    target
                ));
            }
        }

        // Every requested HTTP allow pattern must match at least one policy pattern.
        for url in &requested.http_allow {
            if !Self::glob_match(&policy.allowed_scopes.http_allow, url) {
                return Err(anyhow!(
                    "HTTP allow pattern '{}' is not permitted by stack policy",
                    url
                ));
            }
        }

        // Every requested TryDirect op must be in the policy (exact match).
        let policy_ops: HashSet<&str> = policy
            .allowed_scopes
            .trydirect_ops
            .iter()
            .map(String::as_str)
            .collect();
        for op in &requested.trydirect_ops {
            if !policy_ops.contains(op.as_str()) {
                return Err(anyhow!(
                    "TryDirect operation '{}' is not allowed by stack policy",
                    op
                ));
            }
        }

        Ok(())
    }

    /// Returns `true` if `value` matches at least one of the `patterns`.
    ///
    /// Pattern syntax:
    /// - `*`  — any sequence of characters **not** containing `/`
    /// - `**` — any sequence of characters including `/`
    /// - `?`  — exactly one character that is not `/`
    /// - All other characters match literally.
    fn glob_match(patterns: &[String], value: &str) -> bool {
        patterns
            .iter()
            .any(|p| Self::matches_pattern(p.as_bytes(), value.as_bytes()))
    }

    fn matches_pattern(pat: &[u8], val: &[u8]) -> bool {
        match pat.split_first() {
            // Pattern exhausted — value must also be exhausted.
            None => val.is_empty(),

            Some((&b'*', rest)) => {
                if rest.first() == Some(&b'*') {
                    // `**`: matches any prefix of val, including '/' separators.
                    let after_stars = &rest[1..];
                    for i in 0..=val.len() {
                        if Self::matches_pattern(after_stars, &val[i..]) {
                            return true;
                        }
                    }
                    false
                } else {
                    // `*`: matches any prefix of val that contains no '/'.
                    for i in 0..=val.len() {
                        if i > 0 && val[i - 1] == b'/' {
                            break;
                        }
                        if Self::matches_pattern(rest, &val[i..]) {
                            return true;
                        }
                    }
                    false
                }
            }

            // `?`: matches exactly one non-'/' character.
            Some((&b'?', rest)) => match val.split_first() {
                Some((&c, val_rest)) if c != b'/' => Self::matches_pattern(rest, val_rest),
                _ => false,
            },

            // Literal character: must match exactly.
            Some((&p, rest)) => match val.split_first() {
                Some((&v, val_rest)) if v == p => Self::matches_pattern(rest, val_rest),
                _ => false,
            },
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn make_engine(
        ssh_targets: &[&str],
        http_allow: &[&str],
        trydirect_ops: &[&str],
        max_depth: u32,
        max_sub_agents: u32,
    ) -> PolicyEngine {
        PolicyEngine {
            stack_code: "test-stack".to_string(),
            stacker_url: "http://stacker:8080".to_string(),
            installation_hash: "abc123".to_string(),
            stack_policy: StackPolicy {
                stack_code: "test-stack".to_string(),
                max_depth,
                max_sub_agents,
                policy_version: 1,
                allowed_scopes: PolicyScopes {
                    ssh_targets: strs(ssh_targets),
                    http_allow: strs(http_allow),
                    http_deny: vec![],
                    trydirect_ops: strs(trydirect_ops),
                },
                require_human_approval_above_depth: None,
            },
        }
    }

    #[test]
    fn test_glob_match_wildcard() {
        // `*` matches a single segment (no '/')
        assert!(PolicyEngine::glob_match(
            &strs(&["https://*.example.com/*"]),
            "https://api.example.com/foo"
        ));
    }

    #[test]
    fn test_glob_match_double_star() {
        // `**` crosses '/' separators, so it handles nested subdomains or deep paths
        assert!(PolicyEngine::glob_match(
            &strs(&["https://**.example.com/*"]),
            "https://a.b.example.com/path"
        ));
    }

    #[test]
    fn test_glob_no_match() {
        // An unrelated domain must not match
        assert!(!PolicyEngine::glob_match(
            &strs(&["https://*.example.com/*"]),
            "https://evil.com/attack"
        ));
    }

    #[test]
    fn test_validate_scopes_within_policy() {
        let engine = make_engine(
            &["*"],
            &["https://*.trydirect.app/*"],
            &["deployment:status", "deployment:logs"],
            3,
            10,
        );
        let requested = TaskScopes {
            ssh_targets: vec!["192.168.1.1".to_string()],
            http_allow: vec!["https://api.trydirect.app/v1".to_string()],
            http_deny: vec![],
            trydirect_ops: vec!["deployment:status".to_string()],
            max_depth: 2,
            max_sub_agents: 5,
        };
        assert!(engine.validate_scopes(&requested).is_ok());
    }

    #[test]
    fn test_validate_scopes_exceeds_ssh() {
        let engine = make_engine(
            &["10.0.0.*"],
            &["https://*.trydirect.app/*"],
            &["deployment:status"],
            3,
            10,
        );
        let requested = TaskScopes {
            ssh_targets: vec!["192.168.1.1".to_string()], // not in 10.0.0.*
            http_allow: vec![],
            http_deny: vec![],
            trydirect_ops: vec![],
            max_depth: 1,
            max_sub_agents: 1,
        };
        assert!(engine.validate_scopes(&requested).is_err());
    }

    #[test]
    fn test_validate_scopes_exceeds_ops() {
        let engine = make_engine(
            &["*"],
            &["https://*.trydirect.app/*"],
            &["deployment:status"],
            3,
            10,
        );
        let requested = TaskScopes {
            ssh_targets: vec![],
            http_allow: vec![],
            http_deny: vec![],
            trydirect_ops: vec!["deployment:delete".to_string()], // not in policy
            max_depth: 1,
            max_sub_agents: 1,
        };
        assert!(engine.validate_scopes(&requested).is_err());
    }
}
