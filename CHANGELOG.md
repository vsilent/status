# Changelog

## Unreleased — Extended Audit Log with Agent Events and Stacker Relay
### Added

- **`AuditEvent` enum** in `src/security/audit_log.rs`:
  - `AgentTaskCreated` — fires when an agent task is created (root or child).
  - `AgentTaskRevoked` — fires on revocation, includes cascade count.
  - `AgentTokenVerified` — records token verification success/failure per method.
  - `AgentProxyRequest` — records proxy requests (host-only for privacy), status, and whether blocked.
  - `AgentDelegation` — records parent→child delegation with scope reduction summary.
- **`AuditLogger::with_store(Arc<TaskStore>)`** — creates a logger that also buffers agent events to SQLite.
- **`AuditLogger::log_agent_event(event: AuditEvent)`** — emits via `tracing` and writes to the buffer table when a store is attached.
- **`agent_audit_buffer` SQLite table** (in the existing task DB):
  - Schema: `id`, `event_type`, `payload` (JSON), `created_at`, `relayed_at` (NULL until sent).
- **`TaskStore::buffer_audit_event`**, **`fetch_unrelayed_events`**, **`mark_events_relayed`** — buffer, query, and mark relay status.
- **`src/comms/stacker_relay.rs`** — background relay loop (`spawn_audit_relay`):
  - Runs every 30 seconds, batches up to 50 events.
  - POSTs to `{STACKER_URL}/api/v1/agent/audit` with `X-Internal-Key` auth.
  - On success marks events relayed; on failure logs warning and retries next cycle.
  - Gracefully skips when `STACKER_URL` is not set.
- **`GET /audit/recent?limit=50`** — internal endpoint to query unrelayed audit events.
  - Returns `[{"id", "event_type", "payload", "created_at"}]`.
  - Wired in `src/comms/local_api.rs`.
- **`AppState`** now initializes `AuditLogger::with_store(task_store.clone())` so all agent events are automatically buffered.
- **Task DB fallback**: if the configured `TASK_DB_PATH` can't be opened, falls back to an in-memory SQLite store (with a warning log) instead of panicking.
- **4 new unit tests** in `security::audit_log::tests`:
  - `test_audit_log_agent_task_created` — buffer round-trip with field validation.
  - `test_audit_log_proxy_request` — proxy event fields verified.
  - `test_audit_logger_without_store_does_not_panic` — logger works without a store.
  - `test_existing_methods_still_work` — backward compatibility.
- **2 new unit tests** in `task::store::tests`:
  - `test_buffer_and_fetch_events` — buffer 3 events, fetch returns all 3.
  - `test_mark_relayed_filters_out` — mark 2 relayed, only 1 returned.

## Unreleased — HTTP Proxy with SSRF Protection and Scope Enforcement
### Added — `proxy` module

- **`POST /proxy`** — HTTP proxy endpoint at `http://127.0.0.1:8090/proxy`.
  - AI agents submit requests through the broker instead of calling external APIs directly.
  - Request body: `{ "method", "url", "headers"?, "body"? }`.
  - Response: `{ "status", "headers", "body" }` on success; `{"error": "..."}` with appropriate HTTP status on failure.
- **SSRF hardcoded denylist** (cannot be overridden by token scopes):
  - Blocks `169.254.169.254` (AWS EC2 metadata) and `fd00:ec2::254` (IPv6 metadata).
  - Blocks RFC 1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
  - Blocks loopback: `127.0.0.0/8`, `localhost`, `::1`.
  - Blocks unspecified: `0.0.0.0`, `::`.
  - Resolves hostnames via `tokio::net::lookup_host` and checks every returned IP.
- **Token scope enforcement**: URL must match at least one `http_allow` glob pattern and must not match any `http_deny` pattern from the verified task token.
- **Method allowlist**: Only `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD` are accepted.
- **Error responses**: `401` (missing/invalid token), `403` (SSRF/scope blocked), `400` (bad method/URL), `502` (upstream failure).
- **`AppState`** updated with `http_client: reqwest::Client` — shared client with 30-second timeout, created once at startup.
- **`TaskStore`** — added manual `Debug` impl (required by `#[derive(Debug)]` on `AppState`).
- **`url = "2"`** added to `Cargo.toml` for URL parsing in SSRF checks.
- **14 unit tests** in `proxy::tests`:
  - `test_is_private_ip_ranges` — covers all private/reserved IPv4 and IPv6 ranges.
  - `test_ssrf_block_metadata_ip`, `test_ssrf_block_localhost`, `test_ssrf_block_private_range` — async SSRF checks for IP literals.
  - `test_ssrf_block_localhost_hostname`, `test_ssrf_block_ipv6_loopback`, `test_ssrf_block_ipv6_metadata` — name and IPv6 SSRF checks.
  - `test_allow_list_check`, `test_deny_list_check` — glob matching for scope enforcement.
  - `test_invalid_method` — `TRACE`/`CONNECT`/`OPTIONS` rejected, allowed methods pass.
  - `test_glob_match_double_star`, `test_glob_match_exact` — glob pattern correctness.

## Unreleased — MCP WebSocket Server (Agent Broker)
### Added — `mcp` module (sp-mcp-server)

- **`GET /mcp`** — WebSocket endpoint (JSON-RPC 2.0) exposed at `ws://127.0.0.1:8090/mcp`.
  - Internal Docker network only; authentication is per-request via task tokens (no separate handshake needed).
- **`mcp::types`** — `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcError` structs + standard error codes (`ERR_PARSE`, `ERR_INVALID_REQUEST`, `ERR_METHOD_NOT_FOUND`, `ERR_INVALID_PARAMS`, `ERR_APPLICATION`).
- **`mcp::tools`** — five MCP tool implementations:
  - `task/delegate` — mints a child task token (attenuated scopes, enforced depth limit) via `token::delegate`.
  - `task/info` — returns task metadata (id, depth, scopes, expiry, status) for a verified token.
  - `task/revoke` — cascading revocation of a task and its descendants; caller must be the direct parent.
  - `policy/get` — returns the live `StackPolicy` from `AppState::policy_engine`.
  - `ssh/request_cert` — stub returning `{status: "not_implemented"}` (Vault SSH coming in sp-vault-ssh).
- **`AppState`** updated with two new fields:
  - `task_store: Arc<TaskStore>` — opened from `TASK_DB_PATH` env var (default `/var/lib/status-panel/tasks.db`).
  - `broker_secret: Vec<u8>` — raw bytes of `BROKER_SECRET` env var; used for HMAC token signing.
- **`AppState::new_with_task_store()`** — test-only constructor for injecting an in-memory store.
- **11 unit tests** in `mcp::tests`: JSON-RPC parse, method-not-found, invalid version, parse error, `task/info` happy-path and error paths, `task/delegate` depth-limit and success, `task/revoke` non-parent rejection, `ssh/request_cert` stub.

## Unreleased — Structured Policy Engine (Agent Broker)
### Changed / Added — `security::scopes` module

- **`PolicyEngine`** — new structured policy evaluator held in `Arc<RwLock<Option<PolicyEngine>>>` in `AppState`.
  - `PolicyEngine::load(stack_code, stacker_url, installation_hash)` — fetches the policy from Stacker at startup (`GET {stacker_url}/stacks/{stack_code}/agent_policy`) using `X-Internal-Key` header from `INTERNAL_SERVICES_ACCESS_KEY`.
  - `PolicyEngine::refresh()` — re-fetches the policy; called by a background tokio task every 300 seconds.
  - `PolicyEngine::validate_scopes(requested: &TaskScopes)` — enforces stack-level policy bounds: SSH target glob matching, HTTP allow glob matching, TryDirect ops exact match, `max_depth` and `max_sub_agents` ceiling checks.
  - `PolicyEngine::glob_match` / `matches_pattern` — pure-Rust glob matcher: `*` matches non-`/` chars, `**` crosses path separators, `?` matches one non-`/` char.
- **`StackPolicy`** / **`PolicyScopes`** — serde-serialisable structs mirroring the Stacker `GET /stacks/{code}/agent_policy` response.
- **Legacy `Scopes`** struct preserved unchanged for backward compatibility.
- **`AppState`** updated with `policy_engine: Arc<RwLock<Option<PolicyEngine>>>` field (initialised to `None`).
- **`serve()`** updated to: attempt `PolicyEngine::load` if `STACKER_URL` and `STACK_CODE` env vars are set; log a warning (not a fatal error) if loading fails; spawn the 5-minute refresh background task unconditionally.
- **New env vars** consumed: `STACKER_URL`, `STACK_CODE`, `INTERNAL_SERVICES_ACCESS_KEY` (already required by other services), `INSTALLATION_HASH` (already present).
- **6 unit tests** in `security::scopes::tests`: glob wildcard, double-star, no-match, validate within policy, SSH target rejection, TryDirect op rejection.

## Unreleased — Task Token Engine (Agent Broker)
### Added — `task::token` module (sp-task-token)

- `src/task/token.rs` — full HMAC-SHA256 task token engine:
  - `TaskTokenClaims` — signed payload struct (task_id, installation_id, parent_id, scopes, depth, epoch, iat, exp).
  - `mint(record, secret)` — serializes claims to JSON, base64url-encodes, appends HMAC-SHA256 signature. Format: `<base64url(payload)>.<base64url(sig)>`.
  - `verify(token, secret, store, now)` — decodes token, verifies signature with `subtle::ConstantTimeEq`, checks expiry, loads live DB record, validates epoch matches (revocation detection).
  - `delegate(parent_token, requested_scopes, installation_id, ttl_secs, secret, store, now)` — verifies parent, enforces depth limit, attenuates scopes, persists child task via `store.insert_child`, mints and returns child token.
  - `sign(secret, payload)` internal helper using `hmac`+`sha2` crates.
- `src/task/store.rs` — added `PartialEq` derive to `TaskScopes` (required by token tests).
- 6 unit tests: roundtrip, wrong-secret rejection, expiry, revocation epoch mismatch, depth limit, scope attenuation.

### Fixed — Stacker JWT signature verification (`stacker/src/connectors/admin_service/jwt.rs`)

- `parse_jwt_claims` now reads `JWT_SECRET` from environment and verifies the HMAC-SHA256 signature before accepting any token.
- Added `parse_jwt_claims_with_secret(token, secret)` internal helper for testability.
- Updated unit tests: `create_signed_jwt` helper generates properly signed tokens; added `test_wrong_secret_fails` and `test_tampered_payload_fails` tests.

## Unreleased — Task Store (Agent Broker Foundation)
### Added — `task::store` module (sp-task-store)

- New `rusqlite` (bundled) and `ulid` crate dependencies.
- `src/task/mod.rs` — module root exposing `store` and `token` (placeholder).
- `src/task/store.rs` — `TaskStore` backed by a local SQLite file (`agent_tasks.db` or `$TASK_DB_PATH`):
  - `agent_task` table with indexes on `parent_id` and `installation_id`, created on first open.
  - `TaskScopes` (serde Serialize/Deserialize) — SSH targets, HTTP allow/deny, TryDirect ops, sub-agent limits.
  - `TaskRecord` — in-memory representation of a task row.
  - `TaskStore::insert_root` — creates a depth-0 task with a ULID task ID.
  - `TaskStore::insert_child` — creates a child task with attenuated scopes; rejects if depth would exceed `max_depth`.
  - `TaskStore::get_by_id` — fetch a single task.
  - `TaskStore::revoke_cascade` — sets status to `revoked` and increments epoch for a task and all its descendants (recursive CTE).
  - `TaskStore::get_active_count` — counts active tasks per installation.
  - `attenuate(parent, requested)` free function — computes intersection/union/min across scope fields.
- 6 unit tests covering root creation, child insertion, scope attenuation, cascade revoke, depth limit enforcement, and active count.

- `tests/task_store_integration.rs` — 22 integration tests covering:
  - Schema idempotency (opening the same DB twice)
  - Root task defaults and round-trip retrieval
  - Child task TTL, epoch/depth inheritance
  - Scope attenuation (ssh_targets, http_allow/deny, trydirect_ops, limits)
  - Depth limit enforcement (at-limit succeeds, beyond-limit rejected)
  - Cascade revoke (full subtree, leaf-only, non-existent ID)
  - Active count scoped per installation
  - Thread safety (8 concurrent child inserts via `Arc<TaskStore>`)
  - `attenuate()` edge cases (empty parent, deny-list deduplication)

## 0.1.4 — 2026-03-13
### Added — CLI Improvements, Install Script & GitHub Releases

#### CI: GitHub Releases on Tags
- Added `v*` tag trigger to CI workflow
- New `create-release` job: downloads musl binary, generates SHA256 checksum, publishes GitHub Release via `softprops/action-gh-release@v2`
- Tag-triggered artifacts now use clean names without SHA suffix (e.g. `status-linux-x86_64-musl-v0.1.4`)

#### Install Script (`install.sh`)
- POSIX `sh` installer: `curl -sSfL .../install.sh | sh`
- Detects OS/arch (Linux x86_64 only initially)
- Queries GitHub API for latest release (no `jq` dependency)
- Supports `VERSION` env var to pin a specific version
- Supports `INSTALL_DIR` env var (default `/usr/local/bin`)
- Downloads musl binary, verifies SHA256 checksum, installs with `sudo` if needed

#### New CLI Subcommands (`src/main.rs`)
- `start <name>` — Start a stopped container (Docker)
- `health [name]` — Check container health for one or all containers (Docker)
- `logs <name> [-n lines]` — Fetch container logs with configurable line count (Docker)
- `metrics [--json]` — Print system metrics: CPU, memory, disk usage
- `update check` — Check for available updates against remote server
- `update apply [--version V]` — Download and verify an update
- `update rollback` — Rollback to the previous binary version

#### README
- Added "Quick Install" section with examples for latest install, version pinning, custom directory, and verification

## 2026-02-02
### Added - Container Exec & Server Resources Commands

#### New Stacker Commands (`commands/stacker.rs`)
- `ExecCommand` / `stacker.exec`: Execute commands inside running containers
  - Parameters: deployment_hash, app_code, command, timeout (1-120s)
  - **Security**: Blocks dangerous commands (rm -rf /, mkfs, dd if, shutdown, reboot, poweroff, halt, init 0/6, fork bombs)
  - Case-insensitive pattern matching for security blocks
  - Returns exit_code, stdout, stderr (output redacted for secrets)
  - Comprehensive test suite with 27 security tests

- `ServerResourcesCommand` / `stacker.server_resources`: Collect server metrics
  - Parameters: deployment_hash, include_disk, include_network, include_processes
  - Uses MetricsCollector for CPU, memory, disk, network, and process info
  - Returns structured JSON with system resource data

- `ListContainersCommand` / `stacker.list_containers`: List deployment containers
  - Parameters: deployment_hash, include_health, include_logs, log_lines (1-1000)
  - Returns container list with status, health info, and optional recent logs

#### Docker Module Updates (`agent/docker.rs`)
- Added `exec_in_container_with_output()`: Execute commands and capture stdout/stderr separately
  - Creates exec instance, starts with output capture
  - Waits for completion and inspects exit code
  - Returns structured (exit_code, stdout, stderr) tuple

#### Test Coverage
- `exec_command_security_tests`: 27 tests covering blocked commands, validation, timeout clamping
- `server_resources_command_tests`: 3 tests for parsing and validation
- `list_containers_command_tests`: 3 tests for parsing and log_lines clamping

## 2026-01-29
### Added - Unified Configuration Management Commands

#### New Stacker Commands (`commands/stacker.rs`)
- `FetchAllConfigs` / `stacker.fetch_all_configs`: Bulk fetch all app configs from Vault
  - Parameters: deployment_hash, app_codes (optional - fetch all if empty), apply, archive
  - Lists all available configs via Vault LIST operation
  - Optionally writes all configs to disk
  - Optionally creates tar.gz archive of all configs
  - Returns detailed summary with fetched/applied counts

- `DeployWithConfigs` / `stacker.deploy_with_configs`: Unified config+deploy operation
  - Parameters: deployment_hash, app_code, pull, force_recreate, apply_configs
  - Fetches docker-compose.yml from Vault (_compose key) and app-specific .env
  - Writes configs to disk before deployment
  - Delegates to existing deploy_app handler for container orchestration
  - Combines config and deploy results in single response

- `ConfigDiff` / `stacker.config_diff`: Detect configuration drift
  - Parameters: deployment_hash, app_codes (optional), include_diff
  - Compares SHA256 hashes of Vault configs vs deployed files
  - Reports status: synced, drifted, or missing for each app
  - Optionally includes line counts and content previews for drifted configs
  - Summary with total/synced/drifted/missing counts

#### Command Infrastructure
- Added normalize/validate/with_command_context for all new commands
- Integrated all new commands into execute_with_docker dispatch
- Added test cases for command parsing

## 2026-01-23
### Added - Vault Configuration Management

#### VaultClient Extensions (`security/vault_client.rs`)
- `AppConfig` struct: content, content_type, destination_path, file_mode, owner, group
- `fetch_app_config()`: Retrieve app configuration from Vault KV v2
- `store_app_config()`: Store app configuration in Vault
- `list_app_configs()`: List all app configurations for a deployment
- `delete_app_config()`: Remove app configuration from Vault
- `fetch_all_app_configs()`: Batch fetch all configs for a deployment
- Path template: `{prefix}/{deployment_hash}/apps/{app_name}/config`

#### New Stacker Commands (`commands/stacker.rs`)
- `FetchConfig` / `stacker.fetch_config`: Fetch app config from Vault
  - Parameters: deployment_hash, app_code, apply (optional - write to disk)
  - Returns config content, metadata, and destination path
- `ApplyConfig` / `stacker.apply_config`: Apply config to running container
  - Fetches config from Vault
  - Writes to specified destination path with file mode/owner settings
  - Optionally restarts container after config application
  - Supports `config_content` override to skip Vault fetch

#### Helper Functions
- `write_config_to_disk()`: Write config file with proper permissions (chmod, chown)

## 2026-01-22
### Added - Agent-Based App Deployment & Configuration Management

#### New Stacker Commands
- `stop` / `stacker.stop`: Gracefully stop a container with configurable timeout (1-300 seconds)
- `start` / `stacker.start`: Start a previously stopped container  
- `error_summary` / `stacker.error_summary`: Analyze container logs for error patterns
  - Categorizes errors (connection, timeout, memory, permission, database, network, auth)
  - Provides sample error messages (redacted for security)
  - Generates actionable recommendations based on error patterns

#### Docker Module Updates
- Added `docker::start()` function to start stopped containers
- Added `docker::stop_with_timeout()` for configurable graceful shutdown

#### Command Structs
- `StopCommand`: deployment_hash, app_code, timeout (default 30s)
- `StartCommand`: deployment_hash, app_code
- `ErrorSummaryCommand`: deployment_hash, app_code (optional), hours (1-168), redact

## Unreleased - 2026-01-09
- Added `health`, `logs`, and `restart` command handling with structured responses, log cursors, secret redaction, and Docker-backed execution paths.
- Expanded `CommandResult` metadata (deployment_hash, app_code, command_type, structured errors) to align `/api/v1/agent/commands/report` payloads with the Stacker integration schema.
- Known issue: containerized `status` binary fails to start on hosts with glibc versions older than 2.39; rebuild against the production base image or ship a musl-linked binary to restore compatibility.
- Changed: Docker builds now produce a statically linked musl binary (Dockerfile, Dockerfile.prod) to avoid glibc drift at runtime.
- Planned: align build and runtime images to avoid glibc drift; keep the musl-based build variant as the default container target.
- Planned: update CI to build and test using the production base image so linker/runtime errors are caught early.
- Planned: add a container startup smoke check to surface missing runtime dependencies before release.

