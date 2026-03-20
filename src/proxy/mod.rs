//! HTTP proxy with SSRF protection and task-token scope enforcement.
//!
//! AI agents send HTTP requests through this proxy instead of making direct
//! outbound calls. The broker enforces allow/deny lists and SSRF protections
//! before forwarding the request.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::comms::local_api::AppState;
use crate::task::token;

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ProxyRequest {
    pub method: String,
    pub url: String,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

#[derive(Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

// ── SSRF detection ────────────────────────────────────────────────────────────

/// Returns `true` if the IP is private, loopback, link-local, or unspecified.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local / AWS metadata)
            || (octets[0] == 169 && octets[1] == 254)
            // 0.0.0.0/8
            || ip.is_unspecified()
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}

/// Validate a URL against the SSRF denylist.
///
/// Resolves the hostname to IPs and rejects any that fall into private/reserved
/// ranges. Returns `Ok(())` when the URL is safe to proxy.
async fn check_ssrf(url_str: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url_str).map_err(|_| "malformed URL".to_string())?;

    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Block IPv6 metadata address (fd00:ec2::254) before any DNS lookup.
    let host_clean = host.trim_matches(|c| c == '[' || c == ']');
    if host_clean.eq_ignore_ascii_case("fd00:ec2::254") {
        return Err("SSRF blocked: IPv6 EC2 metadata address".to_string());
    }

    // If the host is already an IP literal, check it directly — no DNS needed.
    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(format!("SSRF blocked: private/reserved IP {ip}"));
        }
        return Ok(());
    }

    // Reject "localhost" by name before DNS resolution.
    if host.eq_ignore_ascii_case("localhost") {
        return Err("SSRF blocked: localhost hostname".to_string());
    }

    // Resolve hostname and check every returned IP.
    let port = parsed.port_or_known_default().unwrap_or(80);
    let lookup_addr = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_addr)
        .await
        .map_err(|e| format!("DNS resolution failed for '{host}': {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS resolution returned no addresses for '{host}'"));
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(format!(
                "SSRF blocked: '{}' resolves to private/reserved IP {}",
                host,
                addr.ip()
            ));
        }
    }

    Ok(())
}

// ── Glob pattern matching ─────────────────────────────────────────────────────

/// Returns `true` if `value` matches at least one of the `patterns`.
///
/// Pattern syntax mirrors [`crate::security::scopes::PolicyEngine`]:
/// - `*`  — any characters excluding `/`
/// - `**` — any characters including `/`
/// - `?`  — exactly one non-`/` character
pub fn glob_match(patterns: &[String], value: &str) -> bool {
    patterns
        .iter()
        .any(|p| matches_pattern(p.as_bytes(), value.as_bytes()))
}

fn matches_pattern(pat: &[u8], val: &[u8]) -> bool {
    match pat.split_first() {
        None => val.is_empty(),
        Some((&b'*', rest)) => {
            if rest.first() == Some(&b'*') {
                let after_stars = &rest[1..];
                for i in 0..=val.len() {
                    if matches_pattern(after_stars, &val[i..]) {
                        return true;
                    }
                }
                false
            } else {
                for i in 0..=val.len() {
                    if i > 0 && val[i - 1] == b'/' {
                        break;
                    }
                    if matches_pattern(rest, &val[i..]) {
                        return true;
                    }
                }
                false
            }
        }
        Some((&b'?', rest)) => match val.split_first() {
            Some((&c, val_rest)) if c != b'/' => matches_pattern(rest, val_rest),
            _ => false,
        },
        Some((&p, rest)) => match val.split_first() {
            Some((&v, val_rest)) if v == p => matches_pattern(rest, val_rest),
            _ => false,
        },
    }
}

// ── Handler ───────────────────────────────────────────────────────────────────

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

fn error_json(status: StatusCode, message: &str) -> impl IntoResponse {
    (status, Json(serde_json::json!({ "error": message })))
}

/// `POST /proxy` — forward an HTTP request on behalf of an authenticated agent.
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ProxyRequest>,
) -> impl IntoResponse {
    // ── 1. Extract and verify task token ──────────────────────────────────────
    let task_token = match headers.get("x-task-token") {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                return error_json(
                    StatusCode::UNAUTHORIZED,
                    "invalid X-Task-Token header encoding",
                )
                .into_response()
            }
        },
        None => {
            return error_json(StatusCode::UNAUTHORIZED, "missing X-Task-Token header")
                .into_response()
        }
    };

    let task_store = &state.task_store;
    let broker_secret = &state.broker_secret;

    // Broker secret must be non-empty to verify tokens.
    if broker_secret.is_empty() {
        warn!("Proxy handler invoked but BROKER_SECRET is not configured");
        return error_json(StatusCode::UNAUTHORIZED, "proxy not configured").into_response();
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs() as i64;

    let claims = match token::verify(&task_token, broker_secret, task_store, now) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Task token verification failed");
            return error_json(StatusCode::UNAUTHORIZED, "invalid or expired token")
                .into_response();
        }
    };

    // ── 2. SSRF denylist ──────────────────────────────────────────────────────
    if let Err(reason) = check_ssrf(&req.url).await {
        warn!(url = %req.url, reason = %reason, "SSRF check blocked request");
        return error_json(StatusCode::FORBIDDEN, &reason).into_response();
    }

    // ── 3. Token http_allow — URL must match at least one allow pattern ───────
    if !glob_match(&claims.scopes.http_allow, &req.url) {
        warn!(url = %req.url, "URL not matched by token http_allow");
        return error_json(StatusCode::FORBIDDEN, "URL not permitted by token scopes")
            .into_response();
    }

    // ── 4. Token http_deny — URL must NOT match any deny pattern ─────────────
    if glob_match(&claims.scopes.http_deny, &req.url) {
        warn!(url = %req.url, "URL matched token http_deny");
        return error_json(StatusCode::FORBIDDEN, "URL denied by token scopes").into_response();
    }

    // ── 5. Method allowlist ───────────────────────────────────────────────────
    let method_upper = req.method.to_uppercase();
    if !ALLOWED_METHODS.contains(&method_upper.as_str()) {
        return error_json(
            StatusCode::BAD_REQUEST,
            &format!("method '{}' not allowed", req.method),
        )
        .into_response();
    }

    // ── 6. Build and forward the proxied request ──────────────────────────────
    debug!(url = %req.url, method = %method_upper, "Forwarding proxied request");

    let method = match reqwest::Method::from_bytes(method_upper.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return error_json(StatusCode::BAD_REQUEST, "invalid HTTP method").into_response()
        }
    };

    let mut builder = state.http_client.request(method, &req.url);

    if let Some(req_headers) = &req.headers {
        for (k, v) in req_headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                builder = builder.header(name, value);
            }
        }
    }

    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(url = %req.url, error = %e, "Upstream request failed");
            return error_json(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {e}"),
            )
            .into_response();
        }
    };

    let status = upstream.status().as_u16();
    let mut resp_headers = HashMap::new();
    for (k, v) in upstream.headers() {
        if let Ok(s) = v.to_str() {
            resp_headers.insert(k.to_string(), s.to_string());
        }
    }

    let body = match upstream.text().await {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "Failed to read upstream response body");
            return error_json(
                StatusCode::BAD_GATEWAY,
                "failed to read upstream response body",
            )
            .into_response();
        }
    };

    Json(ProxyResponse {
        status,
        headers: resp_headers,
        body,
    })
    .into_response()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── is_private_ip ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_private_ip_ranges() {
        // 10.0.0.0/8
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));

        // 172.16.0.0/12
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 15, 0, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));

        // 192.168.0.0/16
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))));

        // 127.0.0.0/8
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 1))));

        // 169.254.0.0/16 (link-local / AWS metadata)
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 255, 0, 1))));

        // 0.0.0.0
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));

        // Public IPs — must not be blocked
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(52, 0, 0, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(104, 16, 0, 0))));

        // IPv6 loopback / unspecified
        assert!(is_private_ip(IpAddr::V6("::1".parse().unwrap())));
        assert!(is_private_ip(IpAddr::V6("::".parse().unwrap())));

        // A non-special IPv6 address is not blocked
        assert!(!is_private_ip(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }

    // ── SSRF checks ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_ssrf_block_metadata_ip() {
        let result = check_ssrf("http://169.254.169.254/latest/meta-data/").await;
        assert!(result.is_err(), "AWS metadata IP must be blocked");
        assert!(
            result.unwrap_err().contains("SSRF"),
            "error should mention SSRF"
        );
    }

    #[tokio::test]
    async fn test_ssrf_block_localhost() {
        let result = check_ssrf("http://127.0.0.1/admin").await;
        assert!(result.is_err(), "127.0.0.1 must be blocked");
        assert!(
            result.unwrap_err().contains("SSRF"),
            "error should mention SSRF"
        );
    }

    #[tokio::test]
    async fn test_ssrf_block_private_range() {
        let result = check_ssrf("http://10.0.0.1/api").await;
        assert!(result.is_err(), "10.x private range must be blocked");
        assert!(
            result.unwrap_err().contains("SSRF"),
            "error should mention SSRF"
        );
    }

    #[tokio::test]
    async fn test_ssrf_block_localhost_hostname() {
        let result = check_ssrf("http://localhost/admin").await;
        assert!(result.is_err(), "localhost hostname must be blocked");
        assert!(
            result.unwrap_err().contains("SSRF"),
            "error should mention SSRF"
        );
    }

    #[tokio::test]
    async fn test_ssrf_block_ipv6_loopback() {
        let result = check_ssrf("http://[::1]/admin").await;
        assert!(result.is_err(), "IPv6 loopback must be blocked");
    }

    #[tokio::test]
    async fn test_ssrf_block_ipv6_metadata() {
        let result = check_ssrf("http://[fd00:ec2::254]/latest/meta-data/").await;
        assert!(result.is_err(), "IPv6 EC2 metadata address must be blocked");
    }

    // ── Allow/deny list logic ─────────────────────────────────────────────────

    #[test]
    fn test_allow_list_check() {
        // Simulate: token grants access to api.example.com only.
        let http_allow = vec!["https://api.example.com/**".to_string()];
        let target_url = "https://evil.example.com/data";

        // URL not in allow list → should be denied (returns false).
        assert!(
            !glob_match(&http_allow, target_url),
            "URL outside allow list must not match"
        );

        // URL inside allow list → should be permitted.
        assert!(
            glob_match(&http_allow, "https://api.example.com/v1/resource"),
            "URL inside allow list must match"
        );
    }

    #[test]
    fn test_deny_list_check() {
        // Simulate: deny list blocks a specific domain.
        let http_deny = vec!["https://blocked.example.com/**".to_string()];
        let denied_url = "https://blocked.example.com/api/v1";
        let allowed_url = "https://safe.example.com/api/v1";

        // URL in deny list → glob_match returns true → request must be blocked.
        assert!(
            glob_match(&http_deny, denied_url),
            "denied URL must match the deny pattern"
        );

        // URL not in deny list → glob_match returns false → request may proceed.
        assert!(
            !glob_match(&http_deny, allowed_url),
            "non-denied URL must not match the deny pattern"
        );
    }

    // ── Method validation ─────────────────────────────────────────────────────

    #[test]
    fn test_invalid_method() {
        // Forbidden methods.
        assert!(
            !ALLOWED_METHODS.contains(&"TRACE"),
            "TRACE must not be allowed"
        );
        assert!(
            !ALLOWED_METHODS.contains(&"CONNECT"),
            "CONNECT must not be allowed"
        );
        assert!(
            !ALLOWED_METHODS.contains(&"OPTIONS"),
            "OPTIONS must not be allowed"
        );

        // Allowed methods.
        assert!(ALLOWED_METHODS.contains(&"GET"));
        assert!(ALLOWED_METHODS.contains(&"POST"));
        assert!(ALLOWED_METHODS.contains(&"PUT"));
        assert!(ALLOWED_METHODS.contains(&"PATCH"));
        assert!(ALLOWED_METHODS.contains(&"DELETE"));
        assert!(ALLOWED_METHODS.contains(&"HEAD"));
    }

    // ── Glob pattern correctness ──────────────────────────────────────────────

    #[test]
    fn test_glob_match_double_star() {
        let patterns = vec!["https://api.example.com/**".to_string()];
        assert!(glob_match(&patterns, "https://api.example.com/v1/models"));
        assert!(glob_match(&patterns, "https://api.example.com/a/b/c/d"));
        assert!(!glob_match(&patterns, "https://api.evil.com/v1/models"));
    }

    #[test]
    fn test_glob_match_exact() {
        let patterns = vec!["https://api.example.com/v1/models".to_string()];
        assert!(glob_match(&patterns, "https://api.example.com/v1/models"));
        assert!(!glob_match(&patterns, "https://api.example.com/v1/other"));
    }
}
