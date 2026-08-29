//! Gateway access log ingestion: parse newline-delimited JSON access logs
//! (the common NGINX and Envoy JSON log formats) into a normalized
//! `TrafficRecord`, so `lifecycle.rs` doesn't need to know which gateway
//! produced the log.
//!
//! This deliberately only reads a status code and method/path, not a
//! response body — plain access logs don't carry one. See the "Honesty
//! note on scope" in ROADMAP.md Phase 2.2 for why response-shape drift
//! detection isn't attempted here.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TrafficRecord {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub timestamp: Option<String>,
    /// The caller identity, if the log carries one -- not every gateway
    /// log format does out of the box. `None` means "can't attribute",
    /// not "anonymous"; records without an identity still count toward
    /// Phase 2's endpoint-level lifecycle report but are excluded from
    /// Phase 4's per-identity analysis (see ROADMAP.md Phase 4.1).
    pub identity: Option<String>,
}

/// Field-name variants seen across common NGINX and Envoy JSON access-log
/// configs, tried in order per record.
const METHOD_FIELDS: &[&str] = &["request_method", "method", "http_method"];
const PATH_FIELDS: &[&str] = &["request_uri", "path", "uri", "url_path"];
const STATUS_FIELDS: &[&str] = &["status", "response_code", "status_code"];
const TIME_FIELDS: &[&str] = &["time", "timestamp", "start_time", "time_local"];
const IDENTITY_FIELDS: &[&str] = &[
    "user_id",
    "agent_id",
    "client_id",
    "remote_user",
    "identity",
    "sub",
];

/// Parse an NDJSON access log: one JSON object per line. Lines that are
/// blank, not valid JSON, or missing a recognizable method/path/status
/// triple are skipped rather than failing the whole parse — real gateway
/// log files routinely have rotation headers or partially-written lines.
pub fn parse_access_log(text: &str) -> Vec<TrafficRecord> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<TrafficRecord> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(trimmed).ok()?;

    let method = first_str_field(&value, METHOD_FIELDS)?.to_uppercase();
    let raw_path = first_str_field(&value, PATH_FIELDS)?;
    let path = raw_path.split('?').next().unwrap_or(raw_path).to_string();
    let status = first_status_field(&value, STATUS_FIELDS)?;
    let timestamp = first_str_field(&value, TIME_FIELDS).map(str::to_string);
    let identity = first_str_field(&value, IDENTITY_FIELDS).map(str::to_string);

    Some(TrafficRecord {
        method,
        path,
        status,
        timestamp,
        identity,
    })
}

fn first_str_field<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a str> {
    fields.iter().find_map(|f| value.get(f)?.as_str())
}

fn first_status_field(value: &Value, fields: &[&str]) -> Option<u16> {
    fields
        .iter()
        .find_map(|f| {
            let field = value.get(f)?;
            field
                .as_u64()
                .or_else(|| field.as_str()?.parse::<u64>().ok())
        })?
        .try_into()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_shaped_json_log() {
        let log = r#"{"time_local": "2026-08-27T10:00:00Z", "request_method": "get", "request_uri": "/widgets/42?verbose=1", "status": "200"}
{"time_local": "2026-08-27T10:00:01Z", "request_method": "post", "request_uri": "/widgets", "status": 500}"#;
        let records = parse_access_log(log);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].method, "GET");
        assert_eq!(records[0].path, "/widgets/42");
        assert_eq!(records[0].status, 200);
        assert_eq!(records[1].status, 500);
    }

    #[test]
    fn parses_envoy_shaped_json_log() {
        let log = r#"{"start_time": "2026-08-27T10:00:00Z", "method": "DELETE", "path": "/users/9", "response_code": 204}"#;
        let records = parse_access_log(log);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].method, "DELETE");
        assert_eq!(records[0].path, "/users/9");
        assert_eq!(records[0].status, 204);
    }

    #[test]
    fn extracts_identity_when_present_and_leaves_it_none_when_absent() {
        let log = "{\"request_method\": \"GET\", \"request_uri\": \"/widgets/1\", \"status\": 200, \"user_id\": \"alice\"}\n{\"request_method\": \"GET\", \"request_uri\": \"/widgets/2\", \"status\": 200}";
        let records = parse_access_log(log);
        assert_eq!(records[0].identity, Some("alice".to_string()));
        assert_eq!(records[1].identity, None);
    }

    #[test]
    fn skips_blank_and_malformed_lines_without_failing() {
        let log = "\n{ not json }\n{\"request_method\": \"GET\", \"request_uri\": \"/ok\", \"status\": 200}\n{\"request_method\": \"GET\"}\n";
        let records = parse_access_log(log);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "/ok");
    }
}
