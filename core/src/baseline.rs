//! Behavioral baselining (Phase 4): per-identity traffic statistics,
//! sequential-ID (BOLA-shaped) access detection, and first-time-observed-
//! operation detection. All three are pure computations over
//! `TrafficRecord`s -- no database or graph connection required, matching
//! Phase 1/2's file-first discipline.

use crate::lifecycle::path_matches_template;
use crate::model::Inventory;
use crate::traffic::TrafficRecord;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct IdentityBaseline {
    pub identity: String,
    pub is_known_agent: bool,
    pub total_requests: usize,
    /// Count of distinct (method, concrete-path) pairs -- i.e. distinct
    /// resources touched, not distinct endpoint *templates* (an identity
    /// calling `GET /orders/{id}` against five different IDs counts as 5
    /// here, not 1; contrast with first-time-operation detection, which
    /// deliberately does key on the template -- see `operation_key`).
    pub distinct_resources: usize,
    pub error_rate: f64,
    pub requests_per_minute: f64,
    /// Coefficient of variation of inter-arrival times between consecutive
    /// requests, in order of appearance in the input -- low means
    /// machine-regular timing, high means bursty/irregular. `None` when
    /// fewer than 3 timestamped requests exist (not enough data for a
    /// meaningful spread). This is a raw statistic, not a verdict -- see
    /// ROADMAP.md Phase 4.2 for why `baseline.rs` doesn't classify
    /// undeclared identities as "agent-like" from this alone.
    pub timing_regularity: Option<f64>,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Build one baseline per distinct identity present in `traffic`. Records
/// with no identity are excluded (nothing to attribute them to).
pub fn build_baselines(
    traffic: &[TrafficRecord],
    known_agents: &HashSet<String>,
) -> Vec<IdentityBaseline> {
    let mut by_identity: HashMap<&str, Vec<&TrafficRecord>> = HashMap::new();
    for record in traffic {
        if let Some(identity) = &record.identity {
            by_identity
                .entry(identity.as_str())
                .or_default()
                .push(record);
        }
    }

    let mut baselines: Vec<IdentityBaseline> = by_identity
        .into_iter()
        .map(|(identity, records)| build_one_baseline(identity, &records, known_agents))
        .collect();
    baselines.sort_by(|a, b| a.identity.cmp(&b.identity));
    baselines
}

fn build_one_baseline(
    identity: &str,
    records: &[&TrafficRecord],
    known_agents: &HashSet<String>,
) -> IdentityBaseline {
    let total_requests = records.len();

    let distinct_resources: HashSet<(&str, &str)> = records
        .iter()
        .map(|r| (r.method.as_str(), r.path.as_str()))
        .collect();

    let error_count = records.iter().filter(|r| r.status >= 400).count();
    let error_rate = error_count as f64 / total_requests as f64;

    let mut timestamps: Vec<DateTime<Utc>> = records
        .iter()
        .filter_map(|r| r.timestamp.as_deref())
        .filter_map(parse_timestamp)
        .collect();
    timestamps.sort();

    let first_seen = timestamps.first().copied();
    let last_seen = timestamps.last().copied();

    let requests_per_minute = match (first_seen, last_seen) {
        (Some(first), Some(last)) if last > first => {
            let minutes = (last - first).num_seconds() as f64 / 60.0;
            if minutes > 0.0 {
                total_requests as f64 / minutes
            } else {
                0.0
            }
        }
        _ => 0.0,
    };

    let timing_regularity = coefficient_of_variation(&timestamps);

    IdentityBaseline {
        identity: identity.to_string(),
        is_known_agent: known_agents.contains(identity),
        total_requests,
        distinct_resources: distinct_resources.len(),
        error_rate,
        requests_per_minute,
        timing_regularity,
        first_seen,
        last_seen,
    }
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Coefficient of variation (stddev / mean) of inter-arrival seconds
/// between consecutive sorted timestamps. `None` if fewer than 3
/// timestamps (2 timestamps give exactly one interval -- no spread to
/// measure regularity from).
fn coefficient_of_variation(sorted_timestamps: &[DateTime<Utc>]) -> Option<f64> {
    if sorted_timestamps.len() < 3 {
        return None;
    }
    let intervals: Vec<f64> = sorted_timestamps
        .windows(2)
        .map(|w| (w[1] - w[0]).num_milliseconds() as f64 / 1000.0)
        .collect();

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean == 0.0 {
        return Some(0.0);
    }
    let variance =
        intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    Some(variance.sqrt() / mean)
}

#[derive(Debug, Clone, Serialize)]
pub struct BolaFinding {
    pub identity: String,
    pub method: String,
    pub path_template: String,
    /// Accessed IDs, in the order encountered in the input.
    pub accessed_ids: Vec<i64>,
    pub run_length: usize,
}

/// Flag identities that accessed a run of `min_run_length` or more
/// near-sequential (step of exactly +1 or -1) numeric IDs on the same
/// single-numeric-ID-parameter endpoint -- the classic BOLA-enumeration
/// signature ("try id=1, id=2, id=3, ..."). Endpoints with zero or more
/// than one path parameter, or a non-numeric one, are skipped: this
/// detector only claims to work where "the ID" is unambiguous.
pub fn detect_sequential_id_access(
    inventory: &Inventory,
    traffic: &[TrafficRecord],
    min_run_length: usize,
) -> Vec<BolaFinding> {
    let mut findings = Vec::new();

    for endpoint in &inventory.endpoints {
        let Some(param_index) = single_numeric_param_index(&endpoint.path) else {
            continue;
        };

        let mut by_identity: HashMap<&str, Vec<i64>> = HashMap::new();
        for record in traffic {
            let Some(identity) = &record.identity else {
                continue;
            };
            if record.method != endpoint.method {
                continue;
            }
            if !path_matches_template(&record.path, &endpoint.path) {
                continue;
            }
            if let Some(id) = extract_numeric_segment(&record.path, param_index) {
                by_identity.entry(identity.as_str()).or_default().push(id);
            }
        }

        for (identity, ids) in by_identity {
            let run_length = longest_sequential_run(&ids);
            if run_length >= min_run_length {
                findings.push(BolaFinding {
                    identity: identity.to_string(),
                    method: endpoint.method.clone(),
                    path_template: endpoint.path.clone(),
                    accessed_ids: ids,
                    run_length,
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        a.identity
            .cmp(&b.identity)
            .then(a.path_template.cmp(&b.path_template))
    });
    findings
}

/// If `template` has exactly one `{param}` segment, return its 0-based
/// segment index; otherwise `None` (zero or more than one -- ambiguous).
fn single_numeric_param_index(template: &str) -> Option<usize> {
    let segments: Vec<&str> = template
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let param_indices: Vec<usize> = segments
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with('{'))
        .map(|(i, _)| i)
        .collect();
    match param_indices.as_slice() {
        [index] => Some(*index),
        _ => None,
    }
}

fn extract_numeric_segment(observed_path: &str, index: usize) -> Option<i64> {
    let segments: Vec<&str> = observed_path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    segments.get(index)?.parse::<i64>().ok()
}

/// Longest run in `ids` (in input order) where each step is exactly +1 or
/// exactly -1 from the previous value.
fn longest_sequential_run(ids: &[i64]) -> usize {
    if ids.is_empty() {
        return 0;
    }
    let mut longest = 1;
    let mut current = 1;
    for window in ids.windows(2) {
        let step = window[1] - window[0];
        if step == 1 || step == -1 {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 1;
        }
    }
    longest
}

#[derive(Debug, Clone, Serialize)]
pub struct FirstTimeOperation {
    pub identity: String,
    pub method: String,
    /// The declared endpoint template this request matched (e.g.
    /// `/orders/{id}`), or the raw observed path for traffic that matches
    /// no declared endpoint. Templated, not the concrete resource path --
    /// otherwise every new resource ID (`/orders/7` after `/orders/6`)
    /// would count as a "new operation", which isn't the signal this is
    /// for. See `operation_key`.
    pub path: String,
    pub timestamp: Option<String>,
}

/// Reduce a traffic record to its "operation": the declared endpoint
/// template it matches, if any, else its own concrete path. Matching
/// against templates (not raw paths) is what makes "first-time operation"
/// mean "first time this identity called this endpoint" rather than
/// "first time this identity touched this exact resource ID" -- the
/// latter would fire on almost every request in real traffic.
fn operation_key<'a>(inventory: &'a Inventory, record: &'a TrafficRecord) -> &'a str {
    inventory
        .endpoints
        .iter()
        .find(|e| e.method == record.method && path_matches_template(&record.path, &e.path))
        .map(|e| e.path.as_str())
        .unwrap_or(record.path.as_str())
}

/// Every (identity, method, operation) in `current` that never appeared
/// for that identity in `historical` -- the exact trigger condition for
/// the product vision's worked scenario ("a known agent calls an
/// operation it's never called before"). "Operation" is the declared
/// endpoint template, not the concrete resource path (see `operation_key`).
pub fn detect_first_time_operations(
    inventory: &Inventory,
    historical: &[TrafficRecord],
    current: &[TrafficRecord],
) -> Vec<FirstTimeOperation> {
    let mut seen: HashSet<(&str, &str, &str)> = HashSet::new();
    for record in historical {
        if let Some(identity) = &record.identity {
            seen.insert((
                identity.as_str(),
                record.method.as_str(),
                operation_key(inventory, record),
            ));
        }
    }

    let mut findings = Vec::new();
    let mut flagged_this_batch: HashSet<(&str, &str, &str)> = HashSet::new();
    for record in current {
        let Some(identity) = &record.identity else {
            continue;
        };
        let op = operation_key(inventory, record);
        let key = (identity.as_str(), record.method.as_str(), op);
        if !seen.contains(&key) && flagged_this_batch.insert(key) {
            findings.push(FirstTimeOperation {
                identity: identity.clone(),
                method: record.method.clone(),
                path: op.to_string(),
                timestamp: record.timestamp.clone(),
            });
        }
    }

    findings.sort_by(|a, b| a.identity.cmp(&b.identity).then(a.path.cmp(&b.path)));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover_from_str;

    fn record(
        method: &str,
        path: &str,
        status: u16,
        identity: Option<&str>,
        ts: Option<&str>,
    ) -> TrafficRecord {
        TrafficRecord {
            method: method.to_string(),
            path: path.to_string(),
            status,
            timestamp: ts.map(String::from),
            identity: identity.map(String::from),
        }
    }

    #[test]
    fn baseline_computes_error_rate_and_distinct_resources() {
        let traffic = vec![
            record("GET", "/widgets/1", 200, Some("alice"), None),
            record("GET", "/widgets/2", 500, Some("alice"), None),
            record("POST", "/widgets", 201, Some("alice"), None),
            record("GET", "/widgets/1", 200, Some("bob"), None),
        ];
        let baselines = build_baselines(&traffic, &HashSet::new());
        assert_eq!(baselines.len(), 2);

        let alice = baselines.iter().find(|b| b.identity == "alice").unwrap();
        assert_eq!(alice.total_requests, 3);
        assert_eq!(alice.distinct_resources, 3);
        assert!((alice.error_rate - (1.0 / 3.0)).abs() < 1e-9);
        assert!(!alice.is_known_agent);
    }

    #[test]
    fn known_agent_flag_is_set_from_caller_supplied_set() {
        let traffic = vec![record("GET", "/x", 200, Some("finance-agent"), None)];
        let mut agents = HashSet::new();
        agents.insert("finance-agent".to_string());
        let baselines = build_baselines(&traffic, &agents);
        assert!(baselines[0].is_known_agent);
    }

    #[test]
    fn regular_machine_timing_has_low_coefficient_of_variation() {
        let traffic = vec![
            record("GET", "/x", 200, Some("bot"), Some("2026-08-27T10:00:00Z")),
            record("GET", "/x", 200, Some("bot"), Some("2026-08-27T10:00:10Z")),
            record("GET", "/x", 200, Some("bot"), Some("2026-08-27T10:00:20Z")),
            record("GET", "/x", 200, Some("bot"), Some("2026-08-27T10:00:30Z")),
        ];
        let baselines = build_baselines(&traffic, &HashSet::new());
        let regularity = baselines[0].timing_regularity.unwrap();
        assert!(
            regularity < 0.01,
            "expected near-zero CV for exact 10s spacing, got {regularity}"
        );
    }

    #[test]
    fn identity_less_records_are_excluded_from_baselines() {
        let traffic = vec![record("GET", "/x", 200, None, None)];
        assert!(build_baselines(&traffic, &HashSet::new()).is_empty());
    }

    const NUMERIC_ID_SPEC: &str = r#"
info:
  title: Svc
  version: "1.0"
paths:
  /widgets:
    get:
      responses:
        "200":
          description: ok
  /widgets/{id}:
    get:
      responses:
        "200":
          description: ok
    delete:
      responses:
        "200":
          description: ok
"#;

    #[test]
    fn detects_sequential_id_enumeration() {
        let inventory = discover_from_str(NUMERIC_ID_SPEC, "spec").unwrap();
        let traffic: Vec<TrafficRecord> = (1..=5)
            .map(|i| record("GET", &format!("/widgets/{i}"), 200, Some("attacker"), None))
            .collect();

        let findings = detect_sequential_id_access(&inventory, &traffic, 3);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].identity, "attacker");
        assert_eq!(findings[0].run_length, 5);
    }

    #[test]
    fn scattered_id_access_is_not_flagged() {
        let inventory = discover_from_str(NUMERIC_ID_SPEC, "spec").unwrap();
        let traffic = vec![
            record("GET", "/widgets/1", 200, Some("normal-user"), None),
            record("GET", "/widgets/88", 200, Some("normal-user"), None),
            record("GET", "/widgets/4", 200, Some("normal-user"), None),
        ];
        let findings = detect_sequential_id_access(&inventory, &traffic, 3);
        assert!(findings.is_empty());
    }

    #[test]
    fn first_time_operation_flags_only_the_genuinely_new_one() {
        let inventory = discover_from_str(NUMERIC_ID_SPEC, "spec").unwrap();
        let historical = vec![
            record("GET", "/widgets", 200, Some("finance-agent"), None),
            record("GET", "/widgets/1", 200, Some("finance-agent"), None),
        ];
        let current = vec![
            // Same operations as before, just a different resource ID --
            // must NOT be flagged (that's the bug this test guards against).
            record("GET", "/widgets", 200, Some("finance-agent"), None),
            record("GET", "/widgets/2", 200, Some("finance-agent"), None),
            record(
                "DELETE",
                "/widgets/1",
                200,
                Some("finance-agent"),
                Some("2026-08-27T12:00:00Z"),
            ),
        ];

        let findings = detect_first_time_operations(&inventory, &historical, &current);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].method, "DELETE");
        assert_eq!(findings[0].identity, "finance-agent");
        assert_eq!(findings[0].path, "/widgets/{id}");
    }

    #[test]
    fn first_time_operation_is_deduped_within_the_same_batch() {
        let inventory = discover_from_str(NUMERIC_ID_SPEC, "spec").unwrap();
        let current = vec![
            record("GET", "/undeclared", 200, Some("agent"), None),
            record("GET", "/undeclared", 200, Some("agent"), None),
        ];
        let findings = detect_first_time_operations(&inventory, &[], &current);
        assert_eq!(findings.len(), 1);
    }
}
