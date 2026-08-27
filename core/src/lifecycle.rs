//! Observed-vs-declared classification: cross-reference a discovered
//! `Inventory` (what's declared) against parsed `TrafficRecord`s (what's
//! actually being called) to find shadow and zombie endpoints.
//!
//! `drifted` (response shape differs from the declared schema) is
//! intentionally not implemented here — see ROADMAP.md Phase 2.2.

use crate::model::Inventory;
use crate::traffic::TrafficRecord;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct ActiveEndpoint {
    pub method: String,
    pub path: String,
    pub request_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZombieEndpoint {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShadowEndpoint {
    pub method: String,
    pub path: String,
    pub request_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleReport {
    pub active: Vec<ActiveEndpoint>,
    pub zombie: Vec<ZombieEndpoint>,
    pub shadow: Vec<ShadowEndpoint>,
}

/// True if a concrete observed path matches a declared OpenAPI/Postman
/// path template: same segment count, and every non-`{param}` template
/// segment matches literally.
fn path_matches_template(observed: &str, template: &str) -> bool {
    let observed_segments: Vec<&str> = observed
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let template_segments: Vec<&str> = template
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if observed_segments.len() != template_segments.len() {
        return false;
    }

    observed_segments
        .iter()
        .zip(template_segments.iter())
        .all(|(obs, tpl)| tpl.starts_with('{') || obs == tpl)
}

/// Cross-reference declared endpoints against observed traffic. Every
/// declared endpoint is classified `active` (>=1 matching request) or
/// `zombie` (none, within the traffic window supplied); every observed
/// (method, path) matching no declared endpoint is `shadow`.
pub fn build_lifecycle_report(inventory: &Inventory, traffic: &[TrafficRecord]) -> LifecycleReport {
    let mut active = Vec::new();
    let mut zombie = Vec::new();

    // (method, path) -> whether at least one declared endpoint matched it.
    let mut matched_traffic: HashMap<(String, String), bool> = traffic
        .iter()
        .map(|r| ((r.method.clone(), r.path.clone()), false))
        .collect();

    for endpoint in &inventory.endpoints {
        let mut count = 0usize;
        for record in traffic {
            if record.method == endpoint.method
                && path_matches_template(&record.path, &endpoint.path)
            {
                count += 1;
                matched_traffic.insert((record.method.clone(), record.path.clone()), true);
            }
        }

        if count > 0 {
            active.push(ActiveEndpoint {
                method: endpoint.method.clone(),
                path: endpoint.path.clone(),
                request_count: count,
            });
        } else {
            zombie.push(ZombieEndpoint {
                method: endpoint.method.clone(),
                path: endpoint.path.clone(),
            });
        }
    }

    let mut shadow_counts: HashMap<(String, String), usize> = HashMap::new();
    for record in traffic {
        let key = (record.method.clone(), record.path.clone());
        if matched_traffic.get(&key) == Some(&false) {
            *shadow_counts.entry(key).or_insert(0) += 1;
        }
    }
    let mut shadow: Vec<ShadowEndpoint> = shadow_counts
        .into_iter()
        .map(|((method, path), request_count)| ShadowEndpoint {
            method,
            path,
            request_count,
        })
        .collect();

    active.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    zombie.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));
    shadow.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    LifecycleReport {
        active,
        zombie,
        shadow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover_from_str;
    use crate::traffic::parse_access_log;

    const SPEC: &str = r#"
info:
  title: Svc
  version: "1.0"
paths:
  /widgets/{id}:
    get:
      responses:
        "200":
          description: ok
  /widgets:
    post:
      responses:
        "200":
          description: ok
"#;

    #[test]
    fn classifies_active_zombie_and_shadow() {
        let inventory = discover_from_str(SPEC, "spec").unwrap();
        let log = r#"{"request_method": "GET", "request_uri": "/widgets/42", "status": 200}
{"request_method": "GET", "request_uri": "/widgets/43", "status": 200}
{"request_method": "DELETE", "request_uri": "/widgets/42", "status": 204}"#;
        let traffic = parse_access_log(log);

        let report = build_lifecycle_report(&inventory, &traffic);

        assert_eq!(report.active.len(), 1);
        assert_eq!(report.active[0].path, "/widgets/{id}");
        assert_eq!(report.active[0].request_count, 2);

        assert_eq!(report.zombie.len(), 1);
        assert_eq!(report.zombie[0].path, "/widgets");

        assert_eq!(report.shadow.len(), 1);
        assert_eq!(report.shadow[0].method, "DELETE");
        assert_eq!(report.shadow[0].path, "/widgets/42");
    }

    #[test]
    fn no_traffic_means_everything_declared_is_zombie() {
        let inventory = discover_from_str(SPEC, "spec").unwrap();
        let report = build_lifecycle_report(&inventory, &[]);
        assert_eq!(report.zombie.len(), 2);
        assert!(report.active.is_empty());
        assert!(report.shadow.is_empty());
    }
}
