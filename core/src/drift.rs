//! OpenAPI drift detection: diff two already-discovered `Inventory`
//! snapshots and report added/removed/changed endpoints. Purely a
//! comparison over two `Inventory` values — resolving "two snapshots" to
//! actual spec text (two files, two Git revisions, ...) is the caller's
//! job; see `crate::diff_specs`/`diff_files`.

use crate::model::{Endpoint, Inventory, SensitiveField};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EndpointRef {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointChange {
    pub method: String,
    pub path: String,
    pub changes: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftReport {
    pub added: Vec<EndpointRef>,
    pub removed: Vec<EndpointRef>,
    pub changed: Vec<EndpointChange>,
}

fn key(e: &Endpoint) -> (&str, &str) {
    (e.method.as_str(), e.path.as_str())
}

fn sensitive_field_signature(fields: &[SensitiveField]) -> Vec<(String, String, String)> {
    let mut v: Vec<(String, String, String)> = fields
        .iter()
        .map(|f| (f.name.clone(), f.category.clone(), f.location.clone()))
        .collect();
    v.sort();
    v
}

/// Diff two inventories keyed on `(method, path)`.
pub fn diff_inventories(old: &Inventory, new: &Inventory) -> DriftReport {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for e in &old.endpoints {
        if !new.endpoints.iter().any(|n| key(n) == key(e)) {
            removed.push(EndpointRef {
                method: e.method.clone(),
                path: e.path.clone(),
            });
        }
    }

    for e in &new.endpoints {
        match old.endpoints.iter().find(|o| key(o) == key(e)) {
            None => added.push(EndpointRef {
                method: e.method.clone(),
                path: e.path.clone(),
            }),
            Some(o) => {
                let mut changes = Vec::new();

                if o.authenticated != e.authenticated {
                    changes.push(FieldChange {
                        field: "authenticated".to_string(),
                        before: o.authenticated.to_string(),
                        after: e.authenticated.to_string(),
                    });
                }
                if o.auth_schemes != e.auth_schemes {
                    changes.push(FieldChange {
                        field: "auth_schemes".to_string(),
                        before: format!("{:?}", o.auth_schemes),
                        after: format!("{:?}", e.auth_schemes),
                    });
                }
                if o.deprecated != e.deprecated {
                    changes.push(FieldChange {
                        field: "deprecated".to_string(),
                        before: o.deprecated.to_string(),
                        after: e.deprecated.to_string(),
                    });
                }
                let old_sig = sensitive_field_signature(&o.sensitive_fields);
                let new_sig = sensitive_field_signature(&e.sensitive_fields);
                if old_sig != new_sig {
                    changes.push(FieldChange {
                        field: "sensitive_fields".to_string(),
                        before: format!("{old_sig:?}"),
                        after: format!("{new_sig:?}"),
                    });
                }

                if !changes.is_empty() {
                    changed.push(EndpointChange {
                        method: e.method.clone(),
                        path: e.path.clone(),
                        changes,
                    });
                }
            }
        }
    }

    let by_path_method =
        |a: &EndpointRef, b: &EndpointRef| a.path.cmp(&b.path).then(a.method.cmp(&b.method));
    added.sort_by(by_path_method);
    removed.sort_by(by_path_method);
    changed.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    DriftReport {
        added,
        removed,
        changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover_from_str;

    const OLD_SPEC: &str = r#"
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
    delete:
      security: []
      responses:
        "200":
          description: ok
"#;

    const NEW_SPEC: &str = r#"
info:
  title: Svc
  version: "1.1"
paths:
  /widgets/{id}:
    delete:
      security:
        - bearerAuth: []
      responses:
        "200":
          description: ok
  /orders:
    post:
      responses:
        "200":
          description: ok
"#;

    #[test]
    fn detects_added_removed_and_changed_endpoints() {
        let old = discover_from_str(OLD_SPEC, "old").unwrap();
        let new = discover_from_str(NEW_SPEC, "new").unwrap();
        let report = diff_inventories(&old, &new);

        assert_eq!(report.added.len(), 1);
        assert_eq!(report.added[0].path, "/orders");

        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].path, "/widgets");

        assert_eq!(report.changed.len(), 1);
        assert_eq!(report.changed[0].path, "/widgets/{id}");
        assert!(report.changed[0]
            .changes
            .iter()
            .any(|c| c.field == "authenticated"));
    }

    #[test]
    fn identical_specs_produce_empty_report() {
        let old = discover_from_str(OLD_SPEC, "old").unwrap();
        let same = discover_from_str(OLD_SPEC, "old").unwrap();
        let report = diff_inventories(&old, &same);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert!(report.changed.is_empty());
    }
}
