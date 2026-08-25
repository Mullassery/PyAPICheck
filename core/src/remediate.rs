//! Automated spec-fix generation.
//!
//! Per the differentiator-gap note in ROADMAP.md: `risk.rs` only scores and
//! explains findings -- there was no path from a finding to an actual fix.
//! This module closes that gap for the subset of findings that have one
//! safe, mechanical, unambiguous fix:
//!
//! - `no_auth`: add a `security` requirement to the operation, but only
//!   referencing a scheme the spec *already declares* in
//!   `components.securitySchemes` -- this tool never invents an auth
//!   mechanism, it only wires up one the API author already set up and
//!   forgot to apply.
//! - `missing_metadata`: add a deterministic `operationId` derived from the
//!   method + path, so the endpoint has a stable identifier for tooling and
//!   ownership tracking.
//!
//! Findings with no safe automatic fix (`sensitive_data`,
//! `unauthenticated_sensitive_data`, `deprecated_still_live`) are
//! deliberately left advisory-only -- deciding what a sensitive field
//! *should* do, or whether a deprecated endpoint can be removed, is a
//! business decision this tool has no basis to make for you.

use crate::model::Endpoint;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SpecFix {
    pub path: String,
    pub method: String,
    pub factor_id: String,
    pub description: String,
    /// The single key this fix adds to the operation object -- "security"
    /// or "operationId". Carried as structured data (not just parsed back
    /// out of `description`) so both `apply_fixes` (JSON `Value`-based) and
    /// `text_patch` (line-based, format-preserving) build the exact same
    /// value from one source of truth.
    pub key: String,
    /// For `key == "security"`: the already-declared scheme name to
    /// reference.
    pub scheme_name: Option<String>,
    /// For `key == "operationId"`: the generated identifier.
    pub operation_id: Option<String>,
}

/// Compute the set of safe, mechanical fixes for the endpoints in `root`
/// that have a fixable risk factor. `endpoints` must have been produced by
/// discovering `root` itself (the two are matched by path+method).
pub fn compute_fixes(root: &Value, endpoints: &[Endpoint]) -> Vec<SpecFix> {
    let scheme_names = declared_security_scheme_names(root);
    let mut fixes = Vec::new();

    for ep in endpoints {
        for factor in &ep.risk.factors {
            match factor.id.as_str() {
                "no_auth" => {
                    if let Some(scheme) = scheme_names.first() {
                        fixes.push(SpecFix {
                            path: ep.path.clone(),
                            method: ep.method.clone(),
                            factor_id: "no_auth".to_string(),
                            description: format!(
                                "Add `security: [{{{scheme}: []}}]` to {} {} (references the \
                                 already-declared '{scheme}' scheme)",
                                ep.method, ep.path
                            ),
                            key: "security".to_string(),
                            scheme_name: Some(scheme.clone()),
                            operation_id: None,
                        });
                    }
                    // No securitySchemes declared anywhere in the spec: there is
                    // nothing safe to reference, so this finding stays
                    // advisory-only (same as the always-advisory factors below).
                }
                "missing_metadata" => {
                    let operation_id = generate_operation_id(&ep.method, &ep.path);
                    fixes.push(SpecFix {
                        path: ep.path.clone(),
                        method: ep.method.clone(),
                        factor_id: "missing_metadata".to_string(),
                        description: format!(
                            "Add `operationId: {operation_id}` to {} {}",
                            ep.method, ep.path
                        ),
                        key: "operationId".to_string(),
                        scheme_name: None,
                        operation_id: Some(operation_id),
                    });
                }
                _ => {}
            }
        }
    }

    fixes
}

/// Apply `fixes` to `root` in place. Returns the number of operations
/// actually modified (a fix whose target path/method/field no longer
/// matches the current document -- e.g. `root` drifted since `fixes` was
/// computed -- is silently skipped rather than panicking).
pub fn apply_fixes(root: &mut Value, fixes: &[SpecFix]) -> usize {
    let mut applied = 0;

    for fix in fixes {
        let method_lower = fix.method.to_lowercase();
        let Some(op) = root
            .pointer_mut(&format!("/paths/{}", escape_pointer(&fix.path)))
            .and_then(|p| p.get_mut(&method_lower))
        else {
            continue;
        };
        let Some(op_obj) = op.as_object_mut() else {
            continue;
        };

        match fix.key.as_str() {
            "security" => {
                let Some(scheme) = &fix.scheme_name else {
                    continue;
                };
                let mut requirement = serde_json::Map::new();
                requirement.insert(scheme.clone(), Value::Array(vec![]));
                op_obj.insert(
                    "security".to_string(),
                    Value::Array(vec![Value::Object(requirement)]),
                );
                applied += 1;
            }
            "operationId" => {
                let Some(operation_id) = &fix.operation_id else {
                    continue;
                };
                if op_obj.contains_key("operationId") {
                    continue;
                }
                op_obj.insert(
                    "operationId".to_string(),
                    Value::String(operation_id.clone()),
                );
                applied += 1;
            }
            _ => {}
        }
    }

    applied
}

/// JSON Pointer path segments (RFC 6901) need `~` and `/` escaped -- an
/// OpenAPI path like `/api/v1/customers/{id}` contains literal `/`
/// characters that must not be read as pointer separators.
fn escape_pointer(path: &str) -> String {
    path.replace('~', "~0").replace('/', "~1")
}

fn declared_security_scheme_names(root: &Value) -> Vec<String> {
    let mut names: Vec<String> = root
        .pointer("/components/securitySchemes")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}

/// Deterministic `operationId` from method + path, e.g.
/// `DELETE /api/v1/users/{id}` -> `delete_api_v1_users_by_id`.
fn generate_operation_id(method: &str, path: &str) -> String {
    let mut parts = vec![method.to_lowercase()];
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        if let Some(param) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            parts.push(format!("by_{}", sanitize_segment(param)));
        } else {
            parts.push(sanitize_segment(segment));
        }
    }
    parts.join("_")
}

fn sanitize_segment(segment: &str) -> String {
    segment
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EndpointDraft;
    use crate::{discover_from_str, risk};

    fn spec_with_unused_scheme() -> Value {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1.0"},
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
            },
            "paths": {
                "/widgets": {
                    "post": {
                        "security": [],
                        "summary": "Create a widget",
                        "requestBody": {"content": {}},
                        "responses": {"201": {"description": "ok"}}
                    }
                }
            }
        })
    }

    fn endpoint_for(root: &Value) -> Endpoint {
        let (_, _, drafts) = crate::openapi::parse_spec(root).unwrap();
        let draft: EndpointDraft = drafts.into_iter().next().unwrap();
        let risk = risk::score_endpoint(&draft);
        Endpoint {
            method: draft.method,
            path: draft.path,
            summary: draft.summary,
            operation_id: draft.operation_id,
            tags: draft.tags,
            deprecated: draft.deprecated,
            authenticated: draft.authenticated,
            auth_schemes: draft.auth_schemes,
            sensitive_fields: draft.sensitive_fields,
            risk,
            openapi_status: "documented".to_string(),
        }
    }

    #[test]
    fn no_auth_fix_references_declared_scheme() {
        let root = spec_with_unused_scheme();
        let endpoints = vec![endpoint_for(&root)];

        let fixes = compute_fixes(&root, &endpoints);

        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].factor_id, "no_auth");
        assert_eq!(fixes[0].path, "/widgets");
        assert_eq!(fixes[0].method, "POST");
        assert!(fixes[0].description.contains("bearerAuth"));
    }

    #[test]
    fn no_auth_produces_no_fix_when_no_scheme_declared() {
        let mut root = spec_with_unused_scheme();
        root.as_object_mut().unwrap().remove("components");
        let endpoints = vec![endpoint_for(&root)];

        let fixes = compute_fixes(&root, &endpoints);

        assert!(fixes.is_empty());
    }

    #[test]
    fn apply_fixes_writes_security_referencing_the_scheme() {
        let mut root = spec_with_unused_scheme();
        let endpoints = vec![endpoint_for(&root)];
        let fixes = compute_fixes(&root, &endpoints);

        let applied = apply_fixes(&mut root, &fixes);

        assert_eq!(applied, 1);
        let security = root.pointer("/paths/~1widgets/post/security").unwrap();
        assert_eq!(security, &serde_json::json!([{"bearerAuth": []}]));
    }

    #[test]
    fn apply_fixes_on_path_with_param_uses_correct_json_pointer() {
        let root = serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1.0"},
            "components": {
                "securitySchemes": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-Key"}}
            },
            "paths": {
                "/users/{id}": {
                    "delete": {
                        "security": [],
                        "summary": "Delete a user",
                        "responses": {"204": {"description": "ok"}}
                    }
                }
            }
        });
        let mut root = root;
        let endpoints = vec![endpoint_for(&root)];
        let fixes = compute_fixes(&root, &endpoints);

        let applied = apply_fixes(&mut root, &fixes);

        assert_eq!(applied, 1);
        assert_eq!(
            root.pointer("/paths/~1users~1{id}/delete/security")
                .unwrap(),
            &serde_json::json!([{"apiKey": []}])
        );
    }

    #[test]
    fn missing_metadata_fix_generates_deterministic_operation_id() {
        let root = serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1.0"},
            "paths": {
                "/users/{id}": {
                    "delete": {"security": [{"none": []}], "responses": {"204": {"description": "ok"}}}
                }
            }
        });
        assert_eq!(
            generate_operation_id("DELETE", "/users/{id}"),
            "delete_users_by_id"
        );
        let _ = root; // documents the shape used above; generation is unit-tested directly
    }

    #[test]
    fn apply_fixes_skips_missing_metadata_when_operation_id_already_present() {
        let mut root = serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1.0"},
            "paths": {
                "/widgets": {
                    "get": {"operationId": "listWidgets", "responses": {"200": {"description": "ok"}}}
                }
            }
        });
        let fixes = vec![SpecFix {
            path: "/widgets".to_string(),
            method: "GET".to_string(),
            factor_id: "missing_metadata".to_string(),
            description: "irrelevant".to_string(),
            key: "operationId".to_string(),
            scheme_name: None,
            operation_id: Some("listWidgets".to_string()),
        }];

        let applied = apply_fixes(&mut root, &fixes);

        assert_eq!(applied, 0);
        assert_eq!(
            root.pointer("/paths/~1widgets/get/operationId").unwrap(),
            "listWidgets"
        );
    }

    #[test]
    fn end_to_end_against_sample_fixture_fixes_both_unauthenticated_endpoints() {
        let spec_text = include_str!("../tests/fixtures/sample-openapi.yaml");
        let mut root: Value = serde_yaml::from_str(spec_text).unwrap();
        let inventory = discover_from_str(spec_text, "fixture").unwrap();

        let fixes = compute_fixes(&root, &inventory.endpoints);
        let no_auth_fixes: Vec<&SpecFix> =
            fixes.iter().filter(|f| f.factor_id == "no_auth").collect();
        assert_eq!(
            no_auth_fixes.len(),
            2,
            "refunds POST and users DELETE both lack auth"
        );

        let applied = apply_fixes(&mut root, &fixes);
        assert!(applied >= 2);

        assert_eq!(
            root.pointer("/paths/~1api~1v1~1refunds/post/security")
                .unwrap(),
            &serde_json::json!([{"bearerAuth": []}])
        );
        assert_eq!(
            root.pointer("/paths/~1api~1v1~1users~1{id}/delete/security")
                .unwrap(),
            &serde_json::json!([{"bearerAuth": []}])
        );

        // Re-discovering the patched spec must show these endpoints as
        // authenticated now -- the fix is a real behavioral change, not
        // just cosmetic JSON.
        let patched_text = serde_json::to_string(&root).unwrap();
        let re_discovered = discover_from_str(&patched_text, "patched").unwrap();
        let refunds = re_discovered
            .endpoints
            .iter()
            .find(|e| e.path == "/api/v1/refunds" && e.method == "POST")
            .unwrap();
        assert!(refunds.authenticated);
        let delete_user = re_discovered
            .endpoints
            .iter()
            .find(|e| e.path == "/api/v1/users/{id}" && e.method == "DELETE")
            .unwrap();
        assert!(delete_user.authenticated);
    }
}
