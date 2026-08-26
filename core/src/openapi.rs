//! Minimal OpenAPI 3.x discovery: enough to extract endpoints, declared
//! authentication, and request/response field names for classification.
//!
//! This intentionally does not implement the full OpenAPI schema object model —
//! it resolves local `#/components/...` refs (with a cycle guard) and walks
//! `properties`/`items` far enough to find field names worth classifying. That
//! is sufficient for discovery + classification; it is not a spec validator.

use crate::classify::classify_field;
use crate::model::{EndpointDraft, SensitiveField};
use serde_json::Value;
use std::collections::HashSet;

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];
const MAX_SCHEMA_DEPTH: u8 = 4;

pub fn parse_spec(root: &Value) -> Result<(String, String, Vec<EndpointDraft>), String> {
    let title = root
        .pointer("/info/title")
        .and_then(|v| v.as_str())
        .unwrap_or("untitled API")
        .to_string();
    let api_version = root
        .pointer("/info/version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let global_security = root.get("security").cloned();

    let paths = root
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "OpenAPI spec has no 'paths' object".to_string())?;

    let mut drafts = Vec::new();

    for (path, path_item) in paths {
        let path_item_obj = match path_item.as_object() {
            Some(o) => o,
            None => continue,
        };

        for &method in HTTP_METHODS {
            let op = match path_item_obj.get(method) {
                Some(o) => o,
                None => continue,
            };

            let summary = op
                .get("summary")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let operation_id = op
                .get("operationId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let deprecated = op
                .get("deprecated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tags = op
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let effective_security = op
                .get("security")
                .cloned()
                .or_else(|| global_security.clone());
            let (authenticated, auth_schemes) = extract_security(&effective_security);

            let mut sensitive_fields: Vec<SensitiveField> = Vec::new();
            if let Some(content) = op.pointer("/requestBody/content") {
                collect_sensitive_from_content(content, root, "request", &mut sensitive_fields);
            }
            if let Some(responses) = op.get("responses").and_then(|v| v.as_object()) {
                for resp in responses.values() {
                    if let Some(content) = resp.get("content") {
                        collect_sensitive_from_content(
                            content,
                            root,
                            "response",
                            &mut sensitive_fields,
                        );
                    }
                }
            }
            dedupe_sensitive_fields(&mut sensitive_fields);

            drafts.push(EndpointDraft {
                method: method.to_uppercase(),
                path: path.clone(),
                summary,
                operation_id,
                tags,
                deprecated,
                authenticated,
                auth_schemes,
                sensitive_fields,
            });
        }
    }

    drafts.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    Ok((title, api_version, drafts))
}

fn dedupe_sensitive_fields(fields: &mut Vec<SensitiveField>) {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    fields.retain(|f| seen.insert((f.name.clone(), f.location.clone())));
}

/// Returns (authenticated, scheme_names). An explicit empty `security: []`
/// (at either operation or document level) means "no auth required", per the
/// OpenAPI spec — that is treated the same as auth being absent entirely.
fn extract_security(security: &Option<Value>) -> (bool, Vec<String>) {
    match security {
        Some(Value::Array(arr)) if !arr.is_empty() => {
            let mut schemes: Vec<String> = Vec::new();
            for requirement in arr {
                if let Some(obj) = requirement.as_object() {
                    for key in obj.keys() {
                        if !schemes.contains(key) {
                            schemes.push(key.clone());
                        }
                    }
                }
            }
            (!schemes.is_empty(), schemes)
        }
        _ => (false, Vec::new()),
    }
}

fn collect_sensitive_from_content(
    content: &Value,
    root: &Value,
    location: &str,
    out: &mut Vec<SensitiveField>,
) {
    let content_obj = match content.as_object() {
        Some(o) => o,
        None => return,
    };
    for media in content_obj.values() {
        if let Some(schema) = media.get("schema") {
            collect_fields(schema, root, location, out, 0);
        }
    }
}

fn resolve_ref(value: &Value, root: &Value, visited: &mut HashSet<String>) -> Value {
    if let Some(r) = value.get("$ref").and_then(|v| v.as_str()) {
        if visited.contains(r) {
            return Value::Null;
        }
        visited.insert(r.to_string());
        if let Some(stripped) = r.strip_prefix("#/") {
            if let Some(target) = root.pointer(&format!("/{stripped}")) {
                return resolve_ref(target, root, visited);
            }
        }
        return Value::Null;
    }
    value.clone()
}

fn collect_fields(
    schema: &Value,
    root: &Value,
    location: &str,
    out: &mut Vec<SensitiveField>,
    depth: u8,
) {
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }

    let resolved = resolve_ref(schema, root, &mut HashSet::new());

    if let Some(items) = resolved.get("items") {
        collect_fields(items, root, location, out, depth + 1);
        return;
    }

    if let Some(props) = resolved.get("properties").and_then(|v| v.as_object()) {
        for (name, prop_schema) in props {
            if let Some(classification) = classify_field(name) {
                out.push(SensitiveField {
                    name: name.clone(),
                    category: classification.category.to_string(),
                    confidence: classification.confidence,
                    location: location.to_string(),
                });
            }
            let resolved_prop = resolve_ref(prop_schema, root, &mut HashSet::new());
            if resolved_prop.get("properties").is_some() || resolved_prop.get("items").is_some() {
                collect_fields(&resolved_prop, root, location, out, depth + 1);
            }
        }
    }
}
