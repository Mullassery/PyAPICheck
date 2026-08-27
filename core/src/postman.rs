//! Postman Collection v2.1 import: normalize each leaf request into the
//! same `EndpointDraft` shape the OpenAPI parser produces, so the rest of
//! the pipeline (classification, risk scoring, reporting) doesn't need to
//! know which discovery source an endpoint came from.
//!
//! Postman collections carry examples, not a schema, so sensitive-field
//! detection here classifies literal key names found in query params and a
//! JSON request body — there is no `properties`/`$ref` graph to walk like
//! there is for OpenAPI.

use crate::classify::Classifier;
use crate::model::{dedupe_sensitive_fields, EndpointDraft, SensitiveField};
use serde_json::Value;

const MAX_BODY_DEPTH: u8 = 4;

/// A Postman collection is recognized by shape: a `item` array plus an
/// `info` object. (OpenAPI documents have neither at the top level.)
pub fn is_postman_collection(root: &Value) -> bool {
    root.get("info").is_some() && root.get("item").and_then(|v| v.as_array()).is_some()
}

pub fn parse_collection(
    root: &Value,
    classifier: &dyn Classifier,
) -> Result<(String, String, Vec<EndpointDraft>), String> {
    let title = root
        .pointer("/info/name")
        .and_then(|v| v.as_str())
        .unwrap_or("untitled collection")
        .to_string();

    let items = root
        .get("item")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Postman collection has no 'item' array".to_string())?;

    let collection_auth = root.get("auth");

    let mut drafts = Vec::new();
    walk_items(items, &[], collection_auth, classifier, &mut drafts);

    drafts.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    // Postman collections aren't versioned the way OpenAPI documents are;
    // "postman" makes the source format visible in the report/JSON output.
    Ok((title, "postman".to_string(), drafts))
}

fn walk_items(
    items: &[Value],
    tags: &[String],
    inherited_auth: Option<&Value>,
    classifier: &dyn Classifier,
    out: &mut Vec<EndpointDraft>,
) {
    for item in items {
        if let Some(sub_items) = item.get("item").and_then(|v| v.as_array()) {
            let mut nested_tags = tags.to_vec();
            if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                nested_tags.push(name.to_string());
            }
            let folder_auth = item.get("auth").or(inherited_auth);
            walk_items(sub_items, &nested_tags, folder_auth, classifier, out);
            continue;
        }

        let request = match item.get("request") {
            Some(r) => r,
            None => continue,
        };

        let summary = item.get("name").and_then(|v| v.as_str()).map(String::from);
        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        let path = extract_path(request);

        let has_auth_header = request
            .get("header")
            .and_then(|v| v.as_array())
            .map(|headers| headers.iter().any(is_nonempty_auth_header))
            .unwrap_or(false);

        let effective_auth = request.get("auth").or(inherited_auth);
        let auth_type = effective_auth
            .and_then(|a| a.get("type"))
            .and_then(|v| v.as_str());
        let is_explicit_noauth = auth_type == Some("noauth");

        let authenticated = !is_explicit_noauth && (auth_type.is_some() || has_auth_header);
        let auth_schemes = if is_explicit_noauth {
            Vec::new()
        } else if let Some(t) = auth_type {
            vec![t.to_string()]
        } else if has_auth_header {
            vec!["header:authorization".to_string()]
        } else {
            Vec::new()
        };

        let mut sensitive_fields = Vec::new();
        collect_from_query(request, classifier, &mut sensitive_fields);
        collect_from_body(request, classifier, &mut sensitive_fields);
        dedupe_sensitive_fields(&mut sensitive_fields);

        out.push(EndpointDraft {
            method,
            path,
            summary,
            operation_id: None,
            tags: tags.to_vec(),
            deprecated: false,
            authenticated,
            auth_schemes,
            sensitive_fields,
        });
    }
}

fn is_nonempty_auth_header(header: &Value) -> bool {
    let is_auth_key = header
        .get("key")
        .and_then(|v| v.as_str())
        .map(|k| k.eq_ignore_ascii_case("authorization"))
        .unwrap_or(false);
    let has_value = header
        .get("value")
        .and_then(|v| v.as_str())
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    is_auth_key && has_value
}

/// Prefer the structured `url.path` segment array (Postman's normalized
/// form); fall back to stripping the scheme+host off `url.raw`/a bare
/// string URL when a request was saved without structured path data.
fn extract_path(request: &Value) -> String {
    let url = request.get("url");

    if let Some(segments) = url.and_then(|u| u.get("path")).and_then(|v| v.as_array()) {
        let normalized: Vec<String> = segments
            .iter()
            .filter_map(|s| s.as_str())
            .map(normalize_segment)
            .collect();
        if !normalized.is_empty() {
            return format!("/{}", normalized.join("/"));
        }
    }

    let raw = match url {
        Some(Value::String(s)) => s.clone(),
        Some(obj) => obj
            .get("raw")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        None => String::new(),
    };
    strip_origin(&raw)
}

/// Postman path variables are `:id`; normalize to OpenAPI-style `{id}` so
/// paths read consistently regardless of discovery source. `{{env_var}}`
/// double-brace templating is flattened to single-brace for the same reason.
fn normalize_segment(segment: &str) -> String {
    if let Some(rest) = segment.strip_prefix(':') {
        format!("{{{rest}}}")
    } else {
        segment.replace("{{", "{").replace("}}", "}")
    }
}

fn strip_origin(raw: &str) -> String {
    let without_query = raw.split('?').next().unwrap_or("");
    if let Some(scheme_end) = without_query.find("://") {
        let after_scheme = &without_query[scheme_end + 3..];
        return match after_scheme.find('/') {
            Some(slash) => after_scheme[slash..].to_string(),
            None => "/".to_string(),
        };
    }
    if without_query.starts_with('/') {
        without_query.to_string()
    } else {
        format!("/{without_query}")
    }
}

fn collect_from_query(request: &Value, classifier: &dyn Classifier, out: &mut Vec<SensitiveField>) {
    if let Some(query) = request.pointer("/url/query").and_then(|v| v.as_array()) {
        for param in query {
            if let Some(key) = param.get("key").and_then(|v| v.as_str()) {
                push_if_classified(key, classifier, out);
            }
        }
    }
}

fn collect_from_body(request: &Value, classifier: &dyn Classifier, out: &mut Vec<SensitiveField>) {
    let Some(body) = request.get("body") else {
        return;
    };
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");

    match mode {
        "raw" => {
            if let Some(raw) = body.get("raw").and_then(|v| v.as_str()) {
                if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
                    collect_json_keys(&parsed, classifier, out, 0);
                }
            }
        }
        "urlencoded" | "formdata" => {
            if let Some(params) = body.get(mode).and_then(|v| v.as_array()) {
                for param in params {
                    if let Some(key) = param.get("key").and_then(|v| v.as_str()) {
                        push_if_classified(key, classifier, out);
                    }
                }
            }
        }
        _ => {}
    }
}

fn collect_json_keys(
    value: &Value,
    classifier: &dyn Classifier,
    out: &mut Vec<SensitiveField>,
    depth: u8,
) {
    if depth > MAX_BODY_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                push_if_classified(key, classifier, out);
                collect_json_keys(nested, classifier, out, depth + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_keys(item, classifier, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn push_if_classified(key: &str, classifier: &dyn Classifier, out: &mut Vec<SensitiveField>) {
    if let Some(classification) = classifier.classify(key) {
        out.push(SensitiveField {
            name: key.to_string(),
            category: classification.category.to_string(),
            confidence: classification.confidence,
            location: "request".to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::KeywordClassifier;

    fn sample_collection() -> Value {
        serde_json::json!({
            "info": {"name": "Demo API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "item": [
                {
                    "name": "Get widget",
                    "request": {
                        "method": "GET",
                        "header": [{"key": "Authorization", "value": "Bearer {{token}}"}],
                        "url": {"raw": "https://api.example.com/widgets/:id", "path": ["widgets", ":id"]}
                    }
                },
                {
                    "name": "Payments",
                    "item": [
                        {
                            "name": "Create refund",
                            "request": {
                                "method": "POST",
                                "url": {"raw": "https://api.example.com/refunds", "path": ["refunds"]},
                                "body": {"mode": "raw", "raw": "{\"account_number\": \"123\"}"}
                            }
                        }
                    ]
                }
            ]
        })
    }

    #[test]
    fn recognizes_postman_shape_and_not_openapi() {
        assert!(is_postman_collection(&sample_collection()));
        let openapi = serde_json::json!({"info": {}, "paths": {}});
        assert!(!is_postman_collection(&openapi));
    }

    #[test]
    fn normalizes_path_variables_and_detects_auth_header() {
        let (title, _, drafts) =
            parse_collection(&sample_collection(), &KeywordClassifier).unwrap();
        assert_eq!(title, "Demo API");

        let widget = drafts.iter().find(|d| d.path == "/widgets/{id}").unwrap();
        assert_eq!(widget.method, "GET");
        assert!(widget.authenticated);
        assert_eq!(
            widget.auth_schemes,
            vec!["header:authorization".to_string()]
        );
    }

    #[test]
    fn unauthenticated_request_with_sensitive_body_is_flagged() {
        let (_, _, drafts) = parse_collection(&sample_collection(), &KeywordClassifier).unwrap();
        let refund = drafts.iter().find(|d| d.path == "/refunds").unwrap();
        assert!(!refund.authenticated);
        assert!(refund
            .sensitive_fields
            .iter()
            .any(|f| f.name == "account_number" && f.category == "financial"));
        assert_eq!(refund.tags, vec!["Payments".to_string()]);
    }
}
