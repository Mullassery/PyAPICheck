pub mod classify;
pub mod model;
pub mod openapi;
pub mod risk;

use model::{summarize, Endpoint, Inventory};
use std::fs;
use std::path::Path;

/// Parse OpenAPI spec text (YAML or JSON, auto-detected) into a full,
/// risk-scored inventory.
pub fn discover_from_str(spec_text: &str, source_label: &str) -> Result<Inventory, String> {
    let root: serde_json::Value = if spec_text.trim_start().starts_with('{') {
        serde_json::from_str(spec_text).map_err(|e| format!("invalid JSON: {e}"))?
    } else {
        serde_yaml::from_str(spec_text).map_err(|e| format!("invalid YAML: {e}"))?
    };

    let (title, api_version, drafts) = openapi::parse_spec(&root)?;

    let endpoints: Vec<Endpoint> = drafts
        .into_iter()
        .map(|d| {
            let risk = risk::score_endpoint(&d);
            Endpoint {
                method: d.method,
                path: d.path,
                summary: d.summary,
                operation_id: d.operation_id,
                tags: d.tags,
                deprecated: d.deprecated,
                authenticated: d.authenticated,
                auth_schemes: d.auth_schemes,
                sensitive_fields: d.sensitive_fields,
                risk,
                openapi_status: "documented".to_string(),
            }
        })
        .collect();

    let summary = summarize(&endpoints);

    Ok(Inventory {
        source: source_label.to_string(),
        title,
        api_version,
        endpoints,
        summary,
    })
}

/// Read an OpenAPI spec file from disk and discover its inventory.
pub fn discover_from_file(path: &Path) -> Result<Inventory, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    discover_from_str(&text, &path.display().to_string())
}
