pub mod classify;
pub mod model;
pub mod openapi;
pub mod remediate;
pub mod risk;
pub mod text_patch;

use model::{summarize, Endpoint, Inventory};
use remediate::SpecFix;
use serde::Serialize;
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
    let text =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    discover_from_str(&text, &path.display().to_string())
}

#[derive(Debug, Clone, Serialize)]
pub struct RemediationPlan {
    pub fixes: Vec<SpecFix>,
    /// The spec text with every fix in `fixes` applied, serialized in the
    /// same format (YAML or JSON) as the input. Equal to the input text
    /// when `fixes` is empty.
    pub patched_spec_text: String,
}

/// Compute (but do not write to disk) the remediation plan for the OpenAPI
/// spec text `spec_text`: every safe, mechanical fix `remediate::compute_fixes`
/// finds, plus the fully patched document as text in the same format the
/// input was in.
pub fn remediate_from_str(spec_text: &str) -> Result<RemediationPlan, String> {
    let is_json = spec_text.trim_start().starts_with('{');
    let root: serde_json::Value = if is_json {
        serde_json::from_str(spec_text).map_err(|e| format!("invalid JSON: {e}"))?
    } else {
        serde_yaml::from_str(spec_text).map_err(|e| format!("invalid YAML: {e}"))?
    };

    let inventory = discover_from_str(spec_text, "")?;
    let fixes = remediate::compute_fixes(&root, &inventory.endpoints);

    // Insert each fix as a single new line directly into the original
    // text (see text_patch.rs) rather than round-tripping the whole
    // document through `Value` and re-serializing -- that would silently
    // alphabetize every key and drop YAML comments throughout the file,
    // not just at the fix site.
    let patched_spec_text = if fixes.is_empty() {
        spec_text.to_string()
    } else if is_json {
        text_patch::patch_json_text(spec_text, &fixes)
    } else {
        text_patch::patch_yaml_text(spec_text, &fixes)
    };

    Ok(RemediationPlan {
        fixes,
        patched_spec_text,
    })
}

/// Read an OpenAPI spec file from disk and compute its remediation plan.
pub fn remediate_from_file(path: &Path) -> Result<RemediationPlan, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    remediate_from_str(&text)
}
