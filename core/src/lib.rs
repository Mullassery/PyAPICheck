pub mod baseline;
pub mod classify;
pub mod db;
pub mod discover_dir;
pub mod drift;
pub mod enforcement;
pub mod graph;
pub mod lifecycle;
pub mod mcp;
pub mod model;
pub mod openapi;
pub mod policy;
pub mod postman;
pub mod remediate;
pub mod risk;
pub mod text_patch;
pub mod traffic;

use classify::{Classifier, KeywordClassifier};
use model::{summarize, Endpoint, Inventory};
use remediate::SpecFix;
use serde::Serialize;
use std::fs;
use std::path::Path;

pub use baseline::{
    build_baselines, detect_first_time_operations, detect_sequential_id_access, BolaFinding,
    FirstTimeOperation, IdentityBaseline,
};
pub use discover_dir::discover_from_directory;
pub use drift::{diff_inventories, DriftReport};
pub use lifecycle::{build_lifecycle_report, LifecycleReport};
use std::collections::HashSet;
pub use traffic::{parse_access_log, TrafficRecord};

#[derive(Debug, Clone, Serialize)]
pub struct BaselineResult {
    pub baselines: Vec<IdentityBaseline>,
    pub bola_findings: Vec<BolaFinding>,
    pub first_time_operations: Vec<FirstTimeOperation>,
}

const BOLA_MIN_RUN_LENGTH: usize = 3;

/// Discover `spec_path`, then compute per-identity baselines (over
/// historical + current traffic combined), BOLA-shaped sequential-ID
/// findings (over current traffic), and first-time-observed-operation
/// findings (current vs. historical) -- see ROADMAP.md Phase 4.
pub fn baseline_from_files(
    spec_path: &Path,
    historical_log_path: &Path,
    current_log_path: &Path,
    known_agents: &HashSet<String>,
) -> Result<BaselineResult, String> {
    let inventory = discover_from_file(spec_path)?;

    let historical_text = fs::read_to_string(historical_log_path)
        .map_err(|e| format!("failed to read {}: {e}", historical_log_path.display()))?;
    let current_text = fs::read_to_string(current_log_path)
        .map_err(|e| format!("failed to read {}: {e}", current_log_path.display()))?;
    let historical = parse_access_log(&historical_text);
    let current = parse_access_log(&current_text);

    let mut combined = historical.clone();
    combined.extend(current.iter().cloned());

    Ok(BaselineResult {
        baselines: build_baselines(&combined, known_agents),
        bola_findings: detect_sequential_id_access(&inventory, &current, BOLA_MIN_RUN_LENGTH),
        first_time_operations: detect_first_time_operations(&inventory, &historical, &current),
    })
}

/// Parse and validate a Cedar policy file, surfacing Cedar's own parse
/// errors on failure.
pub fn validate_policy_file(path: &Path) -> Result<cedar_policy::PolicySet, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    policy::parse_policy_set(&text)
}

/// Parse a Cedar policy file and emit an Envoy RBAC HTTP filter config
/// snippet implementing its `forbid` policies -- see ROADMAP.md Phase 7.1.
/// `None` means there was nothing to translate (no `forbid` policies).
pub fn emit_envoy_rbac_from_file(path: &Path) -> Result<Option<String>, String> {
    let policy_set = validate_policy_file(path)?;
    Ok(enforcement::emit_envoy_rbac(&policy_set))
}

/// Run Phase 4's baseline detectors over the given spec/logs, then
/// generate Cedar policy recommendations from the findings -- see
/// ROADMAP.md Phase 6.2.
pub fn policy_recommendations_from_files(
    spec_path: &Path,
    historical_log_path: &Path,
    current_log_path: &Path,
    known_agents: &HashSet<String>,
) -> Result<Vec<policy::PolicyRecommendation>, String> {
    let result = baseline_from_files(
        spec_path,
        historical_log_path,
        current_log_path,
        known_agents,
    )?;
    let mut recommendations =
        policy::recommend_from_bola_findings(&result.bola_findings, known_agents)?;
    recommendations.extend(policy::recommend_from_first_time_operations(
        &result.first_time_operations,
        known_agents,
    )?);
    Ok(recommendations)
}

/// Run Phase 4's baseline detectors, then check each finding against an
/// existing Cedar policy file: findings the policy would currently
/// `Allow` are genuine gaps, returned with a ready-to-add `forbid` fix.
pub fn policy_diff_from_files(
    policy_path: &Path,
    spec_path: &Path,
    historical_log_path: &Path,
    current_log_path: &Path,
    known_agents: &HashSet<String>,
) -> Result<Vec<policy::PolicyGap>, String> {
    let policy_set = validate_policy_file(policy_path)?;
    let result = baseline_from_files(
        spec_path,
        historical_log_path,
        current_log_path,
        known_agents,
    )?;
    policy::diff_against_policy(
        &policy_set,
        &result.bola_findings,
        &result.first_time_operations,
        known_agents,
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportResult {
    pub inventory: Inventory,
    pub lifecycle: LifecycleReport,
}

/// Discover a spec file and cross-reference it against a parsed gateway
/// access log to produce a combined risk + lifecycle report.
pub fn report_from_files(spec_path: &Path, access_log_path: &Path) -> Result<ReportResult, String> {
    let inventory = discover_from_file(spec_path)?;
    let log_text = fs::read_to_string(access_log_path)
        .map_err(|e| format!("failed to read {}: {e}", access_log_path.display()))?;
    let traffic = parse_access_log(&log_text);
    let lifecycle = build_lifecycle_report(&inventory, &traffic);
    Ok(ReportResult {
        inventory,
        lifecycle,
    })
}

/// Parse spec text (OpenAPI YAML/JSON, or a Postman Collection v2.1 JSON
/// export — auto-detected by shape) into a full, risk-scored inventory,
/// using the default keyword classifier.
pub fn discover_from_str(spec_text: &str, source_label: &str) -> Result<Inventory, String> {
    discover_from_str_with_classifier(spec_text, source_label, &KeywordClassifier)
}

pub fn discover_from_str_with_classifier(
    spec_text: &str,
    source_label: &str,
    classifier: &dyn Classifier,
) -> Result<Inventory, String> {
    let root: serde_json::Value = if spec_text.trim_start().starts_with('{') {
        serde_json::from_str(spec_text).map_err(|e| format!("invalid JSON: {e}"))?
    } else {
        serde_yaml::from_str(spec_text).map_err(|e| format!("invalid YAML: {e}"))?
    };

    let (title, api_version, drafts) = if postman::is_postman_collection(&root) {
        postman::parse_collection(&root, classifier)?
    } else {
        openapi::parse_spec_with_classifier(&root, classifier)?
    };

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

/// Discover both spec files and diff the resulting inventories. Purely a
/// diff over two file paths already on disk — resolving two Git revisions
/// to file paths is the caller's job (e.g. `git show <rev>:<path>` written
/// to a temp file), not something `core` does itself.
pub fn diff_files(old_path: &Path, new_path: &Path) -> Result<DriftReport, String> {
    let old = discover_from_file(old_path)?;
    let new = discover_from_file(new_path)?;
    Ok(diff_inventories(&old, &new))
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
