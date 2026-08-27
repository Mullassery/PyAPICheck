use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitiveField {
    pub name: String,
    pub category: String,
    pub confidence: f32,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub id: String,
    pub description: String,
    pub weight: i32,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: i32,
    pub level: String,
    pub factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone)]
pub struct EndpointDraft {
    pub method: String,
    pub path: String,
    pub summary: Option<String>,
    pub operation_id: Option<String>,
    pub tags: Vec<String>,
    pub deprecated: bool,
    pub authenticated: bool,
    pub auth_schemes: Vec<String>,
    pub sensitive_fields: Vec<SensitiveField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub summary: Option<String>,
    pub operation_id: Option<String>,
    pub tags: Vec<String>,
    pub deprecated: bool,
    pub authenticated: bool,
    pub auth_schemes: Vec<String>,
    pub sensitive_fields: Vec<SensitiveField>,
    pub risk: RiskScore,
    /// Always "documented" for endpoints discovered from a spec file — reserved for
    /// runtime discovery sources (shadow/undocumented/drifted) added in later phases.
    pub openapi_status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventorySummary {
    pub total_endpoints: usize,
    pub high_or_critical: usize,
    pub unauthenticated: usize,
    pub sensitive_endpoints: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub source: String,
    pub title: String,
    pub api_version: String,
    pub endpoints: Vec<Endpoint>,
    pub summary: InventorySummary,
}

/// Drop duplicate (name, location) sensitive-field entries — shared by every
/// discovery source (OpenAPI, Postman, ...) since each may visit the same
/// field name more than once while walking a schema/body.
pub(crate) fn dedupe_sensitive_fields(fields: &mut Vec<SensitiveField>) {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    fields.retain(|f| seen.insert((f.name.clone(), f.location.clone())));
}

pub fn summarize(endpoints: &[Endpoint]) -> InventorySummary {
    InventorySummary {
        total_endpoints: endpoints.len(),
        high_or_critical: endpoints
            .iter()
            .filter(|e| e.risk.level == "HIGH" || e.risk.level == "CRITICAL")
            .count(),
        unauthenticated: endpoints.iter().filter(|e| !e.authenticated).count(),
        sensitive_endpoints: endpoints
            .iter()
            .filter(|e| !e.sensitive_fields.is_empty())
            .count(),
    }
}
