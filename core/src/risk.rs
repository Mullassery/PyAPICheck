//! Transparent risk scoring.
//!
//! Per product principle: no opaque score. Every point on the score traces to a
//! named, human-readable factor returned alongside it — `score_endpoint` builds
//! the factor list first and derives the number from it, not the other way round.

use crate::model::{EndpointDraft, RiskFactor, RiskScore};

fn is_mutating(method: &str) -> bool {
    matches!(
        method.to_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

fn level_for(score: i32) -> &'static str {
    match score {
        0..=14 => "LOW",
        15..=39 => "MEDIUM",
        40..=69 => "HIGH",
        _ => "CRITICAL",
    }
}

pub fn score_endpoint(ep: &EndpointDraft) -> RiskScore {
    let mut factors: Vec<RiskFactor> = Vec::new();
    let mutating = is_mutating(&ep.method);

    if !ep.authenticated {
        let weight = if mutating { 40 } else { 30 };
        factors.push(RiskFactor {
            id: "no_auth".to_string(),
            description: format!(
                "No authentication scheme declared for {} {}",
                ep.method, ep.path
            ),
            weight,
            severity: "HIGH".to_string(),
        });
    }

    if !ep.sensitive_fields.is_empty() {
        let mut categories: Vec<&str> = ep
            .sensitive_fields
            .iter()
            .map(|f| f.category.as_str())
            .collect();
        categories.sort_unstable();
        categories.dedup();
        let has_high_sensitivity = categories
            .iter()
            .any(|c| matches!(*c, "financial" | "credential" | "health"));
        let weight = if has_high_sensitivity { 30 } else { 15 };
        factors.push(RiskFactor {
            id: "sensitive_data".to_string(),
            description: format!(
                "Endpoint handles fields classified as: {}",
                categories.join(", ")
            ),
            weight,
            severity: if has_high_sensitivity {
                "HIGH".to_string()
            } else {
                "MEDIUM".to_string()
            },
        });
    }

    if !ep.authenticated && !ep.sensitive_fields.is_empty() {
        factors.push(RiskFactor {
            id: "unauthenticated_sensitive_data".to_string(),
            description: "Sensitive data is reachable without authentication".to_string(),
            weight: 20,
            severity: "CRITICAL".to_string(),
        });
    }

    if ep.deprecated {
        factors.push(RiskFactor {
            id: "deprecated_still_live".to_string(),
            description: "Endpoint is marked deprecated in the spec but still present".to_string(),
            weight: 10,
            severity: "MEDIUM".to_string(),
        });
    }

    if ep.summary.is_none() && ep.operation_id.is_none() {
        factors.push(RiskFactor {
            id: "missing_metadata".to_string(),
            description: "No summary or operationId — likely no assigned owner".to_string(),
            weight: 5,
            severity: "LOW".to_string(),
        });
    }

    let score: i32 = factors.iter().map(|f| f.weight).sum::<i32>().min(100);
    RiskScore {
        score,
        level: level_for(score).to_string(),
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SensitiveField;

    fn base_draft() -> EndpointDraft {
        EndpointDraft {
            method: "GET".to_string(),
            path: "/widgets".to_string(),
            summary: Some("List widgets".to_string()),
            operation_id: Some("listWidgets".to_string()),
            tags: vec![],
            deprecated: false,
            authenticated: true,
            auth_schemes: vec!["bearerAuth".to_string()],
            sensitive_fields: vec![],
        }
    }

    #[test]
    fn clean_endpoint_scores_zero() {
        let risk = score_endpoint(&base_draft());
        assert_eq!(risk.score, 0);
        assert_eq!(risk.level, "LOW");
        assert!(risk.factors.is_empty());
    }

    #[test]
    fn unauthenticated_mutating_endpoint_is_high_risk() {
        let mut draft = base_draft();
        draft.method = "POST".to_string();
        draft.authenticated = false;
        draft.auth_schemes = vec![];
        let risk = score_endpoint(&draft);
        assert_eq!(risk.score, 40);
        assert_eq!(risk.level, "HIGH");
    }

    #[test]
    fn unauthenticated_endpoint_with_sensitive_data_is_critical() {
        let mut draft = base_draft();
        draft.method = "GET".to_string();
        draft.authenticated = false;
        draft.auth_schemes = vec![];
        draft.sensitive_fields = vec![SensitiveField {
            name: "account_number".to_string(),
            category: "financial".to_string(),
            confidence: 0.9,
            location: "response".to_string(),
        }];
        let risk = score_endpoint(&draft);
        // no_auth(30) + sensitive_data high(30) + unauthenticated_sensitive_data(20) = 80
        assert_eq!(risk.score, 80);
        assert_eq!(risk.level, "CRITICAL");
    }
}
