//! Agent/MCP policy (Phase 6): Cedar policy recommendations generated from
//! Phase 4 findings, and policy-drift detection against an existing Cedar
//! policy set using real Cedar evaluation (`cedar-policy`, Amazon's Cedar
//! -- a local/offline library, no network call).
//!
//! Entity vocabulary: principals are `Agent::"name"` or `User::"name"`
//! (matching Phase 3's graph vertex labels); the action is always
//! `Action::"CallEndpoint"`; resources are `Endpoint::"METHOD path"`.
//!
//! **Cedar has no native "require approval" decision** -- only `permit`
//! and `forbid`. Every policy generated here is a `forbid` (the safe
//! default: block until reviewed); an `@effect_hint(...)` annotation
//! records whether the *recommendation* is "deny" (strong signal) or
//! "require_approval" (weaker, needs human judgment) without pretending
//! Cedar itself can represent a three-way decision it can't.

use crate::baseline::{BolaFinding, FirstTimeOperation};
use cedar_policy::{Authorizer, Context, Entities, EntityUid, ParseErrors, PolicySet, Request};
use serde::Serialize;
use std::collections::HashSet;
use std::str::FromStr;

/// Escape a value for safe interpolation into a double-quoted Cedar string
/// literal.
fn cedar_string(value: &str) -> Result<String, String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("value must not contain newlines: {value:?}"));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn principal_type(identity: &str, known_agents: &HashSet<String>) -> &'static str {
    if known_agents.contains(identity) {
        "Agent"
    } else {
        "User"
    }
}

fn endpoint_resource_name(method: &str, path: &str) -> String {
    format!("{method} {path}")
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyRecommendation {
    pub policy_text: String,
    /// "deny" or "require_approval" -- see module doc for why this is a
    /// recommendation annotation, not a distinct Cedar effect.
    pub effect_hint: String,
    pub reason: String,
}

fn build_forbid_policy(
    principal_name: &str,
    known_agents: &HashSet<String>,
    resource_name: &str,
    effect_hint: &str,
    reason: &str,
) -> Result<PolicyRecommendation, String> {
    let principal_lit = cedar_string(principal_name)?;
    let resource_lit = cedar_string(resource_name)?;
    let reason_lit = cedar_string(reason)?;
    let effect_hint_lit = cedar_string(effect_hint)?;
    let ptype = principal_type(principal_name, known_agents);

    let policy_text = format!(
        "@reason({reason_lit})\n@effect_hint({effect_hint_lit})\nforbid(\n  principal == {ptype}::{principal_lit},\n  action == Action::\"CallEndpoint\",\n  resource == Endpoint::{resource_lit}\n);"
    );

    Ok(PolicyRecommendation {
        policy_text,
        effect_hint: effect_hint.to_string(),
        reason: reason.to_string(),
    })
}

/// One `forbid` recommendation per BOLA-shaped finding, `effect_hint`
/// "deny" -- sequential-ID enumeration is a strong, concrete signal.
pub fn recommend_from_bola_findings(
    findings: &[BolaFinding],
    known_agents: &HashSet<String>,
) -> Result<Vec<PolicyRecommendation>, String> {
    findings
        .iter()
        .map(|f| {
            let resource = endpoint_resource_name(&f.method, &f.path_template);
            let reason = format!(
                "sequential-ID enumeration by {:?}: run of {} IDs {:?}",
                f.identity, f.run_length, f.accessed_ids
            );
            build_forbid_policy(&f.identity, known_agents, &resource, "deny", &reason)
        })
        .collect()
}

/// One `forbid` recommendation per first-time-observed operation,
/// `effect_hint` "require_approval" -- a genuinely new operation from a
/// known identity merits review, not an automatic verdict of malice.
pub fn recommend_from_first_time_operations(
    findings: &[FirstTimeOperation],
    known_agents: &HashSet<String>,
) -> Result<Vec<PolicyRecommendation>, String> {
    findings
        .iter()
        .map(|f| {
            let resource = endpoint_resource_name(&f.method, &f.path);
            let reason = format!(
                "first-time-observed operation for {:?}: {} {}",
                f.identity, f.method, f.path
            );
            build_forbid_policy(
                &f.identity,
                known_agents,
                &resource,
                "require_approval",
                &reason,
            )
        })
        .collect()
}

/// Parse and validate Cedar policy text, surfacing Cedar's own parse
/// errors verbatim rather than a generic "invalid policy" message.
pub fn parse_policy_set(text: &str) -> Result<PolicySet, String> {
    PolicySet::from_str(text).map_err(|e: ParseErrors| format!("invalid Cedar policy: {e}"))
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySummary {
    pub id: String,
    pub effect: String,
    pub annotations: Vec<(String, String)>,
}

/// Summarize a parsed policy set into a serializable form (`PolicySet`
/// itself doesn't implement `Serialize`).
pub fn summarize_policy_set(policy_set: &PolicySet) -> Vec<PolicySummary> {
    let mut summaries: Vec<PolicySummary> = policy_set
        .policies()
        .map(|p| PolicySummary {
            id: p.id().to_string(),
            effect: format!("{:?}", p.effect()),
            annotations: p
                .annotations()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
        .collect();
    summaries.sort_by(|a, b| a.id.cmp(&b.id));
    summaries
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyGap {
    pub principal: String,
    pub resource: String,
    pub reason: String,
    /// The exact Cedar `forbid` policy text that closes this gap.
    pub recommended_fix: String,
}

fn evaluate(
    policy_set: &PolicySet,
    principal_name: &str,
    known_agents: &HashSet<String>,
    resource_name: &str,
) -> Result<cedar_policy::Decision, String> {
    let ptype = principal_type(principal_name, known_agents);
    let principal = EntityUid::from_str(&format!("{ptype}::{}", cedar_string(principal_name)?))
        .map_err(|e| format!("invalid principal entity: {e}"))?;
    let action = EntityUid::from_str(r#"Action::"CallEndpoint""#)
        .map_err(|e| format!("invalid action entity: {e}"))?;
    let resource = EntityUid::from_str(&format!("Endpoint::{}", cedar_string(resource_name)?))
        .map_err(|e| format!("invalid resource entity: {e}"))?;

    let request = Request::new(principal, action, resource, Context::empty(), None)
        .map_err(|e| format!("failed to build request: {e}"))?;
    let response = Authorizer::new().is_authorized(&request, policy_set, &Entities::empty());
    Ok(response.decision())
}

/// For each Phase 4 finding, actually evaluate it against `policy_set`
/// using Cedar's real authorizer. A finding Cedar would currently `Allow`
/// (e.g. a broad `permit` for that agent, with no carve-out) is a genuine
/// policy gap; one that's already `Deny` needs no fix. Every gap comes
/// with the exact `forbid` text that closes it.
pub fn diff_against_policy(
    policy_set: &PolicySet,
    bola_findings: &[BolaFinding],
    first_time_ops: &[FirstTimeOperation],
    known_agents: &HashSet<String>,
) -> Result<Vec<PolicyGap>, String> {
    let mut gaps = Vec::new();

    for finding in bola_findings {
        let resource = endpoint_resource_name(&finding.method, &finding.path_template);
        let decision = evaluate(policy_set, &finding.identity, known_agents, &resource)?;
        if decision == cedar_policy::Decision::Allow {
            let recommendation =
                recommend_from_bola_findings(std::slice::from_ref(finding), known_agents)?
                    .remove(0);
            gaps.push(PolicyGap {
                principal: finding.identity.clone(),
                resource,
                reason: recommendation.reason,
                recommended_fix: recommendation.policy_text,
            });
        }
    }

    for finding in first_time_ops {
        let resource = endpoint_resource_name(&finding.method, &finding.path);
        let decision = evaluate(policy_set, &finding.identity, known_agents, &resource)?;
        if decision == cedar_policy::Decision::Allow {
            let recommendation =
                recommend_from_first_time_operations(std::slice::from_ref(finding), known_agents)?
                    .remove(0);
            gaps.push(PolicyGap {
                principal: finding.identity.clone(),
                resource,
                reason: recommendation.reason,
                recommended_fix: recommendation.policy_text,
            });
        }
    }

    Ok(gaps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bola(identity: &str) -> BolaFinding {
        BolaFinding {
            identity: identity.to_string(),
            method: "GET".to_string(),
            path_template: "/api/v1/customers/{id}".to_string(),
            accessed_ids: vec![1, 2, 3, 4],
            run_length: 4,
        }
    }

    fn first_time(identity: &str) -> FirstTimeOperation {
        FirstTimeOperation {
            identity: identity.to_string(),
            method: "POST".to_string(),
            path: "/api/v1/refunds".to_string(),
            timestamp: None,
        }
    }

    #[test]
    fn recommended_policy_text_is_valid_cedar_and_denies_the_exact_request() {
        let findings = vec![bola("attacker")];
        let recs = recommend_from_bola_findings(&findings, &HashSet::new()).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].effect_hint, "deny");

        let policy_set = parse_policy_set(&recs[0].policy_text).unwrap();
        let decision = evaluate(
            &policy_set,
            "attacker",
            &HashSet::new(),
            "GET /api/v1/customers/{id}",
        )
        .unwrap();
        assert_eq!(decision, cedar_policy::Decision::Deny);
    }

    #[test]
    fn known_agent_generates_agent_typed_principal() {
        let findings = vec![first_time("finance-agent")];
        let mut agents = HashSet::new();
        agents.insert("finance-agent".to_string());
        let recs = recommend_from_first_time_operations(&findings, &agents).unwrap();
        assert!(recs[0].policy_text.contains(r#"Agent::"finance-agent""#));
        assert_eq!(recs[0].effect_hint, "require_approval");
    }

    #[test]
    fn validate_surfaces_real_cedar_parse_errors() {
        let err = parse_policy_set("this is not cedar").unwrap_err();
        assert!(err.contains("invalid Cedar policy"));
    }

    #[test]
    fn summarize_reports_effect_and_annotations() {
        let findings = vec![bola("attacker")];
        let recs = recommend_from_bola_findings(&findings, &HashSet::new()).unwrap();
        let policy_set = parse_policy_set(&recs[0].policy_text).unwrap();

        let summaries = summarize_policy_set(&policy_set);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].effect, "Forbid");
        assert!(summaries[0]
            .annotations
            .iter()
            .any(|(k, v)| k == "effect_hint" && v == "deny"));
    }

    #[test]
    fn diff_flags_a_finding_a_broad_permit_would_currently_allow() {
        // A broad, unconditional permit for finance-agent -- exactly the
        // kind of overly-permissive policy this diff is meant to catch.
        let policy_text = r#"permit(principal == Agent::"finance-agent", action, resource);"#;
        let policy_set = parse_policy_set(policy_text).unwrap();

        let mut agents = HashSet::new();
        agents.insert("finance-agent".to_string());
        let findings = vec![first_time("finance-agent")];

        let gaps = diff_against_policy(&policy_set, &[], &findings, &agents).unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].principal, "finance-agent");
        assert!(gaps[0].recommended_fix.contains("forbid"));

        // Applying the recommended fix as an additional forbid rule
        // should flip the decision to Deny -- prove the fix actually works,
        // not just that we printed something forbid-shaped.
        let combined_text = format!("{policy_text}\n{}", gaps[0].recommended_fix);
        let combined = parse_policy_set(&combined_text).unwrap();
        let decision =
            evaluate(&combined, "finance-agent", &agents, "POST /api/v1/refunds").unwrap();
        assert_eq!(decision, cedar_policy::Decision::Deny);
    }

    #[test]
    fn diff_reports_no_gap_when_policy_already_denies_by_default() {
        // No permit at all -- Cedar's default deny already covers this;
        // no gap, no forbid needed.
        let policy_set = parse_policy_set("").unwrap();
        let findings = vec![bola("attacker")];
        let gaps = diff_against_policy(&policy_set, &findings, &[], &HashSet::new()).unwrap();
        assert!(gaps.is_empty());
    }
}
