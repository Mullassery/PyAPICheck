//! Enforcement integrations (Phase 7): translate `forbid` Cedar policies
//! into an Envoy `envoy.filters.http.rbac` HTTP filter config snippet --
//! a gateway-consumable artifact for a human to review and splice into a
//! real Envoy deployment, not something this crate deploys itself.
//!
//! The generated schema was verified against a real Envoy instance
//! (`envoyproxy/envoy:v1.31`, Docker) before this module was written, not
//! assumed from proto docs: `envoy --mode validate` accepts it, and a
//! live container genuinely returns `403` for the exact (principal,
//! method, path) triple a policy targets, and does not `403` a different
//! principal or a different endpoint for the same principal.
//!
//! Only `forbid` policies with an `principal ==`/`resource ==` equality
//! constraint (the shape `policy.rs` generates) are translated. A
//! `permit` policy has no Envoy RBAC `DENY` equivalent worth emitting --
//! "not denied" is already the default when nothing else denies it.

use cedar_policy::{Effect, PolicySet, PrincipalConstraint, ResourceConstraint};
use std::fmt::Write as _;

/// The HTTP header Envoy is expected to have already populated with the
/// caller identity by the time this filter runs (e.g. via an upstream
/// `jwt_authn` filter copying a claim into a header) -- matches Phase 4's
/// convention of reading identity from a `user_id`/`agent_id`-shaped
/// field.
const IDENTITY_HEADER: &str = "x-user-id";

/// One translatable `forbid` policy: a concrete (principal, method, path)
/// this Envoy filter will deny.
struct ForbidRule {
    policy_id: String,
    principal_id: String,
    method: String,
    path: String,
}

fn extract_forbid_rules(policy_set: &PolicySet) -> Vec<ForbidRule> {
    let mut rules = Vec::new();

    for policy in policy_set.policies() {
        if policy.effect() != Effect::Forbid {
            continue;
        }

        let principal_id = match policy.principal_constraint() {
            PrincipalConstraint::Eq(uid) => uid.id().unescaped().to_string(),
            _ => continue, // untargeted/`in`-constrained forbid: not this generator's shape
        };

        let resource_id = match policy.resource_constraint() {
            ResourceConstraint::Eq(uid) => uid.id().unescaped().to_string(),
            _ => continue,
        };

        // Our own generated resource ids are "METHOD path" (see policy.rs
        // endpoint_resource_name); a policy that doesn't match this shape
        // isn't one this generator knows how to translate.
        let Some((method, path)) = resource_id.split_once(' ') else {
            continue;
        };

        rules.push(ForbidRule {
            policy_id: policy.id().to_string(),
            principal_id,
            method: method.to_string(),
            path: path.to_string(),
        });
    }

    rules
}

/// YAML string escaping for a double-quoted scalar: backslash and
/// double-quote need escaping; this is intentionally narrow (matches what
/// method/path/identity values from `policy.rs` actually contain) rather
/// than a general-purpose YAML emitter.
fn yaml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Emit an Envoy `envoy.filters.http.rbac` HTTP filter config snippet
/// implementing every `forbid` policy in `policy_set`. Returns `Ok(None)`
/// (not an error) when there is nothing to translate -- an all-`permit`
/// or empty policy set has no `DENY` rules to emit, which is a valid,
/// reportable outcome, not a failure.
pub fn emit_envoy_rbac(policy_set: &PolicySet) -> Option<String> {
    let rules = extract_forbid_rules(policy_set);
    if rules.is_empty() {
        return None;
    }

    let mut out = String::new();
    let _ = writeln!(out, "name: envoy.filters.http.rbac");
    let _ = writeln!(out, "typed_config:");
    let _ = writeln!(
        out,
        "  \"@type\": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC"
    );
    let _ = writeln!(out, "  rules:");
    let _ = writeln!(out, "    action: DENY");
    let _ = writeln!(out, "    policies:");

    for rule in &rules {
        let key = yaml_string(&format!("pyapicheck-{}", rule.policy_id));
        let _ = writeln!(out, "      {key}:");
        let _ = writeln!(out, "        permissions:");
        let _ = writeln!(out, "          - and_rules:");
        let _ = writeln!(out, "              rules:");
        let _ = writeln!(out, "                - header:");
        let _ = writeln!(out, "                    name: \":method\"");
        let _ = writeln!(
            out,
            "                    string_match: {{ exact: {} }}",
            yaml_string(&rule.method)
        );
        let _ = writeln!(out, "                - header:");
        let _ = writeln!(out, "                    name: \":path\"");
        let _ = writeln!(
            out,
            "                    string_match: {{ exact: {} }}",
            yaml_string(&rule.path)
        );
        let _ = writeln!(out, "        principals:");
        let _ = writeln!(out, "          - header:");
        let _ = writeln!(out, "              name: {}", yaml_string(IDENTITY_HEADER));
        let _ = writeln!(
            out,
            "              string_match: {{ exact: {} }}",
            yaml_string(&rule.principal_id)
        );
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy_set;

    #[test]
    fn translates_a_forbid_policy_into_a_deny_rule() {
        let policy_set = parse_policy_set(
            r#"
forbid(
  principal == Agent::"finance-agent",
  action == Action::"CallEndpoint",
  resource == Endpoint::"POST /api/v1/refunds"
);
"#,
        )
        .unwrap();

        let yaml = emit_envoy_rbac(&policy_set).unwrap();
        assert!(yaml.contains("envoy.filters.http.rbac"));
        assert!(yaml.contains("action: DENY"));
        assert!(yaml.contains("exact: \"POST\""));
        assert!(yaml.contains("exact: \"/api/v1/refunds\""));
        assert!(yaml.contains("exact: \"finance-agent\""));
        assert!(yaml.contains("x-user-id"));
    }

    #[test]
    fn permit_only_policy_set_emits_nothing() {
        let policy_set =
            parse_policy_set(r#"permit(principal == Agent::"finance-agent", action, resource);"#)
                .unwrap();
        assert!(emit_envoy_rbac(&policy_set).is_none());
    }

    #[test]
    fn empty_policy_set_emits_nothing() {
        let policy_set = parse_policy_set("").unwrap();
        assert!(emit_envoy_rbac(&policy_set).is_none());
    }

    #[test]
    fn multiple_forbid_policies_each_get_a_rule() {
        let policy_set = parse_policy_set(
            r#"
forbid(principal == Agent::"finance-agent", action == Action::"CallEndpoint", resource == Endpoint::"POST /api/v1/refunds");
forbid(principal == User::"attacker", action == Action::"CallEndpoint", resource == Endpoint::"GET /api/v1/customers/{id}");
"#,
        )
        .unwrap();

        let yaml = emit_envoy_rbac(&policy_set).unwrap();
        assert!(yaml.contains("finance-agent"));
        assert!(yaml.contains("attacker"));
        assert_eq!(yaml.matches("action: DENY").count(), 1);
        assert_eq!(yaml.matches("permissions:").count(), 2);
    }

    #[test]
    fn generated_snippet_is_syntactically_valid_yaml() {
        // Not a substitute for the real-Envoy verification this module's
        // doc comment describes (done manually against a live container
        // before writing this code) -- this just guards against a future
        // edit reintroducing a YAML-syntax regression.
        let policy_set = parse_policy_set(
            r#"forbid(principal == Agent::"a", action == Action::"CallEndpoint", resource == Endpoint::"GET /x");"#,
        )
        .unwrap();
        let yaml = emit_envoy_rbac(&policy_set).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("must be valid YAML");
        assert_eq!(
            parsed.get("name").and_then(|v| v.as_str()),
            Some("envoy.filters.http.rbac")
        );
    }
}
