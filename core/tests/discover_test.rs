use std::path::Path;

fn load_fixture() -> pyapicheck_core::model::Inventory {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample-openapi.yaml");
    pyapicheck_core::discover_from_file(&path).expect("fixture should parse")
}

fn find<'a>(
    inventory: &'a pyapicheck_core::model::Inventory,
    method: &str,
    path: &str,
) -> &'a pyapicheck_core::model::Endpoint {
    inventory
        .endpoints
        .iter()
        .find(|e| e.method == method && e.path == path)
        .unwrap_or_else(|| panic!("expected to find {method} {path} in inventory"))
}

#[test]
fn discovers_every_declared_endpoint() {
    let inventory = load_fixture();
    assert_eq!(inventory.summary.total_endpoints, 7);
    assert_eq!(inventory.title, "Commerce API");
    assert_eq!(inventory.api_version, "1.3.0");
}

#[test]
fn authenticated_endpoints_with_pii_are_not_critical() {
    let inventory = load_fixture();
    let ep = find(&inventory, "POST", "/api/v1/customers");
    assert!(ep.authenticated);
    assert!(ep
        .sensitive_fields
        .iter()
        .any(|f| f.name == "email" && f.category == "pii"));
    // PII present but authenticated: sensitive_data(15) only -> MEDIUM, not CRITICAL.
    assert_eq!(ep.risk.level, "MEDIUM");
}

#[test]
fn refunds_endpoint_is_flagged_critical_for_unauthenticated_financial_data() {
    let inventory = load_fixture();
    let ep = find(&inventory, "POST", "/api/v1/refunds");
    assert!(!ep.authenticated);
    assert!(ep
        .sensitive_fields
        .iter()
        .any(|f| f.name == "account_number" && f.category == "financial"));
    assert_eq!(ep.risk.level, "CRITICAL");
    let factor_ids: Vec<&str> = ep.risk.factors.iter().map(|f| f.id.as_str()).collect();
    assert!(factor_ids.contains(&"no_auth"));
    assert!(factor_ids.contains(&"unauthenticated_sensitive_data"));
}

#[test]
fn destructive_delete_without_auth_is_high_risk() {
    let inventory = load_fixture();
    let ep = find(&inventory, "DELETE", "/api/v1/users/{id}");
    assert!(!ep.authenticated);
    assert_eq!(ep.risk.level, "HIGH");
}

#[test]
fn deprecated_endpoint_still_present_is_flagged_low() {
    let inventory = load_fixture();
    let ep = find(&inventory, "GET", "/api/v1/health");
    assert!(ep.deprecated);
    let factor_ids: Vec<&str> = ep.risk.factors.iter().map(|f| f.id.as_str()).collect();
    assert!(factor_ids.contains(&"deprecated_still_live"));
}

#[test]
fn global_security_applies_to_endpoints_without_an_override() {
    let inventory = load_fixture();
    let ep = find(&inventory, "GET", "/api/v1/orders/{id}");
    assert!(ep.authenticated);
    assert_eq!(ep.auth_schemes, vec!["bearerAuth".to_string()]);
}

#[test]
fn summary_counts_are_consistent_with_endpoint_flags() {
    let inventory = load_fixture();
    let expected_unauth = inventory
        .endpoints
        .iter()
        .filter(|e| !e.authenticated)
        .count();
    let expected_sensitive = inventory
        .endpoints
        .iter()
        .filter(|e| !e.sensitive_fields.is_empty())
        .count();
    assert_eq!(inventory.summary.unauthenticated, expected_unauth);
    assert_eq!(inventory.summary.sensitive_endpoints, expected_sensitive);
    assert_eq!(expected_unauth, 2);
}
