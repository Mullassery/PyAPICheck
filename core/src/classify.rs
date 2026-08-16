//! Heuristic sensitive-field classifier.
//!
//! This is deliberately a lightweight, dependency-free keyword classifier — a
//! "Presidio-lite" for the Rust core. The Python wrapper can later swap in or
//! augment this with a real NLP-based classifier (e.g. Presidio) without changing
//! the core's public API, since callers only depend on `classify_field`.

pub struct FieldClassification {
    pub category: &'static str,
    pub confidence: f32,
}

type Rule = (&'static [&'static str], &'static str, f32);

const RULES: &[Rule] = &[
    (
        &[
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
        ],
        "credential",
        0.95,
    ),
    (
        &[
            "card_number",
            "cardnumber",
            "pan",
            "cvv",
            "cvc",
            "account_number",
            "accountnumber",
            "iban",
            "routing_number",
            "swift_code",
            "bank_account",
        ],
        "financial",
        0.9,
    ),
    (
        &[
            "diagnosis",
            "medical_record",
            "health_record",
            "prescription",
            "icd_code",
        ],
        "health",
        0.9,
    ),
    (
        &[
            "ssn",
            "social_security",
            "passport",
            "national_id",
            "aadhaar",
            "aadhar",
            "tax_id",
            "date_of_birth",
            "dob",
            "email",
            "phone_number",
            "phone",
            "home_address",
            "address",
        ],
        "pii",
        0.85,
    ),
    (
        &["name", "first_name", "last_name", "full_name", "username"],
        "pii",
        0.55,
    ),
];

/// Classify a schema field name into a sensitivity category, if it matches a
/// known pattern. Returns `None` for fields with no known sensitivity signal —
/// callers should treat that as "not flagged", not "confirmed non-sensitive".
pub fn classify_field(field_name: &str) -> Option<FieldClassification> {
    let lower = field_name.to_lowercase();
    for (keywords, category, confidence) in RULES {
        if keywords.iter().any(|k| lower.contains(k)) {
            return Some(FieldClassification {
                category,
                confidence: *confidence,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_financial_identifiers() {
        let c = classify_field("account_number").expect("should classify");
        assert_eq!(c.category, "financial");
    }

    #[test]
    fn flags_credentials() {
        let c = classify_field("api_key").expect("should classify");
        assert_eq!(c.category, "credential");
    }

    #[test]
    fn is_case_insensitive() {
        let c = classify_field("Email").expect("should classify");
        assert_eq!(c.category, "pii");
    }

    #[test]
    fn leaves_unknown_fields_unclassified() {
        assert!(classify_field("widget_color").is_none());
    }
}
