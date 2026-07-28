use super::{Check, Finding, Severity};
use crate::token::DecodedToken;

/// Claim key substrings that suggest sensitive data may have been
/// placed directly in the token payload. JWT payloads are base64url
/// encoded, NOT encrypted — anyone who can read the token can read
/// these values, so sensitive data here is effectively exposed.
const SENSITIVE_KEY_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "api_key",
    "apikey",
    "private_key",
    "access_token",
];

pub struct SensitiveDataCheck;

impl Check for SensitiveDataCheck {
    fn id(&self) -> &'static str {
        "sensitive-data-exposure"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let payload_object = token.payload.as_object()?;

        let matched: Vec<&str> = payload_object
            .keys()
            .filter(|key| {
                let lowercase_key = key.to_lowercase();
                SENSITIVE_KEY_PATTERNS
                    .iter()
                    .any(|pattern| lowercase_key.contains(pattern))
            })
            .map(|key| key.as_str())
            .collect();

        if matched.is_empty() {
            return None;
        }

        Some(Finding {
            id: self.id(),
            severity: Severity::High,
            title: format!(
                "Payload may contain sensitive data in claim(s): {}",
                matched.join(", ")
            ),
            description: "JWT payloads are base64url-encoded, not encrypted — anyone who \
                intercepts or stores this token can trivially decode and read its contents. \
                Claim names suggesting passwords, secrets, or personal/financial data indicate \
                sensitive information may be exposed. Consider moving such data server-side \
                and referencing it by an opaque identifier instead."
                .to_string(),
        })
    }
}
