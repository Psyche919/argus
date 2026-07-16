use super::{Check, Finding, Severity};
use crate::token::DecodedToken;

/// Flags tokens that have no `exp` (expiration) claim at all.
///
/// A token with no expiry is valid forever, which violates the principle
/// of least privilege for session tokens: if it's ever leaked, it can be
/// replayed indefinitely with no natural cutoff.
pub struct MissingExpCheck;

impl Check for MissingExpCheck {
    fn id(&self) -> &'static str {
        "missing-exp"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        if token.payload.get("exp").is_some() {
            return None;
        }

        Some(Finding {
            id: self.id(),
            severity: Severity::High,
            title: "Token has no expiration (exp) claim".to_string(),
            description: "This token does not include an 'exp' claim, meaning it never \
                expires on its own. A leaked or stolen token with no expiry remains valid \
                indefinitely, giving an attacker unlimited time to use it. Tokens should \
                generally include a short, deliberate lifetime."
                .to_string(),
        })
    }
}
