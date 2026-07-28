use super::{Check, Finding, Severity};
use crate::token::DecodedToken;
use chrono::Utc;

/// Flags tokens whose `nbf` (not before) claim is in the future,
/// meaning the token isn't valid yet even though it exists.
pub struct NbfFutureCheck;

impl Check for NbfFutureCheck {
    fn id(&self) -> &'static str {
        "nbf-future"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let nbf = token.payload.get("nbf")?.as_i64()?;
        let now = Utc::now().timestamp();

        if nbf <= now {
            return None;
        }

        Some(Finding {
            id: self.id(),
            severity: Severity::Low,
            title: "Token is not yet valid (nbf is in the future)".to_string(),
            description: format!(
                "This token's 'nbf' claim ({nbf}) is later than the current time ({now}), \
                meaning the token should not be accepted yet. This is usually intentional \
                (e.g. pre-issued tokens), but worth confirming it matches the issuer's intent."
            ),
        })
    }
}
