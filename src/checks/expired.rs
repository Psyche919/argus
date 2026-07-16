use super::{Check, Finding, Severity};
use crate::token::DecodedToken;
use chrono::Utc;

/// Flags tokens whose `exp` claim is in the past.
///
/// This check only runs if `exp` is present at all — a *missing* exp
/// claim is `MissingExpCheck`'s responsibility, not this one's. This is
/// exactly the single-responsibility split you asked for: each check
/// owns exactly one condition.
pub struct ExpiredCheck;

impl Check for ExpiredCheck {
    fn id(&self) -> &'static str {
        "expired"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let exp = token.payload.get("exp")?.as_i64()?;
        let now = Utc::now().timestamp();

        if exp >= now {
            return None;
        }

        Some(Finding {
            id: self.id(),
            severity: Severity::High,
            title: "Token has expired".to_string(),
            description: format!(
                "This token's 'exp' claim ({exp}) is in the past relative to the current \
                time ({now}). A correctly implemented verifier should reject this token, \
                but tokens are sometimes found still being accepted past their expiry due \
                to verification bugs or clock skew handled incorrectly."
            ),
        })
    }
}
