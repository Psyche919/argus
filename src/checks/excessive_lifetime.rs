use super::{Check, Finding, Severity};
use crate::token::DecodedToken;

/// Tokens valid for longer than this are flagged. 24 hours is a
/// reasonable default for typical session/access tokens; refresh
/// tokens or special-purpose long-lived tokens may legitimately exceed
/// this, which is why this is Low severity, not a hard violation.
const MAX_REASONABLE_LIFETIME_SECS: i64 = 24 * 60 * 60;

pub struct ExcessiveLifetimeCheck;

impl Check for ExcessiveLifetimeCheck {
    fn id(&self) -> &'static str {
        "excessive-lifetime"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let iat = token.payload.get("iat")?.as_i64()?;
        let exp = token.payload.get("exp")?.as_i64()?;
        let lifetime = exp - iat;

        if lifetime <= MAX_REASONABLE_LIFETIME_SECS {
            return None;
        }

        let hours = lifetime / 3600;

        Some(Finding {
            id: self.id(),
            severity: Severity::Low,
            title: format!("Token has an unusually long lifetime (~{hours} hours)"),
            description: format!(
                "This token is valid for approximately {hours} hours between its 'iat' and \
                'exp' claims. Long-lived tokens increase the impact window if the token is \
                ever leaked. Consider shorter-lived access tokens paired with a separate \
                refresh mechanism, if this isn't already the case."
            ),
        })
    }
}
