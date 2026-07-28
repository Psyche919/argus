use super::{Check, Finding, Severity};
use crate::token::DecodedToken;
use chrono::Utc;

/// Flags tokens whose `iat` (issued at) claim is in the future — a
/// stronger signal than nbf-future, since a legitimately issued token
/// should never claim to have been created after "now".
pub struct IatFutureCheck;

impl Check for IatFutureCheck {
    fn id(&self) -> &'static str {
        "iat-future"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let iat = token.payload.get("iat")?.as_i64()?;
        let now = Utc::now().timestamp();

        if iat <= now {
            return None;
        }

        Some(Finding {
            id: self.id(),
            severity: Severity::Medium,
            title: "Token claims to be issued in the future".to_string(),
            description: format!(
                "This token's 'iat' claim ({iat}) is later than the current time ({now}). \
                A legitimately issued token should never have an issue time in the future — \
                this may indicate clock skew between systems, or a manually crafted/tampered \
                token."
            ),
        })
    }
}
