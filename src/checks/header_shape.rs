use super::{Check, Finding, Severity};
use crate::token::DecodedToken;

/// Verifies the header contains the two claims every JWT is expected to
/// have: `alg` and `typ`. A missing or malformed header is a structural
/// red flag on its own, independent of what `alg` value it contains.
pub struct HeaderShapeCheck;

impl Check for HeaderShapeCheck {
    fn id(&self) -> &'static str {
        "header-shape"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let has_alg = token.header.get("alg").is_some();
        let has_typ = token.header.get("typ").is_some();

        if has_alg && has_typ {
            return None;
        }

        let missing: Vec<&str> = [("alg", has_alg), ("typ", has_typ)]
            .into_iter()
            .filter(|(_, present)| !present)
            .map(|(name, _)| name)
            .collect();

        Some(Finding {
            id: self.id(),
            severity: Severity::Medium,
            title: format!(
                "Header is missing expected claim(s): {}",
                missing.join(", ")
            ),
            description: "A well-formed JWT header should contain both 'alg' (the signing \
                algorithm) and 'typ' (the token type, typically \"JWT\"). Missing these claims \
                suggests a malformed or non-standard token, which may indicate a hand-crafted \
                or tampered token rather than one issued by a standard JWT library."
                .to_string(),
        })
    }
}
