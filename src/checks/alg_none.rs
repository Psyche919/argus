use super::{Check, Finding, Severity};
use crate::token::DecodedToken;

/// Flags tokens that declare `alg: none` in their header.
///
/// This is one of the most well-known JWT vulnerabilities: some poorly
/// implemented verifiers historically treated `alg: none` as "skip
/// signature verification entirely," letting an attacker forge a token
/// with any claims they want, as long as they set this one header value.
pub struct AlgNoneCheck;

impl Check for AlgNoneCheck {
    fn id(&self) -> &'static str {
        "alg-none"
    }

    fn run(&self, token: &DecodedToken) -> Option<Finding> {
        let alg = token.header.get("alg")?.as_str()?;

        if alg.eq_ignore_ascii_case("none") {
            Some(Finding {
                id: self.id(),
                severity: Severity::Critical,
                title: "Token uses alg: none".to_string(),
                description: "This token declares its signing algorithm as \"none\", meaning \
                    it is intentionally unsigned. If the application verifying this token \
                    accepts alg: none, an attacker can forge tokens with arbitrary claims \
                    (e.g. an admin role) with no cryptographic secret required at all. \
                    Applications must explicitly reject alg: none during verification."
                    .to_string(),
            })
        } else {
            None
        }
    }
}
