use crate::token::DecodedToken;
use hmac::{Hmac, Mac};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};

/// A key supplied by the user for signature verification.
///
/// This is the stable center of the verification module: adding a new
/// key type later (ECDSA, or a key resolved from a JWKS response) means
/// adding one variant here and one match arm in `verify()` — no change
/// to how callers construct or pass around a `VerificationKey`.
pub enum VerificationKey {
    Hmac(Vec<u8>),
    RsaPublic(RsaPublicKey),
}

impl VerificationKey {
    /// A human-readable name for this key's type, used in report output.
    pub fn type_name(&self) -> &'static str {
        match self {
            VerificationKey::Hmac(_) => "HMAC Secret",
            VerificationKey::RsaPublic(_) => "RSA Public Key",
        }
    }
}

/// The result of attempting to verify a token's signature against a
/// supplied key.
///
/// Deliberately descriptive, not judgmental: this type reports *what
/// happened*, not what it *means* for the token's security. Deciding
/// whether a mismatch or failure is worth flagging as a security concern
/// is the job of a separate, later analysis layer — not this type.
pub enum VerifyOutcome {
    Verified,
    Failed {
        reason: String,
    },
    KeyTypeMismatch {
        declared_alg: String,
        supplied_key_type: &'static str,
    },
}

/// The exact bytes that a JWT signature is computed over: the base64url
/// header and payload segments, joined with a dot. Neither HMAC nor RSA
/// verification is possible without reconstructing this exact string —
/// it is NOT the same as re-serializing the decoded JSON, which could
/// differ in whitespace/key order from the original.
fn signing_input(token: &DecodedToken) -> String {
    format!("{}.{}", token.raw_parts.header, token.raw_parts.payload)
}

/// Attempts to verify a token's signature using the supplied key.
pub fn verify(token: &DecodedToken, key: &VerificationKey) -> VerifyOutcome {
    let alg = token
        .header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    match key {
        VerificationKey::Hmac(secret) => verify_hmac(token, secret, &alg),
        VerificationKey::RsaPublic(_public_key) => {
            // RSA verification comes in the next step — for now, treat
            // any RSA key against any token as not-yet-supported.
            VerifyOutcome::Failed {
                reason: "RSA verification not yet implemented".to_string(),
            }
        }
    }
}

fn verify_hmac(token: &DecodedToken, secret: &[u8], alg: &str) -> VerifyOutcome {
    let message = signing_input(token);
    let message_bytes = message.as_bytes();

    let result = match alg {
        "HS256" => verify_hmac_sha256(secret, message_bytes, &token.signature),
        "HS384" => verify_hmac_sha384(secret, message_bytes, &token.signature),
        "HS512" => verify_hmac_sha512(secret, message_bytes, &token.signature),
        other => {
            return VerifyOutcome::KeyTypeMismatch {
                declared_alg: other.to_string(),
                supplied_key_type: "HMAC Secret",
            };
        }
    };

    match result {
        Ok(true) => VerifyOutcome::Verified,
        Ok(false) => VerifyOutcome::Failed {
            reason: "Signature does not match the supplied key".to_string(),
        },
        Err(e) => VerifyOutcome::Failed {
            reason: format!("Could not compute HMAC: {e}"),
        },
    }
}

fn verify_hmac_sha256(secret: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(message);
    Ok(mac.verify_slice(signature).is_ok())
}

fn verify_hmac_sha384(secret: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let mut mac = Hmac::<Sha384>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(message);
    Ok(mac.verify_slice(signature).is_ok())
}

fn verify_hmac_sha512(secret: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let mut mac = Hmac::<Sha512>::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(message);
    Ok(mac.verify_slice(signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::decode;

    /// A token signed with HS256 using the secret "test-secret-key",
    /// generated independently (e.g. via jwt.io) so this test doesn't
    /// rely on Argus's own signing code to validate Argus's own
    /// verification code — that would just prove the two agree with
    /// each other, not that either is actually correct.
    const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const CORRECT_SECRET: &[u8] = b"your-256-bit-secret";

    #[test]
    fn hmac_verification_succeeds_with_correct_secret() {
        let token = decode(HS256_TOKEN).unwrap();
        let key = VerificationKey::Hmac(CORRECT_SECRET.to_vec());

        let outcome = verify(&token, &key);

        assert!(matches!(outcome, VerifyOutcome::Verified));
    }

    #[test]
    fn hmac_verification_fails_with_wrong_secret() {
        let token = decode(HS256_TOKEN).unwrap();
        let key = VerificationKey::Hmac(b"wrong-secret".to_vec());

        let outcome = verify(&token, &key);

        assert!(matches!(outcome, VerifyOutcome::Failed { .. }));
    }

    #[test]
    fn hmac_key_against_rs256_token_reports_key_type_mismatch() {
        // Reuse an RS256-declared token from earlier milestones' test
        // fixtures conceptually — here we construct one inline with a
        // fake signature, since we only care about the declared `alg`,
        // not whether the signature is genuine.
        let token = decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let key = VerificationKey::Hmac(CORRECT_SECRET.to_vec());

        let outcome = verify(&token, &key);

        assert!(matches!(outcome, VerifyOutcome::KeyTypeMismatch { .. }));
    }
}
