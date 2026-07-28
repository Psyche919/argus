use crate::token::DecodedToken;
use hmac::{Hmac, Mac};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;
use thiserror::Error;

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

/// Errors that can occur while loading a public key from disk.
#[derive(Debug, Error)]
pub enum KeyLoadError {
    #[error("failed to read key file at {0}: {1}")]
    Read(String, std::io::Error),

    #[error("failed to parse PEM-encoded RSA public key at {0}: {1}")]
    Parse(String, rsa::pkcs8::spki::Error),
}

/// Loads an RSA public key from a PEM-encoded file (e.g. one starting
/// with "-----BEGIN PUBLIC KEY-----").
pub fn load_rsa_public_key(path: &Path) -> Result<RsaPublicKey, KeyLoadError> {
    let pem_contents = std::fs::read_to_string(path)
        .map_err(|e| KeyLoadError::Read(path.display().to_string(), e))?;

    RsaPublicKey::from_public_key_pem(&pem_contents)
        .map_err(|e| KeyLoadError::Parse(path.display().to_string(), e))
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
        VerificationKey::RsaPublic(public_key) => verify_rsa(token, public_key, &alg),
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

fn verify_rsa(token: &DecodedToken, public_key: &RsaPublicKey, alg: &str) -> VerifyOutcome {
    let message = signing_input(token);
    let message_bytes = message.as_bytes();

    let result = match alg {
        "RS256" => verify_rsa_sha256(public_key, message_bytes, &token.signature),
        "RS384" => verify_rsa_sha384(public_key, message_bytes, &token.signature),
        "RS512" => verify_rsa_sha512(public_key, message_bytes, &token.signature),
        other => {
            return VerifyOutcome::KeyTypeMismatch {
                declared_alg: other.to_string(),
                supplied_key_type: "RSA Public Key",
            };
        }
    };

    match result {
        Ok(true) => VerifyOutcome::Verified,
        Ok(false) => VerifyOutcome::Failed {
            reason: "Signature does not match the supplied key".to_string(),
        },
        Err(e) => VerifyOutcome::Failed {
            reason: format!("Could not verify RSA signature: {e}"),
        },
    }
}

fn verify_rsa_sha256(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let hashed = Sha256::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha256>();
    Ok(key.verify(scheme, &hashed, signature).is_ok())
}

fn verify_rsa_sha384(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let hashed = Sha384::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha384>();
    Ok(key.verify(scheme, &hashed, signature).is_ok())
}

fn verify_rsa_sha512(key: &RsaPublicKey, message: &[u8], signature: &[u8]) -> Result<bool, String> {
    let hashed = Sha512::digest(message);
    let scheme = Pkcs1v15Sign::new::<Sha512>();
    Ok(key.verify(scheme, &hashed, signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::decode;

    /// A token signed with HS256 using jwt.io's default example secret,
    /// generated independently via jwt.io so this test doesn't rely on
    /// Argus's own signing code to validate Argus's own verification
    /// code — that would just prove the two agree with each other, not
    /// that either is actually correct.
    const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const CORRECT_SECRET: &[u8] = b"your-256-bit-secret";

    /// Test-only helper: base64url-encodes bytes without padding,
    /// matching how real JWT segments are encoded. Scoped inside this
    /// test module since it exists purely to construct test fixtures,
    /// not for any real Argus functionality.
    fn base64_url_encode(data: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(data)
    }

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
        let token = decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl")
            .unwrap();
        let key = VerificationKey::Hmac(CORRECT_SECRET.to_vec());

        let outcome = verify(&token, &key);

        assert!(matches!(outcome, VerifyOutcome::KeyTypeMismatch { .. }));
    }

    #[test]
    fn loads_a_valid_rsa_public_key_from_pem() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("key generation should succeed");
        let public_key = private_key.to_public_key();
        let pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PEM encoding should succeed");

        let mut file = tempfile::NamedTempFile::new().expect("failed to create temp file");
        std::io::Write::write_all(&mut file, pem.as_bytes())
            .expect("failed to write PEM to temp file");

        let result = load_rsa_public_key(file.path());

        assert!(result.is_ok(), "expected valid PEM to load successfully");
    }

    #[test]
    fn returns_error_for_missing_key_file() {
        let path = Path::new("/tmp/this_file_does_not_exist_12345.pem");
        let result = load_rsa_public_key(path);

        assert!(matches!(result, Err(KeyLoadError::Read(_, _))));
    }

    #[test]
    fn rsa_verification_succeeds_with_correct_public_key() {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).expect("key generation should succeed");
        let public_key = private_key.to_public_key();

        // Build a token whose header/payload are real, but whose
        // signature we compute ourselves using the freshly generated
        // private key — this proves verify_rsa's logic against a
        // signature we know is genuinely correct, without depending on
        // any external tool.
        let header = base64_url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64_url_encode(br#"{"sub":"1234567890"}"#);
        let message = format!("{header}.{payload}");

        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign_with_rng(&mut rng, message.as_bytes());
        let signature_bytes = signature.to_vec();
        let signature_b64 = base64_url_encode(&signature_bytes);

        let full_token = format!("{message}.{signature_b64}");
        let token = decode(&full_token).expect("constructed token should decode");
        let key = VerificationKey::RsaPublic(public_key);

        let outcome = verify(&token, &key);

        assert!(matches!(outcome, VerifyOutcome::Verified));
    }
}
