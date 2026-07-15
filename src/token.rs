use crate::error::TokenError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

/// A JWT that has been split and decoded into its structural parts,
/// without any judgment about whether it is cryptographically valid.
///
/// Decoding is deliberately permissive: Argus's job is to find and report
/// on insecure tokens, which means it must represent tokens that a strict,
/// verification-first JWT library would reject outright (e.g. `alg: none`,
/// missing claims, malformed payload shapes).
#[derive(Debug, Clone)]
pub struct DecodedToken {
    pub header: Value,
    pub payload: Value,
    pub signature: Vec<u8>,
    /// The original base64url segments, preserved because signature
    /// verification (Milestone 6) must re-check against the *exact*
    /// original bytes, not a round-tripped re-serialization of the JSON.
    pub raw_parts: RawParts,
}

#[derive(Debug, Clone)]
pub struct RawParts {
    pub header: String,
    pub payload: String,
    pub signature: String,
}

/// Splits and decodes a raw JWT string into a [`DecodedToken`].
///
/// This performs structural decoding only — it never verifies the
/// signature. A token can decode successfully here and still be
/// cryptographically invalid or insecure; that's exactly what the
/// `checks` modules exist to find.
pub fn decode(raw: &str) -> Result<DecodedToken, TokenError> {
    let parts: Vec<&str> = raw.split('.').collect();

    if parts.len() != 3 {
        return Err(TokenError::MalformedStructure(parts.len()));
    }

    let header = decode_json_segment(parts[0], "header")?;
    let payload = decode_json_segment(parts[1], "payload")?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| TokenError::Base64Decode("signature", e))?;

    Ok(DecodedToken {
        header,
        payload,
        signature,
        raw_parts: RawParts {
            header: parts[0].to_string(),
            payload: parts[1].to_string(),
            signature: parts[2].to_string(),
        },
    })
}

/// Decodes a single base64url segment and parses it as JSON.
fn decode_json_segment(segment: &str, name: &'static str) -> Result<Value, TokenError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| TokenError::Base64Decode(name, e))?;

    let text = String::from_utf8(bytes).map_err(|_| TokenError::InvalidUtf8(name))?;

    serde_json::from_str(&text).map_err(|e| TokenError::JsonParse(name, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed HS256 token (the standard jwt.io example).
    /// Used as our "known good" baseline — if this ever fails to decode,
    /// something fundamental broke, not an edge case.
    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn decodes_a_valid_token() {
        let decoded = decode(VALID_TOKEN).expect("valid token should decode successfully");

        assert_eq!(decoded.header["alg"], "HS256");
        assert_eq!(decoded.header["typ"], "JWT");
        assert_eq!(decoded.payload["sub"], "1234567890");
        assert_eq!(decoded.payload["name"], "John Doe");
    }

    #[test]
    fn permissively_decodes_an_alg_none_token() {
        // This is the architecturally important case: a token claiming
        // alg: none with an empty signature must still decode cleanly,
        // so that later Check implementations can flag it as a finding.
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.";

        let decoded = decode(token).expect("alg:none token should still decode structurally");

        assert_eq!(decoded.header["alg"], "none");
        assert_eq!(decoded.payload["role"], "admin");
        assert!(decoded.signature.is_empty());
    }

    #[test]
    fn rejects_wrong_segment_count() {
        let result = decode("only.two.parts.here"); // 4 segments, not 3

        assert!(matches!(result, Err(TokenError::MalformedStructure(4))));
    }

    #[test]
    fn rejects_missing_segments() {
        let result = decode("onlyonesegment");

        assert!(matches!(result, Err(TokenError::MalformedStructure(1))));
    }

    #[test]
    fn rejects_invalid_base64_in_header() {
        // "!!!invalid!!!" is not valid base64url
        let result = decode("!!!invalid!!!.eyJzdWIiOiJhZG1pbiJ9.sig");

        assert!(matches!(result, Err(TokenError::Base64Decode("header", _))));
    }

    #[test]
    fn rejects_valid_base64_that_is_not_json() {
        // "aGVsbG8" base64url-decodes to the plain text "hello", which
        // is valid UTF-8 but not valid JSON.
        let result = decode("aGVsbG8.eyJzdWIiOiJhZG1pbiJ9.sig");

        assert!(matches!(result, Err(TokenError::JsonParse("header", _))));
    }
}
