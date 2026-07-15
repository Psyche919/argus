use thiserror::Error;

/// Errors that can occur while decoding a raw JWT string into its
/// structural components.
///
/// This type deliberately says nothing about whether a token is
/// cryptographically *valid* — only whether it could be split, decoded,
/// and parsed as JSON at all. Signature validity is a separate concern,
/// handled later by `verify.rs`.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error(
        "token does not have the expected header.payload.signature structure (found {0} segments)"
    )]
    MalformedStructure(usize),

    #[error("failed to base64url-decode the {0} segment: {1}")]
    Base64Decode(&'static str, base64::DecodeError),

    #[error("the {0} segment is not valid UTF-8")]
    InvalidUtf8(&'static str),

    #[error("failed to parse the {0} segment as JSON: {1}")]
    JsonParse(&'static str, serde_json::Error),
}
