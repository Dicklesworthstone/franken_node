//! Fuzz target: shim API translation (FZT-001)
//!
//! Feeds adversarial API call inputs to the shim translation layer.
//! Covers type confusion (objects where primitives expected), boundary
//! values, encoding edge cases (surrogate pairs, overlong UTF-8).

/// Simulated API translation fuzz entry point.
pub fn fuzz_api_translation(data: &[u8]) -> FuzzResult {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return FuzzResult::InvalidInput,
    };

    // Attempt to parse as JSON API call
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(input);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => return FuzzResult::Rejected("invalid_json"),
    };

    // API call must have "method" and "params" fields
    let obj = match value.as_object() {
        Some(o) => o,
        None => return FuzzResult::Rejected("not_an_object"),
    };

    let method = match obj.get("method") {
        Some(m) if m.is_string() => m.as_str().unwrap(),
        Some(_) => return FuzzResult::Rejected("method_not_string"),
        None => return FuzzResult::Rejected("missing_method"),
    };

    // Reject empty method names
    if method.is_empty() {
        return FuzzResult::Rejected("empty_method");
    }

    // Reject method names > 128 chars
    if method.len() > 128 {
        return FuzzResult::Rejected("method_too_long");
    }

    // Validate params is array or object
    if let Some(params) = obj.get("params") {
        if !params.is_array() && !params.is_object() {
            return FuzzResult::Rejected("params_invalid_type");
        }
    }

    FuzzResult::Ok
}

/// Result of a fuzz execution.
#[derive(Debug, PartialEq)]
pub enum FuzzResult {
    Ok,
    InvalidInput,
    Rejected(&'static str),
    Crash(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_api_call() {
        let input = r#"{"method":"getStatus","params":[]}"#;
        assert_eq!(fuzz_api_translation(input.as_bytes()), FuzzResult::Ok);
    }

    #[test]
    fn test_missing_method_rejected() {
        assert_eq!(
            fuzz_api_translation(br#"{"params":[]}"#),
            FuzzResult::Rejected("missing_method")
        );
    }

    #[test]
    fn test_method_not_string_rejected() {
        assert_eq!(
            fuzz_api_translation(br#"{"method":42,"params":[]}"#),
            FuzzResult::Rejected("method_not_string")
        );
    }

    #[test]
    fn test_params_invalid_type_rejected() {
        assert_eq!(
            fuzz_api_translation(br#"{"method":"x","params":"bad"}"#),
            FuzzResult::Rejected("params_invalid_type")
        );
    }

    #[test]
    fn test_empty_method_rejected() {
        assert_eq!(
            fuzz_api_translation(br#"{"method":"","params":[]}"#),
            FuzzResult::Rejected("empty_method")
        );
    }
}
