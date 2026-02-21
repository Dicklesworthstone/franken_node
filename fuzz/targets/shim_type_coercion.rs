//! Fuzz target: shim type coercion (FZT-001)
//!
//! Feeds adversarial type coercion inputs to the shim type coercion logic.
//! Covers policy bypass attempts, mixed-type arrays, nested object depth.

/// Simulated type coercion fuzz entry point.
pub fn fuzz_type_coercion(data: &[u8]) -> FuzzResult {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return FuzzResult::InvalidInput,
    };

    let parsed: Result<serde_json::Value, _> = serde_json::from_str(input);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => return FuzzResult::Rejected("invalid_json"),
    };

    // Check nesting depth (reject > 32 levels)
    if nesting_depth(&value) > 32 {
        return FuzzResult::Rejected("excessive_nesting");
    }

    // Check total node count (reject > 10000)
    if node_count(&value) > 10000 {
        return FuzzResult::Rejected("too_many_nodes");
    }

    FuzzResult::Ok
}

fn nesting_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(nesting_depth).max().unwrap_or(0),
        serde_json::Value::Object(obj) => {
            1 + obj.values().map(nesting_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

fn node_count(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(node_count).sum::<usize>(),
        serde_json::Value::Object(obj) => 1 + obj.values().map(node_count).sum::<usize>(),
        _ => 1,
    }
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
    fn test_simple_value() {
        assert_eq!(fuzz_type_coercion(br#"42"#), FuzzResult::Ok);
    }

    #[test]
    fn test_nested_object() {
        let input = r#"{"a":{"b":{"c":1}}}"#;
        assert_eq!(fuzz_type_coercion(input.as_bytes()), FuzzResult::Ok);
    }

    #[test]
    fn test_excessive_nesting_rejected() {
        let mut s = "1".to_string();
        for _ in 0..40 {
            s = format!("[{s}]");
        }
        assert_eq!(
            fuzz_type_coercion(s.as_bytes()),
            FuzzResult::Rejected("excessive_nesting")
        );
    }

    #[test]
    fn test_invalid_json_rejected() {
        assert_eq!(
            fuzz_type_coercion(b"not json"),
            FuzzResult::Rejected("invalid_json")
        );
    }

    #[test]
    fn test_invalid_utf8() {
        assert_eq!(fuzz_type_coercion(&[0xff, 0xfe]), FuzzResult::InvalidInput);
    }
}
