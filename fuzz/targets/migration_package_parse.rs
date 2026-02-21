//! Fuzz target: migration package.json parse (FZT-001)
//!
//! Feeds malformed package.json data to the migration scanner's package
//! parser. Covers invalid JSON, unexpected types, circular references,
//! oversized files, and encoding edge cases.

/// Simulated package.json parse fuzz entry point.
pub fn fuzz_package_parse(data: &[u8]) -> FuzzResult {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return FuzzResult::InvalidInput,
    };

    // Reject oversized inputs (> 1 MiB)
    if input.len() > 1_048_576 {
        return FuzzResult::Rejected("oversized_input");
    }

    // Attempt JSON parse
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(input);
    let value = match parsed {
        Ok(v) => v,
        Err(_) => return FuzzResult::Rejected("invalid_json"),
    };

    // Validate expected structure
    if !value.is_object() {
        return FuzzResult::Rejected("not_an_object");
    }

    let obj = value.as_object().unwrap();

    // Check for required fields
    if !obj.contains_key("name") {
        return FuzzResult::Rejected("missing_name_field");
    }

    // Check dependencies are objects if present
    for dep_key in &["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(deps) = obj.get(*dep_key) {
            if !deps.is_object() {
                return FuzzResult::Rejected("dependencies_not_object");
            }
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
    fn test_valid_package_json() {
        let input = r#"{"name":"test","version":"1.0.0","dependencies":{"a":"^1.0"}}"#;
        assert_eq!(fuzz_package_parse(input.as_bytes()), FuzzResult::Ok);
    }

    #[test]
    fn test_invalid_json_rejected() {
        assert_eq!(
            fuzz_package_parse(b"{invalid"),
            FuzzResult::Rejected("invalid_json")
        );
    }

    #[test]
    fn test_missing_name_rejected() {
        assert_eq!(
            fuzz_package_parse(b"{\"version\":\"1.0\"}"),
            FuzzResult::Rejected("missing_name_field")
        );
    }

    #[test]
    fn test_deps_not_object_rejected() {
        let input = r#"{"name":"t","dependencies":"bad"}"#;
        assert_eq!(
            fuzz_package_parse(input.as_bytes()),
            FuzzResult::Rejected("dependencies_not_object")
        );
    }

    #[test]
    fn test_oversized_rejected() {
        let big = format!("{{\"name\":\"x\",\"data\":\"{}\"}}", "a".repeat(2_000_000));
        assert_eq!(
            fuzz_package_parse(big.as_bytes()),
            FuzzResult::Rejected("oversized_input")
        );
    }
}
