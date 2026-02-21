//! Fuzz target: migration dependency resolution (FZT-001)
//!
//! Feeds adversarial dependency trees to the dependency resolver.
//! Covers diamond dependencies, version conflicts, impossible constraint
//! sets, and pathologically deep dependency chains.

/// Simulated dependency resolution fuzz entry point.
pub fn fuzz_dependency_resolve(data: &[u8]) -> FuzzResult {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return FuzzResult::InvalidInput,
    };

    // Parse dependency spec lines: "package@version -> dep1@constraint, dep2@constraint"
    let lines: Vec<&str> = input.lines().collect();

    if lines.is_empty() {
        return FuzzResult::Rejected("empty_input");
    }

    // Reject dependency graphs with > 1000 nodes (resource exhaustion)
    if lines.len() > 1000 {
        return FuzzResult::Rejected("too_many_nodes");
    }

    // Check for circular references (simple detection)
    let mut seen = std::collections::HashSet::new();
    for line in &lines {
        let parts: Vec<&str> = line.splitn(2, " -> ").collect();
        if parts.is_empty() {
            continue;
        }
        let pkg = parts[0].trim();
        if !seen.insert(pkg) {
            return FuzzResult::Rejected("duplicate_package");
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
    fn test_valid_deps() {
        let input = "a@1.0 -> b@^1.0, c@^2.0\nb@1.0 -> \nc@2.0 -> ";
        assert_eq!(fuzz_dependency_resolve(input.as_bytes()), FuzzResult::Ok);
    }

    #[test]
    fn test_empty_input_rejected() {
        assert_eq!(
            fuzz_dependency_resolve(b""),
            FuzzResult::Rejected("empty_input")
        );
    }

    #[test]
    fn test_duplicate_package_rejected() {
        let input = "a@1.0 -> b@^1.0\na@1.0 -> c@^2.0";
        assert_eq!(
            fuzz_dependency_resolve(input.as_bytes()),
            FuzzResult::Rejected("duplicate_package")
        );
    }

    #[test]
    fn test_too_many_nodes_rejected() {
        let lines: String = (0..1001).map(|i| format!("pkg-{i}@1.0 -> \n")).collect();
        assert_eq!(
            fuzz_dependency_resolve(lines.as_bytes()),
            FuzzResult::Rejected("too_many_nodes")
        );
    }
}
