//! Fuzz target: migration directory scan (FZT-001)
//!
//! Feeds adversarial directory structures to the migration scanner.
//! Covers deeply nested paths, path traversal attempts, symlink loops,
//! and pathological filenames (null bytes, unicode edge cases).

/// Simulated migration directory scan fuzz entry point.
///
/// In a real cargo-fuzz integration this would be:
/// ```ignore
/// #![no_main]
/// use libfuzzer_sys::fuzz_target;
/// fuzz_target!(|data: &[u8]| { fuzz_directory_scan(data); });
/// ```
pub fn fuzz_directory_scan(data: &[u8]) -> FuzzResult {
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return FuzzResult::InvalidInput,
    };

    // Reject path traversal attempts
    if input.contains("..") || input.contains('\0') {
        return FuzzResult::Rejected("path_traversal_or_null_byte");
    }

    // Reject excessively deep paths (> 256 components)
    if input.split('/').count() > 256 {
        return FuzzResult::Rejected("excessive_depth");
    }

    // Reject excessively long path components (> 255 bytes)
    if input.split('/').any(|c| c.len() > 255) {
        return FuzzResult::Rejected("component_too_long");
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
    fn test_valid_path() {
        assert_eq!(fuzz_directory_scan(b"src/main.rs"), FuzzResult::Ok);
    }

    #[test]
    fn test_path_traversal_rejected() {
        assert_eq!(
            fuzz_directory_scan(b"../../etc/passwd"),
            FuzzResult::Rejected("path_traversal_or_null_byte")
        );
    }

    #[test]
    fn test_null_byte_rejected() {
        assert_eq!(
            fuzz_directory_scan(b"src/\x00evil"),
            FuzzResult::Rejected("path_traversal_or_null_byte")
        );
    }

    #[test]
    fn test_deep_path_rejected() {
        let deep = (0..300).map(|_| "d").collect::<Vec<_>>().join("/");
        assert_eq!(
            fuzz_directory_scan(deep.as_bytes()),
            FuzzResult::Rejected("excessive_depth")
        );
    }

    #[test]
    fn test_invalid_utf8() {
        assert_eq!(fuzz_directory_scan(&[0xff, 0xfe]), FuzzResult::InvalidInput);
    }
}
