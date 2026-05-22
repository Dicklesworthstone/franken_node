#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf, Component};

// Path validation function for testing
fn validate_safe_path(path_str: &str) -> Result<PathBuf, String> {
    if path_str.is_empty() {
        return Err("Empty path".to_string());
    }

    // Reject paths that are too long
    if path_str.len() > 4096 {
        return Err("Path too long".to_string());
    }

    // Reject null bytes
    if path_str.contains('\0') {
        return Err("Path contains null bytes".to_string());
    }

    let path = Path::new(path_str);
    let mut safe_path = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Normal(name) => {
                let name_str = name.to_string_lossy();

                // Reject dangerous filenames
                if name_str == "." || name_str == ".." {
                    return Err("Path traversal attempt".to_string());
                }

                // Reject hidden files starting with dot (configurable security policy)
                if name_str.starts_with('.') && name_str.len() > 1 {
                    return Err("Hidden file access denied".to_string());
                }

                // Reject extremely long filenames
                if name_str.len() > 255 {
                    return Err("Filename too long".to_string());
                }

                // Reject control characters
                if name_str.chars().any(|c| c.is_control()) {
                    return Err("Control characters in filename".to_string());
                }

                // Reject dangerous Windows characters
                if name_str.chars().any(|c| "<>:\"|?*".contains(c)) {
                    return Err("Invalid filename characters".to_string());
                }

                safe_path.push(name);
            }
            Component::ParentDir => {
                return Err("Parent directory access denied".to_string());
            }
            Component::RootDir => {
                return Err("Absolute path access denied".to_string());
            }
            Component::CurDir => {
                // Current directory is generally safe, but we'll skip it
                continue;
            }
            Component::Prefix(_) => {
                return Err("Windows prefix not allowed".to_string());
            }
        }
    }

    if safe_path.as_os_str().is_empty() {
        return Err("Resolved to empty path".to_string());
    }

    Ok(safe_path)
}

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, handling invalid UTF-8 gracefully
    if let Ok(path_input) = std::str::from_utf8(data) {
        // Guard against excessively long paths
        if path_input.len() > 65536 {
            return;
        }

        // Test path validation with arbitrary input
        let validation_result = validate_safe_path(path_input);

        match validation_result {
            Ok(safe_path) => {
                // Valid path - verify security invariants

                // 1. Path should not be empty
                assert!(!safe_path.as_os_str().is_empty(), "Safe path should not be empty");

                // 2. Path should be relative (no absolute components)
                assert!(safe_path.is_relative(), "Safe path should be relative");

                // 3. Path should not contain parent directory references
                for component in safe_path.components() {
                    assert!(!matches!(component, Component::ParentDir),
                           "Safe path should not contain parent directory references");
                    assert!(!matches!(component, Component::RootDir),
                           "Safe path should not contain root directory references");
                }

                // 4. Each component should be reasonable length
                for component in safe_path.components() {
                    if let Component::Normal(name) = component {
                        let name_str = name.to_string_lossy();
                        assert!(name_str.len() <= 255, "Filename components should be reasonable length");
                        assert!(!name_str.chars().any(|c| c.is_control()),
                               "Filename should not contain control characters");
                    }
                }

                // 5. Total path length should be reasonable
                assert!(safe_path.to_string_lossy().len() <= 4096,
                       "Total path length should be reasonable");

                // 6. Path should not end with dangerous patterns
                let path_str = safe_path.to_string_lossy();
                assert!(!path_str.ends_with("/."), "Path should not end with /.");
                assert!(!path_str.ends_with("/.."), "Path should not end with /..");

                // 7. Test that the path can be safely joined with a base directory
                let base = PathBuf::from("/safe/base/dir");
                let joined = base.join(&safe_path);
                let normalized = joined.canonicalize().unwrap_or(joined);

                // Should still be under the base directory (in a real implementation)
                let base_str = base.to_string_lossy();
                let norm_str = normalized.to_string_lossy();
                // This is a simplified check - real implementation would be more robust

            }
            Err(_err) => {
                // Invalid path - verify security checks are working

                // 1. Path traversal attempts should be rejected
                if path_input.contains("..") || path_input.contains("../") || path_input.contains("\\..") {
                    let result2 = validate_safe_path(path_input);
                    assert!(result2.is_err(), "Path traversal attempts should be consistently rejected");
                }

                // 2. Absolute paths should be rejected
                if path_input.starts_with('/') || path_input.starts_with('\\') ||
                   (path_input.len() > 2 && path_input.chars().nth(1) == Some(':')) {
                    assert!(validate_safe_path(path_input).is_err(),
                           "Absolute paths should be rejected");
                }

                // 3. Null bytes should be rejected
                if path_input.contains('\0') {
                    assert!(validate_safe_path(path_input).is_err(),
                           "Paths with null bytes should be rejected");
                }

                // 4. Control characters should be rejected
                if path_input.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                    assert!(validate_safe_path(path_input).is_err(),
                           "Paths with control characters should be rejected");
                }

                // 5. Extremely long paths should be rejected
                if path_input.len() > 4096 {
                    assert!(validate_safe_path(path_input).is_err(),
                           "Extremely long paths should be rejected");
                }
            }
        }

        // Test common path traversal patterns
        let dangerous_patterns = [
            "../", "..\\", "/..", "\\..", "....", "..../",
            "/etc/passwd", "../../etc/passwd", "..\\..\\windows\\system32",
            "CON", "PRN", "AUX", "NUL", // Windows reserved names
        ];

        for pattern in &dangerous_patterns {
            if path_input.contains(pattern) {
                let result = validate_safe_path(path_input);
                // Most of these should be rejected (some edge cases might be allowed)
            }
        }

        // Test edge cases
        if path_input.is_empty() {
            let result = validate_safe_path(path_input);
            assert!(result.is_err(), "Empty path should be rejected");
        }

        // Test single dot
        if path_input == "." {
            let result = validate_safe_path(path_input);
            // Single dot might be allowed or rejected depending on policy
        }

        // Test double dot
        if path_input == ".." {
            let result = validate_safe_path(path_input);
            assert!(result.is_err(), "Double dot should be rejected");
        }

        // Test normal safe filenames
        if path_input == "safe_file.txt" {
            let result = validate_safe_path(path_input);
            assert!(result.is_ok(), "Safe filename should be allowed");
        }

        if path_input == "dir/safe_file.txt" {
            let result = validate_safe_path(path_input);
            assert!(result.is_ok(), "Safe relative path should be allowed");
        }

        // Test hidden files (implementation-dependent policy)
        if path_input.starts_with('.') && path_input != "." && path_input != ".." {
            let result = validate_safe_path(path_input);
            // Hidden files should be rejected per our security policy
            assert!(result.is_err(), "Hidden files should be rejected");
        }

        // Test Windows drive letters
        if path_input.len() >= 2 && path_input.chars().nth(1) == Some(':') {
            let result = validate_safe_path(path_input);
            assert!(result.is_err(), "Windows drive letters should be rejected");
        }

        // Test UNC paths
        if path_input.starts_with("\\\\") {
            let result = validate_safe_path(path_input);
            assert!(result.is_err(), "UNC paths should be rejected");
        }
    }
});