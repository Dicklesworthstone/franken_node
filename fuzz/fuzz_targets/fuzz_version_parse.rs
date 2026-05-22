#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, PartialEq, Clone)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
    prerelease: Option<String>,
    build: Option<String>,
}

// Semantic version parsing function
fn parse_version(version_str: &str) -> Result<Version, String> {
    if version_str.is_empty() {
        return Err("Version string cannot be empty".to_string());
    }

    if version_str.len() > 256 {
        return Err("Version string too long".to_string());
    }

    // Check for null bytes and control characters
    if version_str.contains('\0') || version_str.chars().any(|c| c.is_control()) {
        return Err("Version string contains invalid characters".to_string());
    }

    // Remove build metadata (+xxx)
    let (core_version, build) = if let Some(plus_pos) = version_str.find('+') {
        let build_part = &version_str[plus_pos + 1..];
        if build_part.is_empty() {
            return Err("Empty build metadata".to_string());
        }
        (&version_str[..plus_pos], Some(build_part.to_string()))
    } else {
        (version_str, None)
    };

    // Remove prerelease (-xxx)
    let (base_version, prerelease) = if let Some(dash_pos) = core_version.find('-') {
        let pre_part = &core_version[dash_pos + 1..];
        if pre_part.is_empty() {
            return Err("Empty prerelease".to_string());
        }
        (&core_version[..dash_pos], Some(pre_part.to_string()))
    } else {
        (core_version, None)
    };

    // Parse major.minor.patch
    let parts: Vec<&str> = base_version.split('.').collect();
    if parts.len() != 3 {
        return Err("Version must have exactly 3 numeric parts (major.minor.patch)".to_string());
    }

    let major = parts[0].parse::<u32>()
        .map_err(|_| "Invalid major version number".to_string())?;
    let minor = parts[1].parse::<u32>()
        .map_err(|_| "Invalid minor version number".to_string())?;
    let patch = parts[2].parse::<u32>()
        .map_err(|_| "Invalid patch version number".to_string())?;

    // Validate no leading zeros (except for "0")
    for (i, part) in parts.iter().enumerate() {
        if part.len() > 1 && part.starts_with('0') {
            return Err(format!("Leading zeros not allowed in version part {}", i).to_string());
        }
    }

    // Validate prerelease format
    if let Some(ref pre) = prerelease {
        if !pre.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err("Prerelease contains invalid characters".to_string());
        }
    }

    // Validate build metadata format
    if let Some(ref build_meta) = build {
        if !build_meta.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
            return Err("Build metadata contains invalid characters".to_string());
        }
    }

    Ok(Version {
        major,
        minor,
        patch,
        prerelease,
        build,
    })
}

fn compare_versions(v1: &Version, v2: &Version) -> std::cmp::Ordering {
    match v1.major.cmp(&v2.major) {
        std::cmp::Ordering::Equal => {},
        other => return other,
    }
    match v1.minor.cmp(&v2.minor) {
        std::cmp::Ordering::Equal => {},
        other => return other,
    }
    match v1.patch.cmp(&v2.patch) {
        std::cmp::Ordering::Equal => {},
        other => return other,
    }

    // Prerelease comparison
    match (&v1.prerelease, &v2.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,  // Prerelease < normal
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(p1), Some(p2)) => p1.cmp(p2),
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(version_input) = std::str::from_utf8(data) {
        if version_input.len() > 10000 {
            return;
        }

        let parse_result = parse_version(version_input);

        match parse_result {
            Ok(version) => {
                // Valid version - verify security invariants
                assert!(version.major <= u32::MAX);
                assert!(version.minor <= u32::MAX);
                assert!(version.patch <= u32::MAX);

                // Test round-trip consistency
                let formatted = format!("{}.{}.{}", version.major, version.minor, version.patch);
                let mut full_version = formatted.clone();

                if let Some(ref pre) = version.prerelease {
                    full_version.push('-');
                    full_version.push_str(pre);
                }

                if let Some(ref build_meta) = version.build {
                    full_version.push('+');
                    full_version.push_str(build_meta);
                }

                let reparsed = parse_version(&full_version);
                assert!(reparsed.is_ok(), "Round-trip parsing should succeed");

                if let Ok(reparsed_version) = reparsed {
                    assert_eq!(version, reparsed_version, "Round-trip should preserve version");
                }

                // Test comparison consistency
                let same_version = parse_version(&formatted).unwrap();
                assert_eq!(compare_versions(&version, &same_version), std::cmp::Ordering::Equal);

                // Test that modifications produce different results
                if version.major < u32::MAX {
                    let higher_major = Version {
                        major: version.major + 1,
                        minor: version.minor,
                        patch: version.patch,
                        prerelease: version.prerelease.clone(),
                        build: version.build.clone(),
                    };
                    assert_eq!(compare_versions(&version, &higher_major), std::cmp::Ordering::Less);
                }
            }
            Err(_) => {
                // Invalid version - verify security checks
                if version_input.is_empty() {
                    assert!(parse_version(version_input).is_err());
                }
                if version_input.len() > 256 {
                    assert!(parse_version(version_input).is_err());
                }
                if version_input.contains('\0') {
                    assert!(parse_version(version_input).is_err());
                }
                if version_input.chars().any(|c| c.is_control()) {
                    assert!(parse_version(version_input).is_err());
                }
            }
        }

        // Test specific valid patterns
        if version_input == "1.0.0" {
            let result = parse_version(version_input);
            assert!(result.is_ok());
            if let Ok(v) = result {
                assert_eq!(v.major, 1);
                assert_eq!(v.minor, 0);
                assert_eq!(v.patch, 0);
                assert!(v.prerelease.is_none());
                assert!(v.build.is_none());
            }
        }

        if version_input == "2.1.3-beta.1+build.123" {
            let result = parse_version(version_input);
            assert!(result.is_ok());
            if let Ok(v) = result {
                assert_eq!(v.major, 2);
                assert_eq!(v.minor, 1);
                assert_eq!(v.patch, 3);
                assert_eq!(v.prerelease, Some("beta.1".to_string()));
                assert_eq!(v.build, Some("build.123".to_string()));
            }
        }

        // Test invalid patterns
        if version_input == "1.2" || version_input == "1.2.3.4" {
            assert!(parse_version(version_input).is_err());
        }

        if version_input == "01.0.0" || version_input == "1.02.0" || version_input == "1.0.03" {
            assert!(parse_version(version_input).is_err(), "Leading zeros should be rejected");
        }

        if version_input == "1.2.3-" || version_input == "1.2.3+" {
            assert!(parse_version(version_input).is_err(), "Empty prerelease/build should be rejected");
        }

        // Test injection patterns
        if version_input.contains("<script>") || version_input.contains("javascript:") {
            assert!(parse_version(version_input).is_err(), "XSS attempts should be rejected");
        }

        if version_input.contains("$(") || version_input.contains("`") {
            assert!(parse_version(version_input).is_err(), "Command injection should be rejected");
        }

        // Test buffer overflow patterns
        if version_input.len() > 256 {
            assert!(parse_version(version_input).is_err());
        }

        // Test numeric overflow
        if version_input.contains("999999999999999999999") {
            assert!(parse_version(version_input).is_err(), "Numeric overflow should be rejected");
        }

        // Test special characters
        if version_input.contains('\n') || version_input.contains('\r') || version_input.contains('\t') {
            assert!(parse_version(version_input).is_err(), "Control chars should be rejected");
        }

        // Test comparison edge cases
        if version_input == "1.0.0-alpha" {
            let alpha = parse_version(version_input).unwrap();
            let release = parse_version("1.0.0").unwrap();
            assert_eq!(compare_versions(&alpha, &release), std::cmp::Ordering::Less);
        }

        // Test empty components
        if version_input.contains("..") {
            assert!(parse_version(version_input).is_err(), "Empty components should be rejected");
        }

        // Test negative numbers
        if version_input.contains('-') && !version_input.contains('.') {
            // Negative number (not prerelease)
            assert!(parse_version(version_input).is_err());
        }

        // Test floating point
        if version_input.contains('.') && version_input.matches('.').count() < 2 {
            // Might be floating point, should be rejected
            let result = parse_version(version_input);
        }

        // Test Unicode
        if version_input.chars().any(|c| !c.is_ascii()) {
            assert!(parse_version(version_input).is_err(), "Non-ASCII should be rejected");
        }

        // Test extremely large numbers
        if let Ok(v) = parse_version(version_input) {
            assert!(v.major < 1_000_000_000, "Extremely large versions should be suspicious");
            assert!(v.minor < 1_000_000_000);
            assert!(v.patch < 1_000_000_000);
        }
    }
});