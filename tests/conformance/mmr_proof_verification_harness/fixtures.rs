//! Fixture loading and golden file management for MMR conformance testing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Fixture loader for test data and golden files
pub struct FixtureLoader {
    base_dir: PathBuf,
    golden_files: HashMap<String, PathBuf>,
}

impl FixtureLoader {
    /// Create a new fixture loader
    pub fn new(fixtures_dir: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let base_dir = fixtures_dir.as_ref().to_path_buf();

        // Scan for golden files
        let mut golden_files = HashMap::new();
        if base_dir.exists() {
            Self::scan_golden_files(&base_dir, &mut golden_files)?;
        }

        Ok(Self {
            base_dir,
            golden_files,
        })
    }

    /// Load a golden file by name
    pub fn load_golden(&self, name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let path = self
            .golden_files
            .get(name)
            .ok_or_else(|| format!("Golden file not found: {}", name))?;

        let content = fs::read_to_string(path)?;
        Ok(content)
    }

    /// Save or update a golden file
    pub fn save_golden(
        &self,
        name: &str,
        content: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.base_dir.join(format!("{}.golden", name));

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&path, content)?;
        Ok(())
    }

    /// Check if a golden file exists
    pub fn has_golden(&self, name: &str) -> bool {
        self.golden_files.contains_key(name)
    }

    /// Load structured fixture data
    pub fn load_fixture<T>(&self, name: &str) -> Result<T, Box<dyn std::error::Error>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let path = self.base_dir.join(format!("{}.json", name));
        let content = fs::read_to_string(&path)?;
        let data: T = serde_json::from_str(&content)?;
        Ok(data)
    }

    /// Save structured fixture data
    pub fn save_fixture<T>(&self, name: &str, data: &T) -> Result<(), Box<dyn std::error::Error>>
    where
        T: Serialize,
    {
        let path = self.base_dir.join(format!("{}.json", name));

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(data)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Scan directory for golden files
    fn scan_golden_files(
        dir: &Path,
        golden_files: &mut HashMap<String, PathBuf>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    if path.extension() == Some(std::ffi::OsStr::new("golden")) {
                        golden_files.insert(name.to_string(), path);
                    }
                }
            } else if path.is_dir() {
                Self::scan_golden_files(&path, golden_files)?;
            }
        }

        Ok(())
    }
}

/// Test fixture data structures
#[derive(Debug, Serialize, Deserialize)]
pub struct MmrTestFixture {
    pub name: String,
    pub description: String,
    pub marker_count: u64,
    pub expected_root_hash: String,
    pub expected_tree_size: u64,
    pub test_sequences: Vec<u64>,
    pub expected_proofs: Vec<ExpectedInclusionProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedInclusionProof {
    pub sequence: u64,
    pub leaf_index: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrefixTestFixture {
    pub name: String,
    pub description: String,
    pub prefix_size: u64,
    pub super_size: u64,
    pub should_succeed: bool,
    pub expected_error_code: Option<String>,
}

/// Golden file assertion helper
pub fn assert_golden(
    fixtures: &FixtureLoader,
    name: &str,
    actual: &str,
    update_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if update_mode {
        fixtures.save_golden(name, actual)?;
        eprintln!("UPDATED golden: {}", name);
        return Ok(());
    }

    if !fixtures.has_golden(name) {
        return Err(format!(
            "Golden file not found: {}.golden\n\
             Run with UPDATE_GOLDENS=1 to create it",
            name
        )
        .into());
    }

    let expected = fixtures.load_golden(name)?;

    if actual != expected {
        // Save actual output for comparison
        let actual_name = format!("{}.actual", name);
        fixtures.save_golden(&actual_name, actual)?;

        return Err(format!(
            "GOLDEN MISMATCH: {}\n\
             Expected: {}.golden\n\
             Actual: {}.actual\n\
             Run: diff {} {}",
            name,
            name,
            actual_name,
            fixtures.base_dir.join(format!("{}.golden", name)).display(),
            fixtures.base_dir.join(format!("{}.actual", name)).display()
        )
        .into());
    }

    Ok(())
}