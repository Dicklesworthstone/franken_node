//! Test context and environment for MMR conformance testing.

use super::fixtures::FixtureLoader;
use super::logging::StructuredLogger;
use std::path::PathBuf;
use std::sync::Arc;

/// Test execution context carrying shared state and utilities
#[derive(Clone)]
pub struct TestContext {
    /// Base directory for test artifacts
    pub base_dir: PathBuf,

    /// Directory for golden files and fixtures
    pub fixtures_dir: PathBuf,

    /// Directory for test output and temporary files
    pub output_dir: PathBuf,

    /// Structured logger for test events
    pub logger: Arc<StructuredLogger>,

    /// Fixture loader for test data
    pub fixtures: Arc<FixtureLoader>,

    /// Shared test configuration
    pub config: TestConfig,

    /// Random seed for deterministic testing
    pub seed: u64,

    /// Test run identifier
    pub run_id: String,
}

impl TestContext {
    /// Create a new test context
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self, Box<dyn std::error::Error>> {
        let base_dir = base_dir.into();
        let fixtures_dir = base_dir.join("fixtures");
        let output_dir = base_dir.join("output");

        // Ensure directories exist
        std::fs::create_dir_all(&fixtures_dir)?;
        std::fs::create_dir_all(&output_dir)?;

        let run_id = format!("{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
        let logger = Arc::new(StructuredLogger::new(output_dir.join("test_log.jsonl"))?);
        let fixtures = Arc::new(FixtureLoader::new(&fixtures_dir)?);

        Ok(Self {
            base_dir,
            fixtures_dir,
            output_dir,
            logger,
            fixtures,
            config: TestConfig::default(),
            seed: 0x1337_DEAD_BEEF_CAFE,
            run_id,
        })
    }

    /// Create a temporary file path in the output directory
    pub fn temp_path(&self, name: &str) -> PathBuf {
        self.output_dir.join(format!("{}_{}", self.run_id, name))
    }

    /// Log a test event
    pub fn log(&self, event: &crate::logging::TestEvent) {
        self.logger.log(event);
    }

    /// Generate deterministic test data using the context seed
    pub fn generate_markers(&self, count: u64, prefix: &str) -> crate::MarkerStream {
        let mut stream = crate::MarkerStream::new();
        let mut rng_state = self.seed;

        for i in 0..count {
            // Simple LCG for deterministic "randomness"
            rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

            stream
                .append(
                    crate::MarkerEventType::PolicyChange,
                    &format!("{}-{:08x}-{:08x}", prefix, i, rng_state),
                    1_700_000_000 + i,
                    &format!("trace-{}-{:08}", prefix, i),
                )
                .expect("append marker");
        }

        stream
    }

    /// Create a checkpoint from a marker stream
    pub fn create_checkpoint(&self, stream: &crate::MarkerStream) -> crate::MmrCheckpoint {
        let mut checkpoint = crate::MmrCheckpoint::enabled();
        checkpoint
            .rebuild_from_stream(stream)
            .expect("rebuild checkpoint");
        checkpoint
    }
}

/// Configuration options for test execution
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Whether to update golden files instead of comparing
    pub update_goldens: bool,

    /// Maximum execution time per test in milliseconds
    pub timeout_ms: u64,

    /// Whether to run performance-intensive tests
    pub include_performance: bool,

    /// Whether to run security-specific tests
    pub include_security: bool,

    /// Verbosity level (0-3)
    pub verbosity: u8,

    /// Whether to fail fast on first test failure
    pub fail_fast: bool,

    /// Test filter pattern (regex)
    pub filter: Option<String>,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            update_goldens: std::env::var("UPDATE_GOLDENS").is_ok(),
            timeout_ms: 30_000,
            include_performance: true,
            include_security: true,
            verbosity: 1,
            fail_fast: false,
            filter: std::env::var("TEST_FILTER").ok(),
        }
    }
}
