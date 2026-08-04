//! Structured logging for MMR conformance testing.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

/// Structured logger for test events
pub struct StructuredLogger {
    writer: Mutex<BufWriter<std::fs::File>>,
}

impl StructuredLogger {
    /// Create a new structured logger writing to the specified file
    pub fn new(log_path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Log a test event as structured JSON
    pub fn log(&self, event: &TestEvent) {
        let json = serde_json::to_string(event).expect("serialize test event");

        if let Ok(mut writer) = self.writer.lock() {
            writeln!(writer, "{}", json).expect("write log line");
            writer.flush().expect("flush log");
        }
    }
}

/// Structured test event for JSONL logging
#[derive(Debug, Serialize, Deserialize)]
pub struct TestEvent {
    /// ISO 8601 timestamp
    pub timestamp: String,

    /// Event severity level
    pub level: LogLevel,

    /// Event type code
    pub event_code: EventCode,

    /// Test identifier being executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_id: Option<String>,

    /// Test execution phase
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<TestPhase>,

    /// Human-readable message
    pub message: String,

    /// Test execution duration in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    /// Additional structured data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    /// Test run identifier
    pub run_id: String,
}

impl TestEvent {
    /// Create a new test event
    pub fn new(
        level: LogLevel,
        event_code: EventCode,
        message: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level,
            event_code,
            test_id: None,
            phase: None,
            message: message.into(),
            duration_ms: None,
            details: None,
            run_id: run_id.into(),
        }
    }

    /// Set test identifier
    pub fn with_test_id(mut self, test_id: impl Into<String>) -> Self {
        self.test_id = Some(test_id.into());
        self
    }

    /// Set test phase
    pub fn with_phase(mut self, phase: TestPhase) -> Self {
        self.phase = Some(phase);
        self
    }

    /// Set duration
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// Set additional details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Log levels
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Event type codes for structured parsing
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventCode {
    /// Test execution started
    TestStart,
    /// Individual test case execution
    TestCase,
    /// Test passed
    TestPass,
    /// Test failed
    TestFail,
    /// Test skipped
    TestSkip,
    /// Expected failure occurred
    TestXfail,
    /// Test execution error
    TestError,
    /// Test execution summary
    TestSummary,
    /// Performance measurement
    PerfMeasurement,
    /// Conformance violation detected
    ConformanceViolation,
    /// Security requirement validation
    SecurityCheck,
    /// Fixture generation/loading
    FixtureEvent,
    /// Test harness initialization
    HarnessInit,
    /// Test harness shutdown
    HarnessShutdown,
}

/// Test execution phases
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestPhase {
    /// Initial setup
    Setup,
    /// Core test execution
    Execute,
    /// Result verification
    Verify,
    /// Test cleanup
    Cleanup,
    /// Summary generation
    Summary,
}

/// Convenience macros for common logging patterns
#[macro_export]
macro_rules! log_test_start {
    ($logger:expr, $test_id:expr, $run_id:expr) => {
        $logger.log(
            &$crate::logging::TestEvent::new(
                $crate::logging::LogLevel::Info,
                $crate::logging::EventCode::TestStart,
                format!("Starting test: {}", $test_id),
                $run_id,
            )
            .with_test_id($test_id)
            .with_phase($crate::logging::TestPhase::Setup),
        );
    };
}

#[macro_export]
macro_rules! log_test_result {
    ($logger:expr, $test_id:expr, $result:expr, $duration:expr, $run_id:expr) => {
        let (level, code) = match $result.is_passing() {
            true => (
                $crate::logging::LogLevel::Info,
                $crate::logging::EventCode::TestPass,
            ),
            false => (
                $crate::logging::LogLevel::Error,
                $crate::logging::EventCode::TestFail,
            ),
        };

        $logger.log(
            &$crate::logging::TestEvent::new(
                level,
                code,
                format!("Test result: {}", $result),
                $run_id,
            )
            .with_test_id($test_id)
            .with_duration($duration)
            .with_phase($crate::logging::TestPhase::Summary),
        );
    };
}
