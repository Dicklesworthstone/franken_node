//! bd-29ct: Adversarial fuzz corpus gates for decode-DoS and replay/splice scenarios.
//!
//! Fuzz targets cover parser input, handshake replay/splice, token validation,
//! and decode-DoS.  A campaign runner triages crashes into reproducible fixtures
//! and a gate enforces minimum health budgets.

use std::collections::HashMap;
use std::fmt;

// ── Fuzz target categories ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FuzzCategory {
    ParserInput,
    HandshakeReplay,
    TokenValidation,
    DecodeDos,
}

impl fmt::Display for FuzzCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzCategory::ParserInput => write!(f, "parser_input"),
            FuzzCategory::HandshakeReplay => write!(f, "handshake_replay"),
            FuzzCategory::TokenValidation => write!(f, "token_validation"),
            FuzzCategory::DecodeDos => write!(f, "decode_dos"),
        }
    }
}

// ── Fuzz target ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzTarget {
    pub name: String,
    pub category: FuzzCategory,
    pub description: String,
}

// ── Seed & outcome ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOutcome {
    /// The input should be handled without crash.
    Handled,
    /// The input should be rejected (but not crash).
    Rejected,
}

#[derive(Debug, Clone)]
pub struct FuzzSeed {
    pub target: String,
    pub input_data: String,
    pub expected: SeedOutcome,
}

// ── Campaign result ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzCampaignResult {
    pub target: String,
    pub seeds_run: usize,
    pub crashes: usize,
    pub hangs: usize,
    pub coverage_pct: f64,
}

// ── Triage ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TriagedCrash {
    pub target: String,
    pub seed_input: String,
    pub error: String,
    pub reproducer: String,
}

// ── Gate verdict ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FuzzGateVerdict {
    pub target_results: Vec<FuzzCampaignResult>,
    pub untriaged: Vec<TriagedCrash>,
    pub verdict: String,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    /// FCG_MISSING_TARGET
    MissingTarget(String),
    /// FCG_INSUFFICIENT_CORPUS
    InsufficientCorpus { target: String, have: usize, need: usize },
    /// FCG_REGRESSION
    Regression { target: String, seed: String },
    /// FCG_UNTRIAGED_CRASH
    UntriagedCrash { target: String, seed: String },
    /// FCG_GATE_FAILED
    GateFailed(String),
}

impl FuzzError {
    pub fn code(&self) -> &'static str {
        match self {
            FuzzError::MissingTarget(_) => "FCG_MISSING_TARGET",
            FuzzError::InsufficientCorpus { .. } => "FCG_INSUFFICIENT_CORPUS",
            FuzzError::Regression { .. } => "FCG_REGRESSION",
            FuzzError::UntriagedCrash { .. } => "FCG_UNTRIAGED_CRASH",
            FuzzError::GateFailed(_) => "FCG_GATE_FAILED",
        }
    }
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzError::MissingTarget(t) => write!(f, "FCG_MISSING_TARGET: {t}"),
            FuzzError::InsufficientCorpus { target, have, need } => {
                write!(f, "FCG_INSUFFICIENT_CORPUS: {target} have={have} need={need}")
            }
            FuzzError::Regression { target, seed } => {
                write!(f, "FCG_REGRESSION: {target} seed={seed}")
            }
            FuzzError::UntriagedCrash { target, seed } => {
                write!(f, "FCG_UNTRIAGED_CRASH: {target} seed={seed}")
            }
            FuzzError::GateFailed(d) => write!(f, "FCG_GATE_FAILED: {d}"),
        }
    }
}

// ── Corpus registry ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct FuzzCorpus {
    targets: HashMap<String, FuzzTarget>,
    seeds: HashMap<String, Vec<FuzzSeed>>,
    min_seeds: usize,
}

impl FuzzCorpus {
    pub fn new(min_seeds: usize) -> Self {
        Self {
            targets: HashMap::new(),
            seeds: HashMap::new(),
            min_seeds,
        }
    }

    /// Register a fuzz target.
    pub fn add_target(&mut self, target: FuzzTarget) {
        self.targets.insert(target.name.clone(), target);
    }

    /// Add a seed to a target's corpus.
    pub fn add_seed(&mut self, seed: FuzzSeed) -> Result<(), FuzzError> {
        if !self.targets.contains_key(&seed.target) {
            return Err(FuzzError::MissingTarget(seed.target.clone()));
        }
        self.seeds
            .entry(seed.target.clone())
            .or_default()
            .push(seed);
        Ok(())
    }

    /// Validate that all required categories have targets with sufficient seeds.
    pub fn validate(&self) -> Result<(), FuzzError> {
        let required = [
            FuzzCategory::ParserInput,
            FuzzCategory::HandshakeReplay,
            FuzzCategory::TokenValidation,
            FuzzCategory::DecodeDos,
        ];

        for cat in &required {
            let found = self.targets.values().any(|t| t.category == *cat);
            if !found {
                return Err(FuzzError::MissingTarget(cat.to_string()));
            }
        }

        for (name, _target) in &self.targets {
            let count = self.seeds.get(name).map_or(0, |s| s.len());
            if count < self.min_seeds {
                return Err(FuzzError::InsufficientCorpus {
                    target: name.clone(),
                    have: count,
                    need: self.min_seeds,
                });
            }
        }

        Ok(())
    }

    /// Simulate running all seeds and produce a gate verdict.
    pub fn run_gate(&self) -> FuzzGateVerdict {
        let mut results = Vec::new();
        let mut untriaged = Vec::new();

        for (target_name, seeds) in &self.seeds {
            let mut crashes = 0;
            for seed in seeds {
                // Simulate: seeds with "crash" in input trigger a crash
                if seed.input_data.contains("crash") {
                    crashes += 1;
                    untriaged.push(TriagedCrash {
                        target: target_name.clone(),
                        seed_input: seed.input_data.clone(),
                        error: "simulated crash".into(),
                        reproducer: format!("{{\"target\":\"{target_name}\",\"input\":\"{}\"}}",
                                           seed.input_data),
                    });
                }
            }
            results.push(FuzzCampaignResult {
                target: target_name.clone(),
                seeds_run: seeds.len(),
                crashes,
                hangs: 0,
                coverage_pct: 0.0,
            });
        }

        let verdict = if untriaged.is_empty() {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        FuzzGateVerdict {
            target_results: results,
            untriaged,
            verdict,
        }
    }

    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    pub fn seed_count(&self, target: &str) -> usize {
        self.seeds.get(target).map_or(0, |s| s.len())
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(name: &str, cat: FuzzCategory) -> FuzzTarget {
        FuzzTarget {
            name: name.to_string(),
            category: cat,
            description: format!("test target {name}"),
        }
    }

    fn make_seed(target: &str, input: &str, outcome: SeedOutcome) -> FuzzSeed {
        FuzzSeed {
            target: target.to_string(),
            input_data: input.to_string(),
            expected: outcome,
        }
    }

    fn populated_corpus() -> FuzzCorpus {
        let mut c = FuzzCorpus::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        c.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        c.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));
        c.add_target(make_target("dos_fuzz", FuzzCategory::DecodeDos));

        for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
            for i in 0..3 {
                c.add_seed(make_seed(target, &format!("input_{i}"), SeedOutcome::Handled)).unwrap();
            }
        }
        c
    }

    #[test]
    fn validate_complete_corpus() {
        let c = populated_corpus();
        c.validate().unwrap();
    }

    #[test]
    fn reject_missing_category() {
        let mut c = FuzzCorpus::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        // Missing 3 categories
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), "FCG_MISSING_TARGET");
    }

    #[test]
    fn reject_insufficient_seeds() {
        let mut c = FuzzCorpus::new(3);
        c.add_target(make_target("parser_fuzz", FuzzCategory::ParserInput));
        c.add_target(make_target("handshake_fuzz", FuzzCategory::HandshakeReplay));
        c.add_target(make_target("token_fuzz", FuzzCategory::TokenValidation));
        c.add_target(make_target("dos_fuzz", FuzzCategory::DecodeDos));
        // Only 1 seed for parser_fuzz
        c.add_seed(make_seed("parser_fuzz", "x", SeedOutcome::Handled)).unwrap();
        let err = c.validate().unwrap_err();
        assert_eq!(err.code(), "FCG_INSUFFICIENT_CORPUS");
    }

    #[test]
    fn seed_to_missing_target() {
        let c = FuzzCorpus::new(3);
        let err = c.seeds.get("no_such").is_none();
        assert!(err);
        let mut c2 = FuzzCorpus::new(3);
        let err = c2.add_seed(make_seed("no_such", "x", SeedOutcome::Handled)).unwrap_err();
        assert_eq!(err.code(), "FCG_MISSING_TARGET");
    }

    #[test]
    fn gate_pass_no_crashes() {
        let c = populated_corpus();
        let verdict = c.run_gate();
        assert_eq!(verdict.verdict, "PASS");
        assert!(verdict.untriaged.is_empty());
    }

    #[test]
    fn gate_fail_with_crash() {
        let mut c = populated_corpus();
        c.add_seed(make_seed("parser_fuzz", "crash_input", SeedOutcome::Rejected)).unwrap();
        let verdict = c.run_gate();
        assert_eq!(verdict.verdict, "FAIL");
        assert!(!verdict.untriaged.is_empty());
    }

    #[test]
    fn target_and_seed_counts() {
        let c = populated_corpus();
        assert_eq!(c.target_count(), 4);
        assert_eq!(c.seed_count("parser_fuzz"), 3);
        assert_eq!(c.seed_count("no_such"), 0);
    }

    #[test]
    fn category_display() {
        assert_eq!(FuzzCategory::ParserInput.to_string(), "parser_input");
        assert_eq!(FuzzCategory::HandshakeReplay.to_string(), "handshake_replay");
        assert_eq!(FuzzCategory::TokenValidation.to_string(), "token_validation");
        assert_eq!(FuzzCategory::DecodeDos.to_string(), "decode_dos");
    }

    #[test]
    fn error_display() {
        let e = FuzzError::MissingTarget("t".into());
        assert!(e.to_string().contains("FCG_MISSING_TARGET"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = vec![
            FuzzError::MissingTarget("x".into()),
            FuzzError::InsufficientCorpus { target: "x".into(), have: 1, need: 3 },
            FuzzError::Regression { target: "x".into(), seed: "s".into() },
            FuzzError::UntriagedCrash { target: "x".into(), seed: "s".into() },
            FuzzError::GateFailed("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"FCG_MISSING_TARGET"));
        assert!(codes.contains(&"FCG_INSUFFICIENT_CORPUS"));
        assert!(codes.contains(&"FCG_REGRESSION"));
        assert!(codes.contains(&"FCG_UNTRIAGED_CRASH"));
        assert!(codes.contains(&"FCG_GATE_FAILED"));
    }

    #[test]
    fn triaged_crash_has_reproducer() {
        let tc = TriagedCrash {
            target: "parser_fuzz".into(),
            seed_input: "bad_data".into(),
            error: "panic".into(),
            reproducer: "{\"target\":\"parser_fuzz\"}".into(),
        };
        assert!(tc.reproducer.contains("parser_fuzz"));
    }
}
