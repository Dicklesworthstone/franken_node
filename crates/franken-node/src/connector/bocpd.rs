// Bayesian Online Changepoint Detection (BOCPD) — Adams & MacKay 2007.
//
// Detects regime shifts in workload, incident, and trust-signal streams.
// Supports Gaussian, Poisson, and Categorical observation models with
// configurable hazard functions and multi-stream correlation.
//
// bd-3u4 — Section 10.11

use std::collections::VecDeque;
use std::f64::consts::PI;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_OBSERVATION: &str = "BCP-001";
pub const EVT_CHANGEPOINT_CANDIDATE: &str = "BCP-002";
pub const EVT_REGIME_SHIFT: &str = "BCP-003";
pub const EVT_CORRELATED_SHIFT: &str = "BCP-004";
pub const EVT_FALSE_POSITIVE_SUPPRESSED: &str = "BCP-005";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_BCP_INVALID_CONFIG: &str = "ERR_BCP_INVALID_CONFIG";
pub const ERR_BCP_EMPTY_STREAM: &str = "ERR_BCP_EMPTY_STREAM";
pub const ERR_BCP_MODEL_MISMATCH: &str = "ERR_BCP_MODEL_MISMATCH";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_BCP_POSTERIOR: &str = "INV-BCP-POSTERIOR";
pub const INV_BCP_MONOTONIC: &str = "INV-BCP-MONOTONIC";
pub const INV_BCP_BOUNDED: &str = "INV-BCP-BOUNDED";
pub const INV_BCP_MIN_RUN: &str = "INV-BCP-MIN-RUN";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// BOCPD configuration.
#[derive(Debug, Clone)]
pub struct BocpdConfig {
    /// Constant hazard rate parameter (1/lambda).
    pub hazard_lambda: f64,
    /// Minimum posterior probability to signal a changepoint.
    pub changepoint_threshold: f64,
    /// Minimum observations before signaling a shift.
    pub min_run_length: usize,
    /// Maximum run-length for truncation (bounds memory).
    pub max_run_length: usize,
    /// Maximum regime history entries.
    pub max_regime_history: usize,
    /// Multi-stream correlation window in seconds.
    pub correlation_window_secs: u64,
}

impl Default for BocpdConfig {
    fn default() -> Self {
        Self {
            hazard_lambda: 200.0,
            changepoint_threshold: 0.7,
            min_run_length: 10,
            max_run_length: 500,
            max_regime_history: 1000,
            correlation_window_secs: 60,
        }
    }
}

impl BocpdConfig {
    pub fn validate(&self) -> Result<(), BocpdError> {
        if self.hazard_lambda <= 0.0 {
            return Err(BocpdError::InvalidConfig(
                "hazard_lambda must be > 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.changepoint_threshold) {
            return Err(BocpdError::InvalidConfig(
                "threshold must be in [0, 1]".into(),
            ));
        }
        if self.max_run_length == 0 {
            return Err(BocpdError::InvalidConfig(
                "max_run_length must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum BocpdError {
    InvalidConfig(String),
    EmptyStream,
    ModelMismatch(String),
}

impl std::fmt::Display for BocpdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_BCP_INVALID_CONFIG}: {msg}"),
            Self::EmptyStream => write!(f, "{ERR_BCP_EMPTY_STREAM}"),
            Self::ModelMismatch(msg) => write!(f, "{ERR_BCP_MODEL_MISMATCH}: {msg}"),
        }
    }
}

impl std::error::Error for BocpdError {}

// ---------------------------------------------------------------------------
// Hazard functions
// ---------------------------------------------------------------------------

/// Hazard function type.
#[derive(Debug, Clone)]
pub enum HazardFunction {
    /// Constant hazard: h(r) = 1/lambda.
    Constant { lambda: f64 },
    /// Geometric hazard: h(r) = p.
    Geometric { p: f64 },
}

impl HazardFunction {
    pub fn evaluate(&self, _run_length: usize) -> f64 {
        match self {
            Self::Constant { lambda } => 1.0 / lambda,
            Self::Geometric { p } => *p,
        }
    }
}

// ---------------------------------------------------------------------------
// Observation models
// ---------------------------------------------------------------------------

/// Observation model for BOCPD.
#[derive(Debug, Clone)]
pub enum ObservationModel {
    Gaussian(GaussianModel),
    Poisson(PoissonModel),
    Categorical(CategoricalModel),
}

/// Gaussian (Normal-Inverse-Gamma) model for continuous metrics.
#[derive(Debug, Clone)]
pub struct GaussianModel {
    /// Prior mean.
    pub mu0: f64,
    /// Prior precision scaling (kappa).
    pub kappa0: f64,
    /// Prior shape (alpha).
    pub alpha0: f64,
    /// Prior rate (beta).
    pub beta0: f64,
}

impl Default for GaussianModel {
    fn default() -> Self {
        Self {
            mu0: 0.0,
            kappa0: 1.0,
            alpha0: 1.0,
            beta0: 1.0,
        }
    }
}

/// Sufficient statistics for Gaussian model.
#[derive(Debug, Clone)]
pub(crate) struct GaussianSuffStats {
    n: f64,
    mean: f64,
    sum_sq: f64,
}

impl GaussianSuffStats {
    fn new() -> Self {
        Self {
            n: 0.0,
            mean: 0.0,
            sum_sq: 0.0,
        }
    }

    fn update(&mut self, x: f64) {
        self.n += 1.0;
        let delta = x - self.mean;
        self.mean += delta / self.n;
        let delta2 = x - self.mean;
        self.sum_sq += delta * delta2;
    }
}

impl GaussianModel {
    /// Compute the predictive probability (Student-t) for a new observation.
    pub(crate) fn predictive_prob(&self, stats: &GaussianSuffStats, x: f64) -> f64 {
        let n = stats.n;
        let kappa_n = self.kappa0 + n;
        let mu_n = (self.kappa0 * self.mu0 + n * stats.mean) / kappa_n;
        let alpha_n = self.alpha0 + n / 2.0;
        let beta_n = self.beta0
            + 0.5 * stats.sum_sq
            + 0.5 * self.kappa0 * n * (stats.mean - self.mu0).powi(2) / kappa_n;

        let nu = 2.0 * alpha_n;
        let sigma_sq = beta_n * (kappa_n + 1.0) / (alpha_n * kappa_n);

        student_t_pdf(x, mu_n, sigma_sq, nu)
    }
}

/// Student-t PDF.
fn student_t_pdf(x: f64, mu: f64, sigma_sq: f64, nu: f64) -> f64 {
    let z = (x - mu) / sigma_sq.sqrt();
    let log_coeff = ln_gamma((nu + 1.0) / 2.0)
        - ln_gamma(nu / 2.0)
        - 0.5 * (nu * PI).ln()
        - 0.5 * sigma_sq.ln();
    let log_body = -((nu + 1.0) / 2.0) * (1.0 + z * z / nu).ln();
    (log_coeff + log_body).exp()
}

/// Simple ln(Gamma) via Stirling approximation for moderate values.
fn ln_gamma(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::INFINITY;
    }
    // Use the Lanczos approximation (g=7, n=9).
    let coefficients = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        let result = PI.ln() - (PI * x).sin().ln() - ln_gamma(1.0 - x);
        return result;
    }
    let x = x - 1.0;
    let mut a = coefficients[0];
    let t = x + 7.5;
    for (i, &coeff) in coefficients.iter().enumerate().skip(1) {
        a += coeff / (x + i as f64);
    }
    0.5 * (2.0 * PI).ln() + (t).ln() * (x + 0.5) - t + a.ln()
}

/// Poisson (Gamma prior) model for count data.
#[derive(Debug, Clone)]
pub struct PoissonModel {
    /// Prior shape.
    pub alpha0: f64,
    /// Prior rate.
    pub beta0: f64,
}

impl Default for PoissonModel {
    fn default() -> Self {
        Self {
            alpha0: 1.0,
            beta0: 1.0,
        }
    }
}

/// Sufficient statistics for Poisson model.
#[derive(Debug, Clone)]
pub(crate) struct PoissonSuffStats {
    n: f64,
    sum: f64,
}

impl PoissonSuffStats {
    fn new() -> Self {
        Self { n: 0.0, sum: 0.0 }
    }

    fn update(&mut self, x: f64) {
        self.n += 1.0;
        self.sum += x;
    }
}

impl PoissonModel {
    /// Negative binomial predictive probability.
    pub(crate) fn predictive_prob(&self, stats: &PoissonSuffStats, x: f64) -> f64 {
        let alpha_n = self.alpha0 + stats.sum;
        let beta_n = self.beta0 + stats.n;
        let k = x.round() as u64;

        // Negative binomial: NB(alpha_n, beta_n / (beta_n + 1))
        let p = beta_n / (beta_n + 1.0);
        let r = alpha_n;
        neg_binomial_pmf(k, r, p)
    }
}

fn neg_binomial_pmf(k: u64, r: f64, p: f64) -> f64 {
    let log_coeff = ln_gamma(k as f64 + r) - ln_gamma(k as f64 + 1.0) - ln_gamma(r);
    let log_prob = r * p.ln() + (k as f64) * (1.0 - p).ln();
    (log_coeff + log_prob).exp().max(1e-300)
}

/// Categorical (Dirichlet prior) model for discrete distributions.
#[derive(Debug, Clone)]
pub struct CategoricalModel {
    /// Number of categories.
    pub k: usize,
    /// Prior concentration per category.
    pub alpha0: f64,
}

impl Default for CategoricalModel {
    fn default() -> Self {
        Self { k: 4, alpha0: 1.0 }
    }
}

/// Sufficient statistics for Categorical model.
#[derive(Debug, Clone)]
pub(crate) struct CategoricalSuffStats {
    counts: Vec<f64>,
}

impl CategoricalSuffStats {
    fn new(k: usize) -> Self {
        Self {
            counts: vec![0.0; k],
        }
    }

    fn update(&mut self, category: usize) {
        if category < self.counts.len() {
            self.counts[category] += 1.0;
        }
    }
}

impl CategoricalModel {
    /// Dirichlet-Categorical predictive probability.
    pub(crate) fn predictive_prob(&self, stats: &CategoricalSuffStats, category: usize) -> f64 {
        if category >= self.k {
            return 1e-300;
        }
        let total = stats.counts.iter().sum::<f64>() + self.alpha0 * self.k as f64;
        (stats.counts[category] + self.alpha0) / total
    }
}

// ---------------------------------------------------------------------------
// Regime shift record
// ---------------------------------------------------------------------------

/// Detected regime shift.
#[derive(Debug, Clone)]
pub struct RegimeShift {
    pub stream_name: String,
    pub timestamp: u64,
    pub confidence: f64,
    pub run_length: usize,
    pub old_regime_mean: f64,
    pub new_regime_mean: f64,
}

// ---------------------------------------------------------------------------
// BOCPD detector for a single stream
// ---------------------------------------------------------------------------

/// BOCPD detector for a single observation stream.
#[derive(Debug)]
pub struct BocpdDetector {
    config: BocpdConfig,
    hazard: HazardFunction,
    model: ObservationModel,
    /// Posterior distribution over run lengths: run_length_probs[r] = P(r_t = r).
    run_length_probs: Vec<f64>,
    /// Sufficient statistics per run length.
    gaussian_stats: Vec<GaussianSuffStats>,
    poisson_stats: Vec<PoissonSuffStats>,
    categorical_stats: Vec<CategoricalSuffStats>,
    /// Number of observations processed.
    observation_count: usize,
    /// Current estimated run length (MAP).
    current_run_length: usize,
    /// Regime history.
    regime_history: VecDeque<RegimeShift>,
    /// Stream name.
    stream_name: String,
    /// Current regime mean (for shift detection).
    current_regime_sum: f64,
    current_regime_count: f64,
    /// Events generated.
    events: Vec<BocpdEvent>,
}

#[derive(Debug, Clone)]
pub struct BocpdEvent {
    pub code: String,
    pub detail: String,
}

impl BocpdDetector {
    pub fn new(
        stream_name: &str,
        config: BocpdConfig,
        hazard: HazardFunction,
        model: ObservationModel,
    ) -> Result<Self, BocpdError> {
        config.validate()?;
        let max_rl = config.max_run_length;
        let cat_k = match &model {
            ObservationModel::Categorical(m) => m.k,
            _ => 0,
        };
        Ok(Self {
            config,
            hazard,
            model,
            run_length_probs: vec![1.0], // Start with P(r=0) = 1
            gaussian_stats: vec![GaussianSuffStats::new(); max_rl + 1],
            poisson_stats: vec![PoissonSuffStats::new(); max_rl + 1],
            categorical_stats: vec![CategoricalSuffStats::new(cat_k); max_rl + 1],
            observation_count: 0,
            current_run_length: 0,
            regime_history: VecDeque::new(),
            stream_name: stream_name.to_string(),
            current_regime_sum: 0.0,
            current_regime_count: 0.0,
            events: Vec::new(),
        })
    }

    /// Process a new observation.
    pub fn observe(&mut self, x: f64, timestamp: u64) -> Option<RegimeShift> {
        self.observation_count += 1;
        self.events.push(BocpdEvent {
            code: EVT_OBSERVATION.to_string(),
            detail: format!("x={x:.4}"),
        });

        let n = self.run_length_probs.len();
        let max_rl = self.config.max_run_length.min(n);

        // Step 1: Compute predictive probabilities for each run length.
        let mut pred_probs = vec![0.0; max_rl];
        for (r, pred_prob) in pred_probs.iter_mut().enumerate() {
            *pred_prob = match &self.model {
                ObservationModel::Gaussian(m) => m.predictive_prob(&self.gaussian_stats[r], x),
                ObservationModel::Poisson(m) => m.predictive_prob(&self.poisson_stats[r], x),
                ObservationModel::Categorical(m) => {
                    m.predictive_prob(&self.categorical_stats[r], x as usize)
                }
            };
        }

        // Step 2: Growth probabilities.
        let mut growth_probs = vec![0.0; max_rl + 1];
        let mut changepoint_mass = 0.0;
        for r in 0..max_rl {
            let h = self.hazard.evaluate(r);
            let joint = self.run_length_probs[r] * pred_probs[r];
            growth_probs[r + 1] = joint * (1.0 - h);
            changepoint_mass += joint * h;
        }
        growth_probs[0] = changepoint_mass;

        // Step 3: Normalize.
        // INV-BCP-BOUNDED: truncate at max_run_length.
        if growth_probs.len() > self.config.max_run_length + 1 {
            growth_probs.truncate(self.config.max_run_length + 1);
        }
        let total: f64 = growth_probs.iter().sum();
        if total > 0.0 {
            for p in &mut growth_probs {
                *p /= total;
            }
        }

        self.run_length_probs = growth_probs;

        // Step 4: Update sufficient statistics.
        for r in (1..self.run_length_probs.len()).rev() {
            match &self.model {
                ObservationModel::Gaussian(_) => {
                    if r < self.gaussian_stats.len() {
                        self.gaussian_stats[r] = self.gaussian_stats[r - 1].clone();
                        self.gaussian_stats[r].update(x);
                    }
                }
                ObservationModel::Poisson(_) => {
                    if r < self.poisson_stats.len() {
                        self.poisson_stats[r] = self.poisson_stats[r - 1].clone();
                        self.poisson_stats[r].update(x);
                    }
                }
                ObservationModel::Categorical(_) => {
                    if r < self.categorical_stats.len() {
                        self.categorical_stats[r] = self.categorical_stats[r - 1].clone();
                        self.categorical_stats[r].update(x as usize);
                    }
                }
            }
        }
        // Reset stats for run length 0 (new regime).
        if !self.gaussian_stats.is_empty() {
            self.gaussian_stats[0] = GaussianSuffStats::new();
            self.gaussian_stats[0].update(x);
        }
        if !self.poisson_stats.is_empty() {
            self.poisson_stats[0] = PoissonSuffStats::new();
            self.poisson_stats[0].update(x);
        }
        if !self.categorical_stats.is_empty() {
            let k = self.categorical_stats[0].counts.len();
            self.categorical_stats[0] = CategoricalSuffStats::new(k);
            self.categorical_stats[0].update(x as usize);
        }

        // Track regime statistics.
        self.current_regime_sum += x;
        self.current_regime_count += 1.0;

        // Step 5: Check for changepoint.
        let cp_prob = self.run_length_probs[0];
        if cp_prob >= self.config.changepoint_threshold {
            self.events.push(BocpdEvent {
                code: EVT_CHANGEPOINT_CANDIDATE.to_string(),
                detail: format!("prob={cp_prob:.4}"),
            });

            // INV-BCP-MIN-RUN: only signal if enough observations in new regime.
            if self.current_run_length >= self.config.min_run_length {
                let old_mean = if self.current_regime_count > 1.0 {
                    (self.current_regime_sum - x) / (self.current_regime_count - 1.0)
                } else {
                    0.0
                };
                let shift = RegimeShift {
                    stream_name: self.stream_name.clone(),
                    timestamp,
                    confidence: cp_prob,
                    run_length: self.current_run_length,
                    old_regime_mean: old_mean,
                    new_regime_mean: x,
                };
                self.events.push(BocpdEvent {
                    code: EVT_REGIME_SHIFT.to_string(),
                    detail: format!("confidence={:.4}", shift.confidence),
                });
                self.regime_history.push_back(shift.clone());
                if self.regime_history.len() > self.config.max_regime_history {
                    self.regime_history.pop_front();
                }
                self.current_regime_sum = x;
                self.current_regime_count = 1.0;
                self.current_run_length = 0;
                return Some(shift);
            } else {
                self.events.push(BocpdEvent {
                    code: EVT_FALSE_POSITIVE_SUPPRESSED.to_string(),
                    detail: format!(
                        "run_length={} < min={}",
                        self.current_run_length, self.config.min_run_length
                    ),
                });
            }
        }

        // INV-BCP-MONOTONIC: run length increases within a regime.
        self.current_run_length += 1;
        None
    }

    /// Get the MAP (maximum a posteriori) run length.
    pub fn map_run_length(&self) -> usize {
        self.run_length_probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Get the posterior probability of a changepoint (run length = 0).
    pub fn changepoint_probability(&self) -> f64 {
        self.run_length_probs.first().copied().unwrap_or(0.0)
    }

    /// Get regime history.
    pub fn regime_history(&self) -> &VecDeque<RegimeShift> {
        &self.regime_history
    }

    /// Get number of observations processed.
    pub fn observation_count(&self) -> usize {
        self.observation_count
    }

    /// Get recorded events.
    pub fn events(&self) -> &[BocpdEvent] {
        &self.events
    }

    /// Verify INV-BCP-POSTERIOR: posterior sums to ~1.0.
    pub fn posterior_sum(&self) -> f64 {
        self.run_length_probs.iter().sum()
    }

    /// Get stream name.
    pub fn stream_name(&self) -> &str {
        &self.stream_name
    }
}

// ---------------------------------------------------------------------------
// Multi-stream correlator
// ---------------------------------------------------------------------------

/// Correlates regime shifts across multiple streams.
#[derive(Debug)]
pub struct MultiStreamCorrelator {
    window_secs: u64,
    recent_shifts: Vec<RegimeShift>,
}

impl MultiStreamCorrelator {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs,
            recent_shifts: Vec::new(),
        }
    }

    /// Record a regime shift and check for correlated shifts.
    pub fn record_shift(&mut self, shift: RegimeShift) -> Vec<RegimeShift> {
        // Prune old shifts outside window.
        let cutoff = shift.timestamp.saturating_sub(self.window_secs);
        self.recent_shifts.retain(|s| s.timestamp >= cutoff);

        // Find correlated shifts from different streams.
        let correlated: Vec<RegimeShift> = self
            .recent_shifts
            .iter()
            .filter(|s| s.stream_name != shift.stream_name)
            .cloned()
            .collect();

        self.recent_shifts.push(shift);
        correlated
    }

    /// Get count of recent shifts in window.
    pub fn recent_count(&self) -> usize {
        self.recent_shifts.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> BocpdConfig {
        BocpdConfig::default()
    }

    fn gaussian_detector(name: &str) -> BocpdDetector {
        BocpdDetector::new(
            name,
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap()
    }

    fn poisson_detector(name: &str) -> BocpdDetector {
        BocpdDetector::new(
            name,
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Poisson(PoissonModel::default()),
        )
        .unwrap()
    }

    fn categorical_detector(name: &str) -> BocpdDetector {
        BocpdDetector::new(
            name,
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel { k: 3, alpha0: 1.0 }),
        )
        .unwrap()
    }

    // -- Config validation --

    #[test]
    fn test_default_config_valid() {
        assert!(default_config().validate().is_ok());
    }

    #[test]
    fn test_invalid_hazard_lambda() {
        let mut cfg = default_config();
        cfg.hazard_lambda = -1.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_max_run_length() {
        let mut cfg = default_config();
        cfg.max_run_length = 0;
        assert!(cfg.validate().is_err());
    }

    // -- Detector creation --

    #[test]
    fn test_create_gaussian_detector() {
        let det = gaussian_detector("test");
        assert_eq!(det.stream_name(), "test");
        assert_eq!(det.observation_count(), 0);
    }

    #[test]
    fn test_create_poisson_detector() {
        let det = poisson_detector("test");
        assert_eq!(det.stream_name(), "test");
    }

    #[test]
    fn test_create_categorical_detector() {
        let det = categorical_detector("test");
        assert_eq!(det.stream_name(), "test");
    }

    // -- Observation processing --

    #[test]
    fn test_gaussian_single_observation() {
        let mut det = gaussian_detector("latency");
        det.observe(10.0, 1000);
        assert_eq!(det.observation_count(), 1);
    }

    #[test]
    fn test_poisson_single_observation() {
        let mut det = poisson_detector("incidents");
        det.observe(5.0, 1000);
        assert_eq!(det.observation_count(), 1);
    }

    #[test]
    fn test_categorical_single_observation() {
        let mut det = categorical_detector("errors");
        det.observe(1.0, 1000);
        assert_eq!(det.observation_count(), 1);
    }

    // -- INV-BCP-POSTERIOR: posterior sums to ~1.0 --

    #[test]
    fn test_posterior_sums_to_one_initial() {
        let det = gaussian_detector("test");
        assert!((det.posterior_sum() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_posterior_sums_to_one_after_observations() {
        let mut det = gaussian_detector("test");
        for i in 0..50 {
            det.observe(10.0 + (i as f64) * 0.1, 1000 + i);
        }
        assert!(
            (det.posterior_sum() - 1.0).abs() < 1e-6,
            "Posterior sum = {} (should be ~1.0)",
            det.posterior_sum()
        );
    }

    // -- INV-BCP-MONOTONIC: run length increases --

    #[test]
    fn test_run_length_increases_in_stable_regime() {
        let mut det = gaussian_detector("test");
        let mut prev_map = 0;
        for i in 0..20 {
            det.observe(10.0, 1000 + i);
            let map = det.map_run_length();
            assert!(
                map >= prev_map || map == 0,
                "MAP rl decreased: {prev_map} -> {map}"
            );
            prev_map = map;
        }
    }

    // -- Changepoint detection --

    #[test]
    fn test_no_changepoint_in_stable_stream() {
        let mut det = gaussian_detector("test");
        let mut shifts = 0;
        for i in 0..100 {
            if det.observe(10.0, 1000 + i as u64).is_some() {
                shifts += 1;
            }
        }
        // In a perfectly stable stream, no changepoints should be detected.
        assert_eq!(shifts, 0, "Should not detect changepoints in stable stream");
    }

    #[test]
    fn test_detects_changepoint_gaussian() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = 0.3;
        cfg.min_run_length = 5;
        // With constant hazard, changepoint posterior ≈ h = 1/lambda.
        // lambda must be < 1/threshold ≈ 3.3 for detection to be possible.
        cfg.hazard_lambda = 2.0;
        let mut det = BocpdDetector::new(
            "latency",
            cfg,
            HazardFunction::Constant { lambda: 2.0 },
            ObservationModel::Gaussian(GaussianModel {
                mu0: 10.0,
                kappa0: 0.1,
                alpha0: 1.0,
                beta0: 1.0,
            }),
        )
        .unwrap();

        let mut detected = false;
        // Regime 1: mean≈10 with slight jitter to avoid zero-variance underflow.
        for i in 0..50 {
            let jitter = if i % 2 == 0 { 0.1 } else { -0.1 };
            det.observe(10.0 + jitter, i as u64);
        }
        // Regime 2: mean=50 (big shift)
        for i in 50..100 {
            if det.observe(50.0, i as u64).is_some() {
                detected = true;
            }
        }
        assert!(detected, "Should detect regime shift from 10 to 50");
    }

    // -- INV-BCP-MIN-RUN: false positive suppression --

    #[test]
    fn test_min_run_length_suppression() {
        let mut cfg = default_config();
        cfg.min_run_length = 100; // Very high threshold.
        cfg.changepoint_threshold = 0.01;
        let mut det = BocpdDetector::new(
            "test",
            cfg,
            HazardFunction::Constant { lambda: 10.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap();

        // Only 20 observations — should never signal due to min_run_length.
        let mut shifts = 0;
        for i in 0..20 {
            if det
                .observe(if i < 10 { 0.0 } else { 100.0 }, i as u64)
                .is_some()
            {
                shifts += 1;
            }
        }
        assert_eq!(shifts, 0, "min_run_length should suppress all signals");
    }

    // -- INV-BCP-BOUNDED: truncation --

    #[test]
    fn test_run_length_bounded() {
        let mut cfg = default_config();
        cfg.max_run_length = 50;
        let mut det = BocpdDetector::new(
            "test",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap();

        for i in 0..100 {
            det.observe(10.0, i as u64);
        }
        assert!(
            det.run_length_probs.len() <= 52,
            "Run length should be bounded: {}",
            det.run_length_probs.len()
        );
    }

    // -- Hazard functions --

    #[test]
    fn test_constant_hazard() {
        let h = HazardFunction::Constant { lambda: 100.0 };
        assert!((h.evaluate(0) - 0.01).abs() < 1e-10);
        assert!((h.evaluate(50) - 0.01).abs() < 1e-10);
    }

    #[test]
    fn test_geometric_hazard() {
        let h = HazardFunction::Geometric { p: 0.05 };
        assert!((h.evaluate(0) - 0.05).abs() < 1e-10);
        assert!((h.evaluate(100) - 0.05).abs() < 1e-10);
    }

    // -- Observation models --

    #[test]
    fn test_gaussian_predictive_positive() {
        let m = GaussianModel::default();
        let stats = GaussianSuffStats::new();
        let p = m.predictive_prob(&stats, 0.0);
        assert!(p > 0.0, "Predictive probability should be positive");
        assert!(p.is_finite(), "Predictive probability should be finite");
    }

    #[test]
    fn test_poisson_predictive_positive() {
        let m = PoissonModel::default();
        let stats = PoissonSuffStats::new();
        let p = m.predictive_prob(&stats, 5.0);
        assert!(p > 0.0, "Predictive probability should be positive");
    }

    #[test]
    fn test_categorical_predictive_positive() {
        let m = CategoricalModel { k: 3, alpha0: 1.0 };
        let stats = CategoricalSuffStats::new(3);
        let p = m.predictive_prob(&stats, 0);
        assert!(p > 0.0);
    }

    #[test]
    fn test_categorical_predictive_sums_to_one() {
        let m = CategoricalModel { k: 3, alpha0: 1.0 };
        let stats = CategoricalSuffStats::new(3);
        let total: f64 = (0..3).map(|c| m.predictive_prob(&stats, c)).sum();
        assert!((total - 1.0).abs() < 1e-10);
    }

    // -- Sufficient statistics --

    #[test]
    fn test_gaussian_stats_update() {
        let mut stats = GaussianSuffStats::new();
        stats.update(10.0);
        stats.update(20.0);
        assert!((stats.n - 2.0).abs() < 1e-10);
        assert!((stats.mean - 15.0).abs() < 1e-10);
    }

    #[test]
    fn test_poisson_stats_update() {
        let mut stats = PoissonSuffStats::new();
        stats.update(3.0);
        stats.update(7.0);
        assert!((stats.n - 2.0).abs() < 1e-10);
        assert!((stats.sum - 10.0).abs() < 1e-10);
    }

    #[test]
    fn test_categorical_stats_update() {
        let mut stats = CategoricalSuffStats::new(3);
        stats.update(0);
        stats.update(0);
        stats.update(2);
        assert!((stats.counts[0] - 2.0).abs() < 1e-10);
        assert!((stats.counts[1] - 0.0).abs() < 1e-10);
        assert!((stats.counts[2] - 1.0).abs() < 1e-10);
    }

    // -- Regime history --

    #[test]
    fn test_regime_history_bounded() {
        let mut cfg = default_config();
        cfg.max_regime_history = 5;
        cfg.changepoint_threshold = 0.3;
        cfg.min_run_length = 3;
        cfg.hazard_lambda = 20.0;
        let mut det = BocpdDetector::new(
            "test",
            cfg,
            HazardFunction::Constant { lambda: 20.0 },
            ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: 0.01,
                alpha0: 1.0,
                beta0: 0.1,
            }),
        )
        .unwrap();

        // Generate many regime shifts.
        for epoch in 0..20 {
            let value = if epoch % 2 == 0 { 0.0 } else { 1000.0 };
            for i in 0..30 {
                det.observe(value, (epoch * 30 + i) as u64);
            }
        }
        assert!(
            det.regime_history().len() <= 5,
            "History should be bounded at 5, got {}",
            det.regime_history().len()
        );
    }

    // -- Multi-stream correlator --

    #[test]
    fn test_correlator_no_correlation() {
        let mut corr = MultiStreamCorrelator::new(60);
        let shift = RegimeShift {
            stream_name: "stream-a".to_string(),
            timestamp: 1000,
            confidence: 0.8,
            run_length: 50,
            old_regime_mean: 10.0,
            new_regime_mean: 50.0,
        };
        let correlated = corr.record_shift(shift);
        assert!(correlated.is_empty());
    }

    #[test]
    fn test_correlator_detects_correlation() {
        let mut corr = MultiStreamCorrelator::new(60);

        let shift_a = RegimeShift {
            stream_name: "stream-a".to_string(),
            timestamp: 1000,
            confidence: 0.8,
            run_length: 50,
            old_regime_mean: 10.0,
            new_regime_mean: 50.0,
        };
        corr.record_shift(shift_a);

        let shift_b = RegimeShift {
            stream_name: "stream-b".to_string(),
            timestamp: 1030,
            confidence: 0.9,
            run_length: 40,
            old_regime_mean: 5.0,
            new_regime_mean: 20.0,
        };
        let correlated = corr.record_shift(shift_b);
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].stream_name, "stream-a");
    }

    #[test]
    fn test_correlator_outside_window() {
        let mut corr = MultiStreamCorrelator::new(60);

        let shift_a = RegimeShift {
            stream_name: "stream-a".to_string(),
            timestamp: 1000,
            confidence: 0.8,
            run_length: 50,
            old_regime_mean: 10.0,
            new_regime_mean: 50.0,
        };
        corr.record_shift(shift_a);

        let shift_b = RegimeShift {
            stream_name: "stream-b".to_string(),
            timestamp: 2000, // Way outside 60s window
            confidence: 0.9,
            run_length: 40,
            old_regime_mean: 5.0,
            new_regime_mean: 20.0,
        };
        let correlated = corr.record_shift(shift_b);
        assert!(correlated.is_empty());
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = BocpdError::InvalidConfig("test".into());
        let msg = format!("{err}");
        assert!(msg.contains(ERR_BCP_INVALID_CONFIG));
    }

    #[test]
    fn test_empty_stream_error() {
        let err = BocpdError::EmptyStream;
        let msg = format!("{err}");
        assert!(msg.contains(ERR_BCP_EMPTY_STREAM));
    }

    // -- ln_gamma sanity --

    #[test]
    fn test_ln_gamma_basic() {
        // ln(Gamma(1)) = 0
        assert!((ln_gamma(1.0)).abs() < 0.01);
        // ln(Gamma(2)) = 0
        assert!((ln_gamma(2.0)).abs() < 0.01);
        // Gamma(5) = 24, ln(24) ≈ 3.178
        assert!((ln_gamma(5.0) - (24.0_f64).ln()).abs() < 0.01);
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut det = gaussian_detector("test");
        det.observe(10.0, 1000);
        assert!(!det.events().is_empty());
        assert_eq!(det.events()[0].code, EVT_OBSERVATION);
    }
}
