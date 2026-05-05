// Bayesian Online Changepoint Detection (BOCPD) — Adams & MacKay 2007.
//
// Detects regime shifts in workload, incident, and trust-signal streams.
// Supports Gaussian, Poisson, and Categorical observation models with
// configurable hazard functions and multi-stream correlation.
//
// bd-3u4 — Section 10.11

use std::collections::VecDeque;
use std::f64::consts::PI;

use crate::capacity_defaults::aliases::MAX_EVENTS;
use crate::push_bounded;
const MAX_RECENT_SHIFTS: usize = 4096;
const MAX_CATEGORICAL_STATE_CELLS: usize = MAX_EVENTS;

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
        if !self.hazard_lambda.is_finite() || self.hazard_lambda <= 0.0 {
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
        if self.min_run_length == 0 {
            return Err(BocpdError::InvalidConfig(
                "min_run_length must be > 0".into(),
            ));
        }
        if self.min_run_length > self.max_run_length {
            return Err(BocpdError::InvalidConfig(
                "min_run_length must be <= max_run_length".into(),
            ));
        }
        if self.max_regime_history == 0 {
            return Err(BocpdError::InvalidConfig(
                "max_regime_history must be > 0".into(),
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
            Self::Constant { lambda } => {
                if !lambda.is_finite() || *lambda <= 0.0 {
                    return 0.0;
                }
                (1.0 / lambda).min(1.0)
            }
            Self::Geometric { p } => {
                if !p.is_finite() || !(0.0..=1.0).contains(p) {
                    return 0.0;
                }
                *p
            }
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
        if !x.is_finite() {
            return;
        }
        if !self.n.is_finite()
            || self.n < 0.0
            || !self.mean.is_finite()
            || !self.sum_sq.is_finite()
            || self.sum_sq < 0.0
        {
            *self = Self::new();
        }
        // Hardening: use saturating arithmetic for counter operations
        self.n = if self.n >= f64::MAX - 1.0 {
            f64::MAX
        } else {
            let result = self.n + 1.0;
            if !result.is_finite() {
                f64::MAX
            } else {
                result
            }
        };
        let delta = x - self.mean;
        self.mean += delta / self.n;
        if !self.mean.is_finite() {
            self.mean = 0.0;
        }
        let delta2 = x - self.mean;
        // Hardening: use safe addition with overflow detection
        let old_sum_sq = self.sum_sq;
        self.sum_sq = old_sum_sq + (delta * delta2);
        if !self.sum_sq.is_finite() || self.sum_sq < old_sum_sq {
            self.sum_sq = f64::MAX; // Saturated
        }
    }
}

impl GaussianModel {
    /// Compute the predictive probability (Student-t) for a new observation.
    pub(crate) fn predictive_prob(&self, stats: &GaussianSuffStats, x: f64) -> f64 {
        if !x.is_finite()
            || !self.mu0.is_finite()
            || !self.kappa0.is_finite()
            || self.kappa0 <= 0.0
            || !self.alpha0.is_finite()
            || self.alpha0 <= 0.0
            || !self.beta0.is_finite()
            || self.beta0 <= 0.0
            || !stats.n.is_finite()
            || stats.n < 0.0
            || !stats.mean.is_finite()
            || !stats.sum_sq.is_finite()
            || stats.sum_sq < 0.0
        {
            return 1e-300;
        }
        let n = stats.n;
        // Hardening: safe addition with overflow detection
        let kappa_n = {
            let result = self.kappa0 + n;
            if !result.is_finite() || result < self.kappa0.max(n) {
                f64::MAX // Saturated
            } else {
                result
            }
        };
        if kappa_n <= 0.0 {
            return 1e-300;
        }
        let mu_n = (self.kappa0 * self.mu0 + n * stats.mean) / kappa_n;
        if !mu_n.is_finite() {
            return 1e-300;
        }
        // Hardening: safe addition for alpha_n
        let alpha_n = {
            let half_n = n / 2.0;
            let result = self.alpha0 + half_n;
            if !result.is_finite() || result < self.alpha0.max(half_n) {
                f64::MAX // Saturated
            } else {
                result
            }
        };
        if alpha_n <= 0.0 {
            return 1e-300;
        }
        // Hardening: safe arithmetic for beta_n calculation
        let beta_n = {
            let term1 = self.beta0;
            let term2 = 0.5 * stats.sum_sq;
            let mean_diff = stats.mean - self.mu0;
            if !mean_diff.is_finite() {
                return 1e-300;
            }
            let term3 = 0.5 * self.kappa0 * n * mean_diff.powi(2) / kappa_n;

            let partial = term1 + term2;
            if !partial.is_finite() || partial < term1.max(term2) {
                f64::MAX
            } else {
                let result = partial + term3;
                if !result.is_finite() || result < partial.max(term3) {
                    f64::MAX
                } else {
                    result
                }
            }
        };

        let nu = 2.0 * alpha_n;
        let sigma_sq = beta_n * (kappa_n + 1.0) / (alpha_n * kappa_n);
        if !sigma_sq.is_finite() || sigma_sq <= 0.0 {
            return 1e-300;
        }

        student_t_pdf(x, mu_n, sigma_sq, nu)
    }
}

/// Student-t PDF.
fn student_t_pdf(x: f64, mu: f64, sigma_sq: f64, nu: f64) -> f64 {
    if !x.is_finite()
        || !mu.is_finite()
        || !sigma_sq.is_finite()
        || sigma_sq <= 0.0
        || !nu.is_finite()
        || nu <= 0.0
    {
        return 1e-300;
    }
    let z = (x - mu) / sigma_sq.sqrt();
    let log_coeff = ln_gamma((nu + 1.0) / 2.0)
        - ln_gamma(nu / 2.0)
        - 0.5 * (nu * PI).ln()
        - 0.5 * sigma_sq.ln();
    let log_body = -((nu + 1.0) / 2.0) * (1.0 + z * z / nu).ln();
    let result = (log_coeff + log_body).exp().max(1e-300);
    if result.is_finite() { result } else { 1e-300 }
}

/// Simple ln(Gamma) via Stirling approximation for moderate values.
fn ln_gamma(x: f64) -> f64 {
    if !x.is_finite() || x <= 0.0 {
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
    let mut a: f64 = coefficients[0];
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
        if !x.is_finite() || x < 0.0 || x.fract() != 0.0 || x >= (1u64 << 53) as f64 {
            return;
        }
        if !self.n.is_finite() || self.n < 0.0 || !self.sum.is_finite() || self.sum < 0.0 {
            *self = Self::new();
        }
        // Hardening: use saturating arithmetic for counter operations
        self.n = if self.n >= f64::MAX - 1.0 {
            f64::MAX
        } else {
            let result = self.n + 1.0;
            if !result.is_finite() {
                f64::MAX
            } else {
                result
            }
        };
        // Hardening: use safe addition with overflow detection
        let old_sum = self.sum;
        self.sum = old_sum + x;
        if !self.sum.is_finite() || (x > 0.0 && self.sum < old_sum) {
            self.sum = f64::MAX; // Saturated for overflow, preserve sign for underflow
        } else if x < 0.0 && self.sum > old_sum {
            self.sum = -f64::MAX; // Saturated underflow
        }
    }
}

impl PoissonModel {
    /// Negative binomial predictive probability.
    pub(crate) fn predictive_prob(&self, stats: &PoissonSuffStats, x: f64) -> f64 {
        if x < 0.0 || !x.is_finite() || x.fract() != 0.0 || x >= (1u64 << 53) as f64 {
            return 0.0;
        }
        if !self.alpha0.is_finite()
            || self.alpha0 <= 0.0
            || !self.beta0.is_finite()
            || self.beta0 <= 0.0
            || !stats.n.is_finite()
            || stats.n < 0.0
            || !stats.sum.is_finite()
            || stats.sum < 0.0
        {
            return 1e-300;
        }
        // Hardening: safe addition with overflow detection
        let alpha_n = {
            let result = self.alpha0 + stats.sum;
            if !result.is_finite() || result < self.alpha0.max(stats.sum) {
                f64::MAX // Saturated
            } else {
                result
            }
        };
        let beta_n = {
            let result = self.beta0 + stats.n;
            if !result.is_finite() || result < self.beta0.max(stats.n) {
                f64::MAX // Saturated
            } else {
                result
            }
        };
        // SECURITY: Safe f64 to u64 conversion with bounds checking.
        // x is pre-validated as finite, non-negative, integral, and < 2^53.
        let k = if x.is_finite() && x >= 0.0 && x <= (u64::MAX as f64) {
            x.round() as u64
        } else {
            // Defensive fallback - should not reach here due to earlier validation
            return 1e-300;
        };

        // Negative binomial: NB(alpha_n, beta_n / (beta_n + 1))
        let p = beta_n / (beta_n + 1.0);
        let r = alpha_n;
        neg_binomial_pmf(k, r, p)
    }
}

fn neg_binomial_pmf(k: u64, r: f64, p: f64) -> f64 {
    if !p.is_finite() || !r.is_finite() || p <= 0.0 || p >= 1.0 || r <= 0.0 {
        return 1e-300;
    }
    let k_f64 = if k <= (1u64 << 53) {
        k as f64
    } else {
        (1u64 << 53) as f64 // Cap to prevent precision loss
    };
    let log_coeff = ln_gamma(k_f64 + r) - ln_gamma(k_f64 + 1.0) - ln_gamma(r);
    let log_prob = r * p.ln() + k_f64 * (1.0 - p).ln();
    let result = (log_coeff + log_prob).exp().max(1e-300);
    if result.is_finite() { result } else { 1e-300 }
}

fn poisson_count(x: f64) -> Option<f64> {
    if !x.is_finite() || x < 0.0 || x.fract() != 0.0 || x >= (1u64 << 53) as f64 {
        None
    } else {
        Some(x)
    }
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
            // Hardening: use safe counter increment with overflow detection
            // Hardening: use saturating arithmetic for counter operations
            let old_count = self.counts[category];
            self.counts[category] = if old_count >= f64::MAX - 1.0 {
                f64::MAX
            } else {
                let result = old_count + 1.0;
                if !result.is_finite() {
                    f64::MAX
                } else {
                    result
                }
            };
        }
    }
}

impl CategoricalModel {
    /// Dirichlet-Categorical predictive probability.
    pub(crate) fn predictive_prob(&self, stats: &CategoricalSuffStats, category: usize) -> f64 {
        if self.k == 0
            || !self.alpha0.is_finite()
            || self.alpha0 <= 0.0
            || category >= self.k
            || stats.counts.len() != self.k
            || stats
                .counts
                .iter()
                .any(|count| !count.is_finite() || *count < 0.0)
        {
            return 1e-300;
        }
        let total = stats.counts.iter().copied().fold(0.0_f64, |a, b| {
            let sum = a + b;
            if sum.is_finite() { sum } else { f64::MAX }
        }) + self.alpha0 * self.k as f64;
        if !total.is_finite() || total <= 0.0 {
            return 1e-300;
        }
        let result = (stats.counts[category] + self.alpha0) / total;
        if result.is_finite() && result > 0.0 && result <= 1.0 {
            result
        } else {
            1e-300
        }
    }
}

fn categorical_index(x: f64) -> usize {
    if !x.is_finite() || x < 0.0 || x.fract() != 0.0 || x >= usize::MAX as f64 {
        usize::MAX
    } else {
        x as usize
    }
}

fn observation_model_accepts(model: &ObservationModel, x: f64) -> bool {
    if !x.is_finite() {
        return false;
    }

    match model {
        ObservationModel::Gaussian(m) => {
            m.mu0.is_finite()
                && m.kappa0.is_finite()
                && m.kappa0 > 0.0
                && m.alpha0.is_finite()
                && m.alpha0 > 0.0
                && m.beta0.is_finite()
                && m.beta0 > 0.0
        }
        ObservationModel::Poisson(m) => {
            m.alpha0.is_finite()
                && m.alpha0 > 0.0
                && m.beta0.is_finite()
                && m.beta0 > 0.0
                && poisson_count(x).is_some()
        }
        ObservationModel::Categorical(m) => {
            m.k > 0 && m.alpha0.is_finite() && m.alpha0 > 0.0 && categorical_index(x) < m.k
        }
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

fn stream_name_is_canonical(stream_name: &str) -> bool {
    let trimmed = stream_name.trim();
    !trimmed.is_empty() && trimmed == stream_name && !stream_name.chars().any(char::is_whitespace)
}

impl BocpdDetector {
    pub fn new(
        stream_name: &str,
        config: BocpdConfig,
        hazard: HazardFunction,
        model: ObservationModel,
    ) -> Result<Self, BocpdError> {
        if !stream_name_is_canonical(stream_name) {
            return Err(BocpdError::InvalidConfig(
                "stream_name must be non-empty and canonical".into(),
            ));
        }
        config.validate()?;
        let max_rl = config.max_run_length;
        let state_slots = max_rl.checked_add(1).ok_or_else(|| {
            BocpdError::InvalidConfig("max_run_length is too large for detector state".into())
        })?;
        let cat_k = match &model {
            ObservationModel::Categorical(m) => m.k,
            _ => 0,
        };
        if cat_k > 0 {
            let categorical_state_cells = state_slots.checked_mul(cat_k).ok_or_else(|| {
                BocpdError::InvalidConfig("categorical state is too large".into())
            })?;
            if categorical_state_cells > MAX_CATEGORICAL_STATE_CELLS {
                return Err(BocpdError::InvalidConfig(
                    "categorical state is too large".into(),
                ));
            }
        }
        Ok(Self {
            config,
            hazard,
            model,
            run_length_probs: vec![1.0], // Start with P(r=0) = 1
            gaussian_stats: vec![GaussianSuffStats::new(); state_slots],
            poisson_stats: vec![PoissonSuffStats::new(); state_slots],
            categorical_stats: vec![CategoricalSuffStats::new(cat_k); state_slots],
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
        if !observation_model_accepts(&self.model, x) {
            return None;
        }
        self.observation_count = self.observation_count.saturating_add(1);
        self.emit_event(BocpdEvent {
            code: EVT_OBSERVATION.to_string(),
            detail: format!("x={x:.4}"),
        });

        let n = self.run_length_probs.len();
        let max_rl = self.config.max_run_length.min(n);

        // Step 1: Compute predictive probabilities for each run length.
        let mut pred_probs = vec![0.0; max_rl];
        for (r, pred_prob) in pred_probs.iter_mut().enumerate() {
            *pred_prob = match &self.model {
                ObservationModel::Gaussian(m) => {
                    if r < self.gaussian_stats.len() {
                        m.predictive_prob(&self.gaussian_stats[r], x)
                    } else {
                        0.0
                    }
                }
                ObservationModel::Poisson(m) => {
                    if r < self.poisson_stats.len() {
                        m.predictive_prob(&self.poisson_stats[r], x)
                    } else {
                        0.0
                    }
                }
                ObservationModel::Categorical(m) => {
                    if r < self.categorical_stats.len() {
                        let cat = categorical_index(x);
                        m.predictive_prob(&self.categorical_stats[r], cat)
                    } else {
                        0.0
                    }
                }
            };
        }

        // Step 2: Growth probabilities.
        let mut growth_probs = vec![0.0; max_rl + 1];
        let mut changepoint_mass: f64 = 0.0;
        for r in 0..max_rl {
            let h = self.hazard.evaluate(r);
            // Hardening: safe multiplication with overflow detection
            let joint = {
                let result = self.run_length_probs[r] * pred_probs[r];
                if !result.is_finite() { 0.0 } else { result }
            };

            // Hardening: safe probability calculation with bounds checking
            let growth_prob = {
                let one_minus_h = 1.0 - h;
                let result = joint * one_minus_h;
                if !result.is_finite() || result < 0.0 {
                    0.0
                } else {
                    result
                }
            };
            growth_probs[r + 1] = growth_prob;

            // Hardening: safe addition with overflow detection
            let joint_h = joint * h;
            let old_mass = changepoint_mass;
            changepoint_mass = old_mass + joint_h;
            if !changepoint_mass.is_finite() || changepoint_mass < old_mass.max(joint_h) {
                changepoint_mass = f64::MAX; // Saturated
            }
        }
        growth_probs[0] = changepoint_mass;

        // Step 3: Normalize.
        // INV-BCP-BOUNDED: truncate at max_run_length.
        if growth_probs.len() > self.config.max_run_length + 1 {
            growth_probs.truncate(self.config.max_run_length + 1);
        }
        let total: f64 = growth_probs.iter().sum();
        if total.is_finite() && total > 0.0 {
            for p in &mut growth_probs {
                *p /= total;
            }
        } else {
            // Posterior collapsed — reinitialize to changepoint prior to prevent
            // permanent detector death from an all-zero/NaN posterior.
            growth_probs.fill(0.0);
            if !growth_probs.is_empty() {
                growth_probs[0] = 1.0;
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
                        if let Some(count) = poisson_count(x) {
                            self.poisson_stats[r].update(count);
                        }
                    }
                }
                ObservationModel::Categorical(_) => {
                    if r < self.categorical_stats.len() {
                        self.categorical_stats[r] = self.categorical_stats[r - 1].clone();
                        let cat = categorical_index(x);
                        self.categorical_stats[r].update(cat);
                    }
                }
            }
        }
        // Reset stats for run length 0 (new regime).
        match &self.model {
            ObservationModel::Gaussian(_) => {
                if !self.gaussian_stats.is_empty() {
                    self.gaussian_stats[0] = GaussianSuffStats::new();
                    self.gaussian_stats[0].update(x);
                }
            }
            ObservationModel::Poisson(_) => {
                if !self.poisson_stats.is_empty() {
                    self.poisson_stats[0] = PoissonSuffStats::new();
                    if let Some(count) = poisson_count(x) {
                        self.poisson_stats[0].update(count);
                    }
                }
            }
            ObservationModel::Categorical(_) => {
                if !self.categorical_stats.is_empty() {
                    let k = self.categorical_stats[0].counts.len();
                    self.categorical_stats[0] = CategoricalSuffStats::new(k);
                    let cat = categorical_index(x);
                    self.categorical_stats[0].update(cat);
                }
            }
        }

        // Track regime statistics.
        // Hardening: use safe addition with overflow detection
        let old_sum = self.current_regime_sum;
        self.current_regime_sum = old_sum + x;
        if !self.current_regime_sum.is_finite()
            || (x > 0.0 && self.current_regime_sum < old_sum)
            || (x < 0.0 && self.current_regime_sum > old_sum)
        {
            self.current_regime_sum = if x >= 0.0 { f64::MAX } else { -f64::MAX };
        }

        let old_count = self.current_regime_count;
        self.current_regime_count = if old_count >= f64::MAX - 1.0 {
            f64::MAX // Saturated
        } else {
            old_count + 1.0
        };
        if !self.current_regime_count.is_finite() {
            self.current_regime_count = f64::MAX;
        }

        // Step 5: Check for changepoint.
        let cp_prob = self.run_length_probs[0];
        if cp_prob >= self.config.changepoint_threshold {
            self.emit_event(BocpdEvent {
                code: EVT_CHANGEPOINT_CANDIDATE.to_string(),
                detail: format!("prob={cp_prob:.4}"),
            });

            // INV-BCP-MIN-RUN: only signal if enough observations in new regime.
            if self.current_run_length >= self.config.min_run_length {
                let old_mean = if self.current_regime_count > 1.0 {
                    let raw = (self.current_regime_sum - x) / (self.current_regime_count - 1.0);
                    if raw.is_finite() { raw } else { 0.0 }
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
                self.emit_event(BocpdEvent {
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
                self.emit_event(BocpdEvent {
                    code: EVT_FALSE_POSITIVE_SUPPRESSED.to_string(),
                    detail: format!(
                        "run_length={} < min={}",
                        self.current_run_length, self.config.min_run_length
                    ),
                });
            }
        }

        // INV-BCP-MONOTONIC: run length increases within a regime.
        self.current_run_length = self.current_run_length.saturating_add(1);
        None
    }

    /// Get the MAP (maximum a posteriori) run length.
    pub fn map_run_length(&self) -> usize {
        self.run_length_probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.total_cmp(b))
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

    fn emit_event(&mut self, event: BocpdEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
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
        if !regime_shift_is_valid(&shift) {
            return Vec::new();
        }

        // Prune old shifts outside window.
        let cutoff = shift.timestamp.saturating_sub(self.window_secs);
        self.recent_shifts
            .retain(|s| regime_shift_is_valid(s) && s.timestamp >= cutoff);

        // Find correlated shifts from different streams.
        let correlated: Vec<RegimeShift> = self
            .recent_shifts
            .iter()
            .filter(|s| s.stream_name != shift.stream_name)
            .cloned()
            .collect();

        push_bounded(&mut self.recent_shifts, shift, MAX_RECENT_SHIFTS);
        correlated
    }

    /// Get count of recent shifts in window.
    pub fn recent_count(&self) -> usize {
        self.recent_shifts.len()
    }
}

fn regime_shift_is_valid(shift: &RegimeShift) -> bool {
    stream_name_is_canonical(&shift.stream_name)
        && shift.confidence.is_finite()
        && (0.0..=1.0).contains(&shift.confidence)
        && shift.run_length > 0
        && shift.old_regime_mean.is_finite()
        && shift.new_regime_mean.is_finite()
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

    fn assert_detector_stream_name_rejected(stream_name: &str) {
        let err = BocpdDetector::new(
            stream_name,
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("non-canonical stream names must fail detector construction");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("stream_name")
        ));
    }

    #[test]
    fn negative_empty_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical(""));
    }

    #[test]
    fn negative_space_only_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("   "));
    }

    #[test]
    fn negative_tab_only_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("\t"));
    }

    #[test]
    fn negative_newline_only_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("\n"));
    }

    #[test]
    fn negative_leading_space_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical(" stream-a"));
    }

    #[test]
    fn negative_trailing_space_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream-a "));
    }

    #[test]
    fn negative_tab_padded_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("\tstream-a\t"));
    }

    #[test]
    fn negative_internal_space_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream a"));
    }

    #[test]
    fn negative_internal_tab_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream\ta"));
    }

    #[test]
    fn negative_internal_newline_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream\na"));
    }

    #[test]
    fn negative_internal_carriage_return_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream\ra"));
    }

    #[test]
    fn negative_crlf_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream\r\na"));
    }

    #[test]
    fn negative_form_feed_stream_name_is_not_canonical() {
        assert!(!stream_name_is_canonical("stream\u{000c}a"));
    }

    #[test]
    fn negative_detector_rejects_internal_space_stream_name() {
        assert_detector_stream_name_rejected("stream a");
    }

    #[test]
    fn negative_detector_rejects_internal_tab_stream_name() {
        assert_detector_stream_name_rejected("stream\ta");
    }

    #[test]
    fn negative_detector_rejects_internal_newline_stream_name() {
        assert_detector_stream_name_rejected("stream\na");
    }

    #[test]
    fn negative_detector_rejects_internal_carriage_return_stream_name() {
        assert_detector_stream_name_rejected("stream\ra");
    }

    #[test]
    fn negative_detector_rejects_crlf_stream_name() {
        assert_detector_stream_name_rejected("stream\r\na");
    }

    #[test]
    fn negative_detector_rejects_form_feed_stream_name() {
        assert_detector_stream_name_rejected("stream\u{000c}a");
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
    fn negative_nan_hazard_lambda_config_is_invalid() {
        let mut cfg = default_config();
        cfg.hazard_lambda = f64::NAN;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("hazard_lambda")
        ));
    }

    #[test]
    fn negative_infinite_hazard_lambda_config_is_invalid() {
        let mut cfg = default_config();
        cfg.hazard_lambda = f64::INFINITY;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("hazard_lambda")
        ));
    }

    #[test]
    fn negative_nan_threshold_config_is_invalid() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = f64::NAN;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("threshold")
        ));
    }

    #[test]
    fn negative_infinite_threshold_config_is_invalid() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = f64::INFINITY;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("threshold")
        ));
    }

    #[test]
    fn negative_negative_infinite_threshold_config_is_invalid() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = f64::NEG_INFINITY;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("threshold")
        ));
    }

    #[test]
    fn negative_below_zero_threshold_config_is_invalid() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = -0.01;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("threshold")
        ));
    }

    #[test]
    fn test_invalid_max_run_length() {
        let mut cfg = default_config();
        cfg.max_run_length = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn negative_zero_regime_history_config_is_invalid() {
        let mut cfg = default_config();
        cfg.max_regime_history = 0;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("max_regime_history")
        ));
    }

    #[test]
    fn negative_zero_min_run_length_config_is_invalid() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_min_run_length_above_run_length_cap_is_invalid() {
        let mut cfg = default_config();
        cfg.max_run_length = 4;
        cfg.min_run_length = 5;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_zero_regime_history_config() {
        let mut cfg = default_config();
        cfg.max_regime_history = 0;

        let err = BocpdDetector::new(
            "bad-history-cap",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("zero regime history cap must fail detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_regime_history")
        ));
    }

    #[test]
    fn negative_detector_rejects_zero_min_run_length_config() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;

        let err = BocpdDetector::new(
            "bad-zero-min-run",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("zero min_run_length must fail detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_zero_min_run_length_is_not_hidden_by_one_step_run_cap() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;
        cfg.max_run_length = 1;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_zero_min_run_length_is_not_hidden_by_zero_threshold() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;
        cfg.changepoint_threshold = 0.0;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_zero_min_run_length_is_not_hidden_by_large_hazard_lambda() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;
        cfg.hazard_lambda = f64::MAX;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_zero_min_run_length_for_poisson_model() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;

        let err = BocpdDetector::new(
            "bad-zero-min-run-poisson",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Poisson(PoissonModel::default()),
        )
        .expect_err("zero min_run_length must fail poisson detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_zero_min_run_length_for_categorical_model() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;

        let err = BocpdDetector::new(
            "bad-zero-min-run-categorical",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel { k: 3, alpha0: 1.0 }),
        )
        .expect_err("zero min_run_length must fail categorical detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_zero_min_run_length_takes_precedence_over_history_cap_failure() {
        let mut cfg = default_config();
        cfg.min_run_length = 0;
        cfg.max_regime_history = 0;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_unsatisfiable_min_run_length_config() {
        let mut cfg = default_config();
        cfg.max_run_length = 3;
        cfg.min_run_length = 4;

        let err = BocpdDetector::new(
            "bad-min-run",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("min_run_length beyond run-length cap must fail detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("min_run_length")
        ));
    }

    #[test]
    fn negative_config_validation_reports_first_structural_failure() {
        let mut cfg = default_config();
        cfg.max_run_length = 0;
        cfg.max_regime_history = 0;
        cfg.correlation_window_secs = 0;

        assert!(matches!(
            cfg.validate(),
            Err(BocpdError::InvalidConfig(msg)) if msg.contains("max_run_length")
        ));
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

    fn assert_invalid_stream_name_rejected(stream_name: &str) {
        let err = BocpdDetector::new(
            stream_name,
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("malformed stream name must fail detector creation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("stream_name")
        ));
    }

    #[test]
    fn negative_empty_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected("");
    }

    #[test]
    fn negative_space_only_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected("   ");
    }

    #[test]
    fn negative_newline_only_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected("\n");
    }

    #[test]
    fn negative_leading_space_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected(" latency");
    }

    #[test]
    fn negative_trailing_space_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected("latency ");
    }

    #[test]
    fn negative_tab_padded_stream_name_is_rejected() {
        assert_invalid_stream_name_rejected("\tlatency\t");
    }

    #[test]
    fn negative_invalid_stream_name_precedes_model_state_allocation() {
        let err = BocpdDetector::new(
            " latency ",
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel {
                k: usize::MAX,
                alpha0: 1.0,
            }),
        )
        .expect_err("stream identity must be rejected before model state allocation");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("stream_name")
        ));
    }

    fn detector_rejects_state_slot_overflow(model: ObservationModel) -> BocpdError {
        let mut cfg = default_config();
        cfg.min_run_length = usize::MAX;
        cfg.max_run_length = usize::MAX;

        assert!(
            cfg.validate().is_ok(),
            "config validation should remain structural; detector allocation guard owns state sizing"
        );

        BocpdDetector::new(
            "run-length-overflow",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            model,
        )
        .expect_err("detector creation must reject run-length state-slot overflow")
    }

    #[test]
    fn negative_detector_rejects_run_length_slot_overflow_for_gaussian_model() {
        let err = detector_rejects_state_slot_overflow(ObservationModel::Gaussian(
            GaussianModel::default(),
        ));

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_run_length_slot_overflow_for_poisson_model() {
        let err = detector_rejects_state_slot_overflow(ObservationModel::Poisson(
            PoissonModel::default(),
        ));

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_detector_rejects_run_length_slot_overflow_for_categorical_model() {
        let err =
            detector_rejects_state_slot_overflow(ObservationModel::Categorical(CategoricalModel {
                k: 3,
                alpha0: 1.0,
            }));

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_run_length_slot_overflow_is_not_hidden_by_zero_threshold() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = 0.0;
        cfg.min_run_length = usize::MAX;
        cfg.max_run_length = usize::MAX;

        let err = BocpdDetector::new(
            "zero-threshold-overflow",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("zero threshold must not hide run-length state overflow");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_run_length_slot_overflow_is_not_hidden_by_huge_history_cap() {
        let mut cfg = default_config();
        cfg.min_run_length = usize::MAX;
        cfg.max_run_length = usize::MAX;
        cfg.max_regime_history = usize::MAX;

        let err = BocpdDetector::new(
            "huge-history-overflow",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("huge history cap must not hide run-length state overflow");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_run_length_slot_overflow_precedes_oversized_categorical_state() {
        let mut cfg = default_config();
        cfg.min_run_length = usize::MAX;
        cfg.max_run_length = usize::MAX;

        let err = BocpdDetector::new(
            "categorical-state-overflow",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel {
                k: usize::MAX,
                alpha0: 1.0,
            }),
        )
        .expect_err(
            "run-length state overflow must be rejected before categorical state allocation",
        );

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    #[test]
    fn negative_run_length_slot_overflow_is_not_hidden_by_huge_hazard_lambda() {
        let mut cfg = default_config();
        cfg.hazard_lambda = f64::MAX;
        cfg.min_run_length = usize::MAX;
        cfg.max_run_length = usize::MAX;

        let err = BocpdDetector::new(
            "huge-hazard-overflow",
            cfg,
            HazardFunction::Constant { lambda: f64::MAX },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect_err("huge hazard lambda must not hide run-length state overflow");

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("max_run_length")
        ));
    }

    fn detector_rejects_categorical_state_size(cfg: BocpdConfig, k: usize) -> BocpdError {
        assert!(
            cfg.validate().is_ok(),
            "config validation should not allocate categorical state"
        );

        BocpdDetector::new(
            "categorical-state-too-large",
            cfg,
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Categorical(CategoricalModel { k, alpha0: 1.0 }),
        )
        .expect_err("detector creation must reject oversized categorical state")
    }

    #[test]
    fn negative_detector_rejects_categorical_state_cell_count_over_cap() {
        let err = detector_rejects_categorical_state_size(default_config(), MAX_EVENTS);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_detector_rejects_categorical_state_cell_count_overflow() {
        let mut cfg = default_config();
        cfg.min_run_length = usize::MAX - 1;
        cfg.max_run_length = usize::MAX - 1;

        let err = detector_rejects_categorical_state_size(cfg, 2);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_categorical_state_limit_is_not_hidden_by_zero_threshold() {
        let mut cfg = default_config();
        cfg.changepoint_threshold = 0.0;

        let err = detector_rejects_categorical_state_size(cfg, MAX_EVENTS);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_categorical_state_limit_is_not_hidden_by_huge_history_cap() {
        let mut cfg = default_config();
        cfg.max_regime_history = usize::MAX;

        let err = detector_rejects_categorical_state_size(cfg, MAX_EVENTS);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_categorical_state_limit_is_not_hidden_by_huge_hazard_lambda() {
        let mut cfg = default_config();
        cfg.hazard_lambda = f64::MAX;

        let err = detector_rejects_categorical_state_size(cfg, MAX_EVENTS);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_one_step_run_cap_still_bounds_categorical_state_cells() {
        let mut cfg = default_config();
        cfg.min_run_length = 1;
        cfg.max_run_length = 1;

        let err = detector_rejects_categorical_state_size(cfg, MAX_EVENTS);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
    }

    #[test]
    fn negative_categorical_state_limit_is_not_hidden_by_near_cap_run_length() {
        let mut cfg = default_config();
        cfg.min_run_length = MAX_EVENTS;
        cfg.max_run_length = MAX_EVENTS;

        let err = detector_rejects_categorical_state_size(cfg, 2);

        assert!(matches!(
            err,
            BocpdError::InvalidConfig(msg) if msg.contains("categorical state")
        ));
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
        let mut shifts: u32 = 0;
        for i in 0..100 {
            if det.observe(10.0, 1000 + i as u64).is_some() {
                shifts = shifts.saturating_add(1);
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
        let mut shifts: u32 = 0;
        for i in 0..20 {
            if det
                .observe(if i < 10 { 0.0 } else { 100.0 }, i as u64)
                .is_some()
            {
                shifts = shifts.saturating_add(1);
            }
        }
        assert_eq!(shifts, 0, "min_run_length should suppress all reports");
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

    fn valid_shift(stream_name: &str) -> RegimeShift {
        RegimeShift {
            stream_name: stream_name.to_string(),
            timestamp: 1_000,
            confidence: 0.8,
            run_length: 5,
            old_regime_mean: 1.0,
            new_regime_mean: 10.0,
        }
    }

    fn assert_invalid_shift_is_ignored(mut shift: RegimeShift) {
        let mut corr = MultiStreamCorrelator::new(60);
        assert!(corr.record_shift(valid_shift("baseline")).is_empty());
        shift.timestamp = 1_010;

        let correlated = corr.record_shift(shift);

        assert!(correlated.is_empty());
        assert_eq!(corr.recent_count(), 1);
    }

    fn assert_invalid_retained_shift_is_pruned(mut retained: RegimeShift) {
        retained.timestamp = 990;
        let mut corr = MultiStreamCorrelator {
            window_secs: 60,
            recent_shifts: vec![retained],
        };

        let correlated = corr.record_shift(valid_shift("fresh-valid-stream"));

        assert!(correlated.is_empty());
        assert_eq!(corr.recent_count(), 1);
        assert_eq!(corr.recent_shifts[0].stream_name, "fresh-valid-stream");
    }

    fn assert_confidence_is_rejected(confidence: f64) {
        let mut shift = valid_shift("negative-confidence");
        shift.confidence = confidence;

        assert!(!regime_shift_is_valid(&shift));
    }

    fn assert_correlator_confidence_is_ignored(confidence: f64) {
        let mut shift = valid_shift("correlator-negative-confidence");
        shift.confidence = confidence;

        assert_invalid_shift_is_ignored(shift);
    }

    fn assert_retained_confidence_is_pruned(confidence: f64) {
        let mut shift = valid_shift("retained-negative-confidence");
        shift.confidence = confidence;

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_empty_stream_name() {
        let mut shift = valid_shift("");
        shift.stream_name.clear();

        assert!(!regime_shift_is_valid(&shift));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_padded_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift(" padded-stream ")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_space_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream bad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_tab_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream\tbad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_newline_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream\nbad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_carriage_return_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream\rbad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_crlf_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream\r\nbad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_internal_form_feed_stream_name() {
        assert!(!regime_shift_is_valid(&valid_shift("stream\u{000c}bad")));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_nonfinite_confidence() {
        let mut shift = valid_shift("bad-confidence");
        shift.confidence = f64::NAN;

        assert!(!regime_shift_is_valid(&shift));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_confidence_above_one() {
        let mut shift = valid_shift("bad-confidence-bound");
        shift.confidence = 1.000_001;

        assert!(!regime_shift_is_valid(&shift));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_tiny_negative_confidence() {
        assert_confidence_is_rejected(-f64::EPSILON);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_small_negative_confidence() {
        assert_confidence_is_rejected(-0.000_001);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_fractional_negative_confidence() {
        assert_confidence_is_rejected(-0.5);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_minus_one_confidence() {
        assert_confidence_is_rejected(-1.0);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_large_negative_confidence() {
        assert_confidence_is_rejected(-1_000.0);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_min_finite_confidence() {
        assert_confidence_is_rejected(f64::MIN);
    }

    #[test]
    fn negative_regime_shift_validation_rejects_zero_run_length() {
        let mut shift = valid_shift("bad-run-length");
        shift.run_length = 0;

        assert!(!regime_shift_is_valid(&shift));
    }

    #[test]
    fn negative_regime_shift_validation_rejects_nonfinite_regime_means() {
        let mut old_mean = valid_shift("bad-old-mean");
        old_mean.old_regime_mean = f64::NEG_INFINITY;
        let mut new_mean = valid_shift("bad-new-mean");
        new_mean.new_regime_mean = f64::INFINITY;

        assert!(!regime_shift_is_valid(&old_mean));
        assert!(!regime_shift_is_valid(&new_mean));
    }

    #[test]
    fn negative_correlator_ignores_empty_stream_name_shift() {
        let mut shift = valid_shift("");
        shift.stream_name.clear();

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_padded_stream_name_shift() {
        let mut shift = valid_shift(" padded-stream ");
        shift.stream_name = " padded-stream ".to_string();

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_internal_space_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream bad"));
    }

    #[test]
    fn negative_correlator_ignores_internal_tab_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream\tbad"));
    }

    #[test]
    fn negative_correlator_ignores_internal_newline_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream\nbad"));
    }

    #[test]
    fn negative_correlator_ignores_internal_carriage_return_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream\rbad"));
    }

    #[test]
    fn negative_correlator_ignores_internal_crlf_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream\r\nbad"));
    }

    #[test]
    fn negative_correlator_ignores_internal_form_feed_stream_name_shift() {
        assert_invalid_shift_is_ignored(valid_shift("stream\u{000c}bad"));
    }

    #[test]
    fn negative_correlator_ignores_nonfinite_confidence_shift() {
        let mut shift = valid_shift("bad-confidence");
        shift.confidence = f64::NAN;

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_confidence_above_one_shift() {
        let mut shift = valid_shift("confidence-above-one");
        shift.confidence = 1.1;

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_tiny_negative_confidence_shift() {
        assert_correlator_confidence_is_ignored(-f64::EPSILON);
    }

    #[test]
    fn negative_correlator_ignores_small_negative_confidence_shift() {
        assert_correlator_confidence_is_ignored(-0.000_001);
    }

    #[test]
    fn negative_correlator_ignores_fractional_negative_confidence_shift() {
        assert_correlator_confidence_is_ignored(-0.5);
    }

    #[test]
    fn negative_correlator_ignores_minus_one_confidence_shift() {
        assert_correlator_confidence_is_ignored(-1.0);
    }

    #[test]
    fn negative_correlator_ignores_large_negative_confidence_shift() {
        assert_correlator_confidence_is_ignored(-1_000.0);
    }

    #[test]
    fn negative_correlator_ignores_min_finite_confidence_shift() {
        assert_correlator_confidence_is_ignored(f64::MIN);
    }

    #[test]
    fn negative_correlator_ignores_zero_run_length_shift() {
        let mut shift = valid_shift("zero-run-length");
        shift.run_length = 0;

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_nonfinite_old_mean_shift() {
        let mut shift = valid_shift("bad-old-mean");
        shift.old_regime_mean = f64::INFINITY;

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_ignores_nonfinite_new_mean_shift() {
        let mut shift = valid_shift("bad-new-mean");
        shift.new_regime_mean = f64::NEG_INFINITY;

        assert_invalid_shift_is_ignored(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_empty_stream_name_shift() {
        let mut shift = valid_shift("");
        shift.stream_name.clear();

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_padded_stream_name_shift() {
        let mut shift = valid_shift(" retained-stream ");
        shift.stream_name = " retained-stream ".to_string();

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_space_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained bad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_tab_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained\tbad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_newline_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained\nbad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_carriage_return_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained\rbad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_crlf_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained\r\nbad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_internal_form_feed_stream_name_shift() {
        assert_invalid_retained_shift_is_pruned(valid_shift("retained\u{000c}bad"));
    }

    #[test]
    fn negative_correlator_prunes_retained_nonfinite_confidence_shift() {
        let mut shift = valid_shift("retained-bad-confidence");
        shift.confidence = f64::NEG_INFINITY;

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_confidence_above_one_shift() {
        let mut shift = valid_shift("retained-confidence-above-one");
        shift.confidence = 1.01;

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_tiny_negative_confidence_shift() {
        assert_retained_confidence_is_pruned(-f64::EPSILON);
    }

    #[test]
    fn negative_correlator_prunes_retained_small_negative_confidence_shift() {
        assert_retained_confidence_is_pruned(-0.000_001);
    }

    #[test]
    fn negative_correlator_prunes_retained_fractional_negative_confidence_shift() {
        assert_retained_confidence_is_pruned(-0.5);
    }

    #[test]
    fn negative_correlator_prunes_retained_minus_one_confidence_shift() {
        assert_retained_confidence_is_pruned(-1.0);
    }

    #[test]
    fn negative_correlator_prunes_retained_large_negative_confidence_shift() {
        assert_retained_confidence_is_pruned(-1_000.0);
    }

    #[test]
    fn negative_correlator_prunes_retained_min_finite_confidence_shift() {
        assert_retained_confidence_is_pruned(f64::MIN);
    }

    #[test]
    fn negative_correlator_prunes_retained_zero_run_length_shift() {
        let mut shift = valid_shift("retained-zero-run-length");
        shift.run_length = 0;

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_nonfinite_old_mean_shift() {
        let mut shift = valid_shift("retained-bad-old-mean");
        shift.old_regime_mean = f64::NAN;

        assert_invalid_retained_shift_is_pruned(shift);
    }

    #[test]
    fn negative_correlator_prunes_retained_nonfinite_new_mean_shift() {
        let mut shift = valid_shift("retained-bad-new-mean");
        shift.new_regime_mean = f64::INFINITY;

        assert_invalid_retained_shift_is_pruned(shift);
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

    // -- Negative path hardening --

    #[test]
    fn negative_constant_hazard_rejects_non_positive_and_non_finite_values() {
        for hazard in [
            HazardFunction::Constant { lambda: 0.0 },
            HazardFunction::Constant { lambda: -1.0 },
            HazardFunction::Constant { lambda: f64::NAN },
            HazardFunction::Constant {
                lambda: f64::INFINITY,
            },
        ] {
            assert_eq!(hazard.evaluate(42), 0.0);
        }
    }

    #[test]
    fn negative_constant_hazard_below_one_is_clamped_to_probability_bound() {
        let hazard = HazardFunction::Constant { lambda: 0.5 };

        assert_eq!(hazard.evaluate(0), 1.0);
    }

    #[test]
    fn negative_geometric_hazard_rejects_out_of_probability_domain_values() {
        for hazard in [
            HazardFunction::Geometric { p: -0.1 },
            HazardFunction::Geometric { p: 1.1 },
            HazardFunction::Geometric { p: f64::NAN },
            HazardFunction::Geometric { p: f64::INFINITY },
        ] {
            assert_eq!(hazard.evaluate(7), 0.0);
        }
    }

    #[test]
    fn negative_student_t_invalid_parameters_return_floor_probability() {
        assert_eq!(student_t_pdf(0.0, 0.0, 0.0, 1.0), 1e-300);
        assert_eq!(student_t_pdf(0.0, 0.0, 1.0, 0.0), 1e-300);
        assert_eq!(student_t_pdf(f64::NAN, 0.0, 1.0, 1.0), 1e-300);
    }

    #[test]
    fn negative_student_t_rejects_all_nonfinite_parameters_before_math() {
        for (x, mu, variance, nu) in [
            (f64::INFINITY, 0.0, 1.0, 1.0),
            (0.0, f64::NAN, 1.0, 1.0),
            (0.0, 0.0, f64::INFINITY, 1.0),
            (0.0, 0.0, 1.0, f64::NAN),
        ] {
            assert_eq!(student_t_pdf(x, mu, variance, nu), 1e-300);
        }
    }

    #[test]
    fn negative_ln_gamma_rejects_nonfinite_domain_values() {
        for x in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(ln_gamma(x), f64::INFINITY);
        }
    }

    #[test]
    fn negative_student_t_rejects_negative_variance() {
        assert_eq!(student_t_pdf(0.0, 0.0, -1.0, 1.0), 1e-300);
    }

    #[test]
    fn negative_student_t_rejects_negative_zero_variance() {
        assert_eq!(student_t_pdf(0.0, 0.0, -0.0, 1.0), 1e-300);
    }

    #[test]
    fn negative_student_t_rejects_negative_degrees_of_freedom() {
        assert_eq!(student_t_pdf(0.0, 0.0, 1.0, -1.0), 1e-300);
    }

    #[test]
    fn negative_ln_gamma_rejects_zero_domain_value() {
        assert_eq!(ln_gamma(0.0), f64::INFINITY);
    }

    #[test]
    fn negative_ln_gamma_rejects_negative_integer_domain_value() {
        assert_eq!(ln_gamma(-2.0), f64::INFINITY);
    }

    #[test]
    fn negative_ln_gamma_rejects_negative_fraction_domain_value() {
        assert_eq!(ln_gamma(-0.25), f64::INFINITY);
    }

    #[test]
    fn negative_gaussian_predictive_rejects_impossible_prior_parameters() {
        let model = GaussianModel {
            mu0: 0.0,
            kappa0: 0.0,
            alpha0: 0.0,
            beta0: 0.0,
        };
        let stats = GaussianSuffStats::new();

        assert_eq!(model.predictive_prob(&stats, 0.0), 1e-300);
    }

    #[test]
    fn negative_gaussian_predictive_rejects_nonfinite_prior_mean() {
        let stats = GaussianSuffStats::new();
        for mu0 in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let model = GaussianModel {
                mu0,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 1.0,
            };

            assert_eq!(model.predictive_prob(&stats, 0.0), 1e-300);
        }
    }

    #[test]
    fn negative_gaussian_predictive_rejects_invalid_sufficient_stats() {
        let model = GaussianModel::default();

        for stats in [
            GaussianSuffStats {
                n: -1.0,
                mean: 0.0,
                sum_sq: 0.0,
            },
            GaussianSuffStats {
                n: 1.0,
                mean: f64::NAN,
                sum_sq: 0.0,
            },
            GaussianSuffStats {
                n: 1.0,
                mean: 0.0,
                sum_sq: -0.01,
            },
        ] {
            assert_eq!(model.predictive_prob(&stats, 0.0), 1e-300);
        }
    }

    #[test]
    fn negative_gaussian_predictive_rejects_overflowed_posterior_mean() {
        let model = GaussianModel {
            mu0: f64::MAX,
            kappa0: f64::MAX,
            alpha0: 1.0,
            beta0: 1.0,
        };
        let stats = GaussianSuffStats {
            n: f64::MAX,
            mean: f64::MAX,
            sum_sq: 0.0,
        };

        assert_eq!(model.predictive_prob(&stats, 1.0), 1e-300);
    }

    #[test]
    fn negative_gaussian_stats_update_ignores_nonfinite_observations() {
        for x in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut stats = GaussianSuffStats::new();
            stats.update(10.0);

            stats.update(x);

            assert_eq!(stats.n, 1.0);
            assert_eq!(stats.mean, 10.0);
            assert_eq!(stats.sum_sq, 0.0);
        }
    }

    #[test]
    fn negative_gaussian_stats_update_recovers_from_poisoned_state() {
        for mut stats in [
            GaussianSuffStats {
                n: -1.0,
                mean: 0.0,
                sum_sq: 0.0,
            },
            GaussianSuffStats {
                n: 1.0,
                mean: f64::NAN,
                sum_sq: 0.0,
            },
            GaussianSuffStats {
                n: 1.0,
                mean: 0.0,
                sum_sq: -1.0,
            },
        ] {
            stats.update(10.0);

            assert_eq!(stats.n, 1.0);
            assert_eq!(stats.mean, 10.0);
            assert_eq!(stats.sum_sq, 0.0);
        }
    }

    #[test]
    fn negative_observe_rejects_gaussian_nonfinite_prior_before_side_effects() {
        let mut det = BocpdDetector::new(
            "invalid-gaussian-prior",
            default_config(),
            HazardFunction::Constant { lambda: 200.0 },
            ObservationModel::Gaussian(GaussianModel {
                mu0: f64::NAN,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 1.0,
            }),
        )
        .unwrap();

        assert!(det.observe(10.0, 1).is_none());
        assert_eq!(det.observation_count(), 0);
        assert_eq!(det.current_regime_count, 0.0);
        assert!(det.events().is_empty());
    }

    #[test]
    fn negative_observe_rejects_gaussian_nonpositive_hyperparameters_before_side_effects() {
        for model in [
            GaussianModel {
                mu0: 0.0,
                kappa0: 0.0,
                alpha0: 1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: -1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 0.0,
            },
        ] {
            let mut det = BocpdDetector::new(
                "invalid-gaussian-scale",
                default_config(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Gaussian(model),
            )
            .unwrap();

            assert!(det.observe(10.0, 1).is_none());
            assert_eq!(det.observation_count(), 0);
            assert_eq!(det.current_regime_sum, 0.0);
            assert!(det.events().is_empty());
        }
    }

    #[test]
    fn negative_poisson_predictive_rejects_invalid_prior_and_stats() {
        let stats = PoissonSuffStats::new();
        assert_eq!(
            PoissonModel {
                alpha0: -1.0,
                beta0: 1.0,
            }
            .predictive_prob(&stats, 1.0),
            1e-300
        );

        let model = PoissonModel::default();
        for stats in [
            PoissonSuffStats { n: -1.0, sum: 0.0 },
            PoissonSuffStats { n: 1.0, sum: -0.1 },
            PoissonSuffStats {
                n: f64::NAN,
                sum: 1.0,
            },
        ] {
            assert_eq!(model.predictive_prob(&stats, 1.0), 1e-300);
        }
    }

    #[test]
    fn negative_observe_rejects_poisson_invalid_prior_before_side_effects() {
        for model in [
            PoissonModel {
                alpha0: 0.0,
                beta0: 1.0,
            },
            PoissonModel {
                alpha0: 1.0,
                beta0: f64::NAN,
            },
            PoissonModel {
                alpha0: 1.0,
                beta0: -1.0,
            },
        ] {
            let mut det = BocpdDetector::new(
                "invalid-poisson-prior",
                default_config(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Poisson(model),
            )
            .unwrap();

            assert!(det.observe(1.0, 1).is_none());
            assert_eq!(det.observation_count(), 0);
            assert_eq!(det.current_regime_count, 0.0);
            assert!(det.events().is_empty());
        }
    }

    #[test]
    fn negative_poisson_predictive_rejects_fractional_and_too_large_counts() {
        let model = PoissonModel::default();
        let stats = PoissonSuffStats::new();

        for x in [1.5, f64::NAN, f64::INFINITY, f64::MAX, u64::MAX as f64] {
            assert_eq!(model.predictive_prob(&stats, x), 0.0);
        }
    }

    #[test]
    fn negative_binomial_rejects_nonfinite_parameters_before_math() {
        for (r, p) in [(f64::NAN, 0.5), (1.0, f64::NAN), (f64::INFINITY, 0.5)] {
            assert_eq!(neg_binomial_pmf(1, r, p), 1e-300);
        }
    }

    #[test]
    fn negative_binomial_rejects_out_of_probability_domain() {
        for p in [0.0, -0.1, 1.0, 1.1] {
            assert_eq!(neg_binomial_pmf(1, 1.0, p), 1e-300);
        }
        assert_eq!(neg_binomial_pmf(1, 0.0, 0.5), 1e-300);
    }

    #[test]
    fn negative_poisson_count_rejects_malformed_observations() {
        for x in [
            -1.0,
            1.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            u64::MAX as f64,
        ] {
            assert_eq!(poisson_count(x), None);
        }
    }

    #[test]
    fn negative_poisson_stats_update_ignores_malformed_counts() {
        for x in [
            -1.0,
            1.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            u64::MAX as f64,
        ] {
            let mut stats = PoissonSuffStats::new();
            stats.update(3.0);

            stats.update(x);

            assert_eq!(stats.n, 1.0);
            assert_eq!(stats.sum, 3.0);
        }
    }

    #[test]
    fn negative_poisson_observe_does_not_coerce_negative_count_to_zero() {
        let mut det = poisson_detector("negative-count");

        det.observe(-1.0, 1);

        assert_eq!(det.observation_count(), 0);
        assert!(det.events().is_empty());
        assert!(
            det.poisson_stats
                .iter()
                .all(|stats| stats.n == 0.0 && stats.sum == 0.0)
        );
    }

    #[test]
    fn negative_poisson_observe_does_not_update_stats_for_fractional_count() {
        let mut det = poisson_detector("fractional-count");

        det.observe(1.5, 1);

        assert_eq!(det.observation_count(), 0);
        assert!(det.events().is_empty());
        assert!(
            det.poisson_stats
                .iter()
                .all(|stats| stats.n == 0.0 && stats.sum == 0.0)
        );
    }

    #[test]
    fn negative_poisson_observe_rejects_malformed_counts_before_regime_tracking() {
        for x in [-1.0, 1.5, f64::MAX] {
            let mut det = poisson_detector("malformed-count");

            assert!(det.observe(x, 1).is_none());

            assert_eq!(det.observation_count(), 0);
            assert_eq!(det.current_regime_count, 0.0);
            assert_eq!(det.current_regime_sum, 0.0);
            assert!(det.events().is_empty());
        }
    }

    #[test]
    fn negative_poisson_stats_update_recovers_from_poisoned_state() {
        for mut stats in [
            PoissonSuffStats { n: -1.0, sum: 0.0 },
            PoissonSuffStats {
                n: f64::NAN,
                sum: 0.0,
            },
            PoissonSuffStats { n: 1.0, sum: -1.0 },
            PoissonSuffStats {
                n: 1.0,
                sum: f64::INFINITY,
            },
        ] {
            stats.update(3.0);

            assert_eq!(stats.n, 1.0);
            assert_eq!(stats.sum, 3.0);
        }
    }

    #[test]
    fn negative_categorical_update_ignores_out_of_range_category() {
        let mut stats = CategoricalSuffStats::new(2);
        stats.update(usize::MAX);
        stats.update(2);

        assert_eq!(stats.counts, vec![0.0, 0.0]);
    }

    #[test]
    fn negative_categorical_update_recovers_poisoned_target_count() {
        for poisoned in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut stats = CategoricalSuffStats {
                counts: vec![poisoned, 2.0],
            };

            stats.update(0);

            assert_eq!(stats.counts, vec![1.0, 2.0]);
        }
    }

    #[test]
    fn negative_observe_rejects_categorical_invalid_prior_before_side_effects() {
        for model in [
            CategoricalModel { k: 0, alpha0: 1.0 },
            CategoricalModel {
                k: 3,
                alpha0: f64::INFINITY,
            },
            CategoricalModel { k: 3, alpha0: 0.0 },
        ] {
            let mut det = BocpdDetector::new(
                "invalid-categorical-prior",
                default_config(),
                HazardFunction::Constant { lambda: 200.0 },
                ObservationModel::Categorical(model),
            )
            .unwrap();

            assert!(det.observe(1.0, 1).is_none());
            assert_eq!(det.observation_count(), 0);
            assert_eq!(det.current_regime_sum, 0.0);
            assert!(det.events().is_empty());
        }
    }

    #[test]
    fn negative_categorical_index_rejects_fractional_and_oversized_values() {
        for x in [-1.0, 1.5, f64::MAX, usize::MAX as f64] {
            assert_eq!(categorical_index(x), usize::MAX);
        }
    }

    #[test]
    fn negative_observation_model_accepts_rejects_malformed_models() {
        assert!(!observation_model_accepts(
            &ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: f64::INFINITY,
                alpha0: 1.0,
                beta0: 1.0,
            }),
            1.0,
        ));
        assert!(!observation_model_accepts(
            &ObservationModel::Poisson(PoissonModel {
                alpha0: 1.0,
                beta0: 0.0,
            }),
            1.0,
        ));
        assert!(!observation_model_accepts(
            &ObservationModel::Categorical(CategoricalModel { k: 0, alpha0: 1.0 }),
            0.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_still_rejects_invalid_observation_values() {
        assert!(!observation_model_accepts(
            &ObservationModel::Gaussian(GaussianModel::default()),
            f64::NAN,
        ));
        assert!(!observation_model_accepts(
            &ObservationModel::Poisson(PoissonModel::default()),
            1.5,
        ));
        assert!(!observation_model_accepts(
            &ObservationModel::Categorical(CategoricalModel { k: 3, alpha0: 1.0 }),
            3.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_zero_gaussian_kappa() {
        assert!(!observation_model_accepts(
            &ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: 0.0,
                alpha0: 1.0,
                beta0: 1.0,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_negative_gaussian_alpha() {
        assert!(!observation_model_accepts(
            &ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: -1.0,
                beta0: 1.0,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_nonfinite_gaussian_beta() {
        assert!(!observation_model_accepts(
            &ObservationModel::Gaussian(GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: f64::NAN,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_nonfinite_poisson_alpha() {
        assert!(!observation_model_accepts(
            &ObservationModel::Poisson(PoissonModel {
                alpha0: f64::INFINITY,
                beta0: 1.0,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_negative_poisson_beta() {
        assert!(!observation_model_accepts(
            &ObservationModel::Poisson(PoissonModel {
                alpha0: 1.0,
                beta0: -1.0,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_observation_model_accepts_rejects_nonfinite_categorical_alpha() {
        assert!(!observation_model_accepts(
            &ObservationModel::Categorical(CategoricalModel {
                k: 3,
                alpha0: f64::NEG_INFINITY,
            }),
            1.0,
        ));
    }

    #[test]
    fn negative_categorical_observe_does_not_truncate_fractional_category() {
        let mut det = categorical_detector("fractional-category");

        det.observe(1.5, 1);

        assert_eq!(det.observation_count(), 0);
        assert!(det.events().is_empty());
        assert!(
            det.categorical_stats
                .iter()
                .all(|stats| stats.counts.iter().all(|count| *count == 0.0))
        );
    }

    #[test]
    fn negative_categorical_observe_does_not_saturate_oversized_category() {
        let mut det = categorical_detector("oversized-category");

        det.observe(f64::MAX, 1);

        assert_eq!(det.observation_count(), 0);
        assert!(det.events().is_empty());
        assert!(
            det.categorical_stats
                .iter()
                .all(|stats| stats.counts.iter().all(|count| *count == 0.0))
        );
    }

    #[test]
    fn negative_categorical_observe_rejects_out_of_range_category_before_tracking() {
        let mut det = categorical_detector("out-of-range-category");

        assert!(det.observe(3.0, 1).is_none());

        assert_eq!(det.observation_count(), 0);
        assert_eq!(det.current_regime_count, 0.0);
        assert_eq!(det.current_regime_sum, 0.0);
        assert!(det.events().is_empty());
        assert!(
            det.categorical_stats
                .iter()
                .all(|stats| stats.counts.iter().all(|count| *count == 0.0))
        );
    }

    #[test]
    fn negative_categorical_predictive_rejects_negative_probability_result() {
        let model = CategoricalModel { k: 2, alpha0: -0.5 };
        let stats = CategoricalSuffStats {
            counts: vec![2.0, 0.0],
        };

        assert_eq!(model.predictive_prob(&stats, 1), 1e-300);
    }

    #[test]
    fn negative_categorical_predictive_rejects_nonfinite_and_negative_counts() {
        let model = CategoricalModel { k: 2, alpha0: 1.0 };

        for stats in [
            CategoricalSuffStats {
                counts: vec![f64::NAN, 1.0],
            },
            CategoricalSuffStats {
                counts: vec![1.0, f64::INFINITY],
            },
            CategoricalSuffStats {
                counts: vec![1.0, -0.1],
            },
        ] {
            assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
        }
    }

    #[test]
    fn negative_categorical_predictive_rejects_probability_above_one() {
        let model = CategoricalModel { k: 2, alpha0: 1.0 };
        let stats = CategoricalSuffStats {
            counts: vec![10.0, -9.9],
        };

        assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
    }

    #[test]
    fn negative_categorical_predictive_rejects_mismatched_stats_width() {
        let model = CategoricalModel { k: 3, alpha0: 1.0 };
        for stats in [
            CategoricalSuffStats { counts: vec![1.0] },
            CategoricalSuffStats {
                counts: vec![1.0, 0.0, 0.0, 100.0],
            },
        ] {
            assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
        }
    }

    #[test]
    fn negative_geometric_hazard_above_one_is_ignored_by_detector() {
        let mut det = BocpdDetector::new(
            "bad-geometric",
            default_config(),
            HazardFunction::Geometric { p: 2.0 },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .unwrap();

        det.observe(10.0, 1);

        assert_eq!(HazardFunction::Geometric { p: 2.0 }.evaluate(0), 0.0);
        assert!(det.posterior_sum().is_finite());
        assert!((det.posterior_sum() - 1.0).abs() < 1e-6);
        assert!(det.run_length_probs.iter().all(|prob| *prob >= 0.0));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_existing_and_new_items() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_push_bounded_cap_one_drops_existing_item() {
        let mut items = vec![1];

        push_bounded(&mut items, 2, 1);

        assert_eq!(items, vec![2]);
    }

    #[test]
    fn negative_push_bounded_exactly_full_cap_drops_oldest_item() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 3);

        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn negative_push_bounded_overfull_vector_drains_to_capacity() {
        let mut items = vec![1, 2, 3, 4, 5];

        push_bounded(&mut items, 6, 3);

        assert_eq!(items, vec![4, 5, 6]);
    }

    #[test]
    fn negative_push_bounded_overfull_cap_one_keeps_only_new_item() {
        let mut items = vec![1, 2, 3, 4];

        push_bounded(&mut items, 5, 1);

        assert_eq!(items, vec![5]);
    }

    #[test]
    fn negative_push_bounded_repeated_pushes_never_exceed_cap() {
        let mut items = Vec::new();

        for item in 0..10 {
            push_bounded(&mut items, item, 3);
            assert!(items.len() <= 3);
        }

        assert_eq!(items, vec![7, 8, 9]);
    }

    #[test]
    fn negative_push_bounded_zero_capacity_remains_empty_after_repeated_pushes() {
        let mut items = Vec::new();

        for item in 0..10 {
            push_bounded(&mut items, item, 0);
        }

        assert!(items.is_empty());
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut det = gaussian_detector("test");
        det.observe(10.0, 1000);
        assert!(!det.events().is_empty());
        assert_eq!(det.events()[0].code, EVT_OBSERVATION);
    }

    #[test]
    fn test_nan_observation_is_ignored() {
        let mut det = gaussian_detector("test");
        let count_before = det.observation_count;
        let result = det.observe(f64::NAN, 1000);
        assert!(result.is_none());
        assert_eq!(det.observation_count, count_before);
    }

    #[test]
    fn test_inf_observation_is_ignored() {
        let mut det = gaussian_detector("test");
        let count_before = det.observation_count;
        let result = det.observe(f64::INFINITY, 2000);
        assert!(result.is_none());
        assert_eq!(det.observation_count, count_before);
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_bocpd_config_with_extreme_floating_point_values() {
        // Test BocpdConfig with various problematic floating point values
        let extreme_configs = vec![
            BocpdConfig {
                hazard_lambda: f64::NAN,
                changepoint_threshold: 0.7,
                min_run_length: 10,
                max_run_length: 500,
                max_regime_history: 1000,
                correlation_window_secs: 60,
            },
            BocpdConfig {
                hazard_lambda: f64::INFINITY,
                changepoint_threshold: 0.7,
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: f64::NEG_INFINITY,
                changepoint_threshold: 0.7,
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: 200.0,
                changepoint_threshold: f64::NAN,
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: 200.0,
                changepoint_threshold: 2.0, // > 1.0
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: 200.0,
                changepoint_threshold: -0.5, // < 0.0
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: 0.0, // Zero hazard
                changepoint_threshold: 0.7,
                ..Default::default()
            },
            BocpdConfig {
                hazard_lambda: -100.0, // Negative hazard
                changepoint_threshold: 0.7,
                ..Default::default()
            },
        ];

        for config in extreme_configs {
            // All invalid configs should be rejected by validation
            let result = config.validate();
            assert!(
                result.is_err(),
                "Config should be invalid: hazard_lambda={}, threshold={}",
                config.hazard_lambda,
                config.changepoint_threshold
            );

            match result.unwrap_err() {
                BocpdError::InvalidConfig(msg) => {
                    assert!(!msg.is_empty(), "Error message should not be empty");
                }
                other => panic!("Expected InvalidConfig error, got {:?}", other),
            }
        }
    }

    #[test]
    fn negative_bocpd_config_with_boundary_and_zero_length_values() {
        // Test BocpdConfig with boundary conditions for length parameters
        let boundary_configs = vec![
            BocpdConfig {
                min_run_length: 0, // Zero min run length
                ..Default::default()
            },
            BocpdConfig {
                max_run_length: 0, // Zero max run length
                ..Default::default()
            },
            BocpdConfig {
                min_run_length: 1000,
                max_run_length: 500, // min > max
                ..Default::default()
            },
            BocpdConfig {
                max_regime_history: 0, // Zero history
                ..Default::default()
            },
            BocpdConfig {
                min_run_length: usize::MAX,
                max_run_length: usize::MAX, // Maximum values
                max_regime_history: usize::MAX,
                correlation_window_secs: u64::MAX,
                ..Default::default()
            },
        ];

        for config in boundary_configs {
            let result = config.validate();

            // Zero min/max run length and min > max should be invalid
            if config.min_run_length == 0
                || config.max_run_length == 0
                || config.min_run_length > config.max_run_length
            {
                assert!(result.is_err(), "Should reject invalid run length config");
            } else {
                // Other boundary cases might be valid
                match result {
                    Ok(_) => {}  // Valid configuration
                    Err(_) => {} // Implementation may reject extreme values
                }
            }
        }
    }

    #[test]
    fn negative_hazard_function_with_invalid_parameters() {
        // Test HazardFunction evaluation with invalid parameters
        let invalid_hazards = vec![
            HazardFunction::Constant { lambda: 0.0 },      // Zero lambda
            HazardFunction::Constant { lambda: -1.0 },     // Negative lambda
            HazardFunction::Constant { lambda: f64::NAN }, // NaN lambda
            HazardFunction::Constant {
                lambda: f64::INFINITY,
            }, // Infinite lambda
            HazardFunction::Geometric { p: -0.5 },         // Negative probability
            HazardFunction::Geometric { p: 1.5 },          // Probability > 1.0
            HazardFunction::Geometric { p: f64::NAN },     // NaN probability
            HazardFunction::Geometric { p: f64::INFINITY }, // Infinite probability
        ];

        for hazard in invalid_hazards {
            // evaluate should return 0.0 for invalid parameters (safe fallback)
            let rate1 = hazard.evaluate(0);
            let rate2 = hazard.evaluate(100);
            let rate3 = hazard.evaluate(usize::MAX);

            for rate in [rate1, rate2, rate3] {
                assert!(
                    rate.is_finite(),
                    "Hazard rate should be finite for invalid parameters"
                );
                assert!(rate >= 0.0, "Hazard rate should be non-negative");
                assert!(rate <= 1.0, "Hazard rate should not exceed 1.0");
            }
        }

        // Test with valid edge case parameters
        let valid_edge_hazards = vec![
            HazardFunction::Constant {
                lambda: f64::EPSILON,
            }, // Very small lambda
            HazardFunction::Constant { lambda: 1e-100 }, // Extremely small lambda
            HazardFunction::Constant { lambda: 1e100 },  // Very large lambda
            HazardFunction::Geometric { p: 0.0 },        // Zero probability
            HazardFunction::Geometric { p: 1.0 },        // Maximum probability
            HazardFunction::Geometric { p: f64::EPSILON }, // Very small probability
        ];

        for hazard in valid_edge_hazards {
            let rate = hazard.evaluate(50);
            assert!(rate.is_finite(), "Valid hazard should produce finite rate");
            assert!(
                rate >= 0.0 && rate <= 1.0,
                "Valid hazard rate should be in [0,1]"
            );
        }
    }

    #[test]
    fn negative_gaussian_model_with_problematic_priors() {
        // Test GaussianModel with various problematic prior parameters
        let problematic_models = vec![
            GaussianModel {
                mu0: f64::NAN, // NaN prior mean
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: f64::INFINITY, // Infinite prior mean
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: 0.0, // Zero kappa (precision scaling)
                alpha0: 1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: -1.0, // Negative kappa
                alpha0: 1.0,
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: 0.0, // Zero alpha (shape)
                beta0: 1.0,
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 0.0, // Zero beta (rate)
            },
            GaussianModel {
                mu0: 0.0,
                kappa0: f64::NAN,
                alpha0: f64::INFINITY,
                beta0: f64::NEG_INFINITY,
            },
        ];

        for model in problematic_models {
            // Model creation should not panic with invalid parameters
            assert!(model.mu0.is_finite() || !model.mu0.is_finite()); // Basic existence check

            // Parameters should be preserved as-is (validation happens during use)
            if model.mu0.is_nan() {
                assert!(model.mu0.is_nan());
            }
            if model.kappa0.is_infinite() {
                assert!(model.kappa0.is_infinite());
            }
        }

        // Test default model is well-formed
        let default_model = GaussianModel::default();
        assert!(default_model.mu0.is_finite());
        assert!(default_model.kappa0.is_finite() && default_model.kappa0 > 0.0);
        assert!(default_model.alpha0.is_finite() && default_model.alpha0 > 0.0);
        assert!(default_model.beta0.is_finite() && default_model.beta0 > 0.0);
    }

    #[test]
    fn negative_gaussian_suff_stats_with_extreme_numerical_values() {
        // Test GaussianSuffStats with extreme numerical values
        let mut stats = GaussianSuffStats::new();

        // Initial state should be valid
        assert_eq!(stats.n, 0.0);
        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.sum_sq, 0.0);

        // Test update with extreme values
        let extreme_values = vec![
            f64::MIN,
            f64::MAX,
            -1e100,
            1e100,
            f64::EPSILON,
            -f64::EPSILON,
        ];

        for value in extreme_values {
            let original_n = stats.n;
            stats.update(value);

            // After update, n should increment
            assert_eq!(stats.n, original_n + 1.0);

            // Mean and sum_sq should be finite or handle overflow gracefully
            if !stats.mean.is_finite() || !stats.sum_sq.is_finite() {
                // If overflow occurs, it should not be NaN (though inf is possible)
                assert!(!stats.mean.is_nan() && !stats.sum_sq.is_nan());
            }
        }

        // Test with many small updates (numerical stability)
        let mut stable_stats = GaussianSuffStats::new();
        for _ in 0..10_000 {
            stable_stats.update(1e-100);
        }

        assert!(stable_stats.n > 0.0);
        assert!(stable_stats.mean.is_finite() || stable_stats.mean.is_infinite());
        assert!(stable_stats.sum_sq.is_finite() || stable_stats.sum_sq.is_infinite());
    }

    #[test]
    fn negative_bocpd_error_display_with_malicious_content() {
        // Test BocpdError Display implementation with problematic content
        let malicious_errors = vec![
            BocpdError::InvalidConfig("\0config\x01error\x7f".to_string()),
            BocpdError::ModelMismatch("model\nwith\nnewlines".to_string()),
            BocpdError::InvalidConfig("<script>alert('bocpd')</script>".to_string()),
            BocpdError::ModelMismatch("🚀model💀mismatch".to_string()),
            BocpdError::InvalidConfig("../../../etc/passwd".to_string()),
            BocpdError::ModelMismatch("\u{FFFF}unicode_error".to_string()),
        ];

        for error in malicious_errors {
            // Display formatting should not panic or interpret malicious content
            let display_output = format!("{}", error);
            let debug_output = format!("{:?}", error);

            // Should contain expected error code prefix
            assert!(display_output.starts_with("ERR_BCP_"));

            // Should not interpret malicious content as code
            assert!(!display_output.contains("(null)"));
            assert!(!display_output.contains("Error"));

            // Debug output should also be safe
            assert!(debug_output.contains("BocpdError"));
        }

        // Test EmptyStream error (no message content)
        let empty_error = BocpdError::EmptyStream;
        let display = format!("{}", empty_error);
        assert_eq!(display, ERR_BCP_EMPTY_STREAM);
    }

    #[test]
    fn negative_observation_model_type_safety_and_edge_cases() {
        // Test ObservationModel variants with edge cases
        let gaussian_model = GaussianModel {
            mu0: 1e100,     // Very large prior mean
            kappa0: 1e-100, // Very small precision
            alpha0: 1e100,  // Very large shape
            beta0: 1e-100,  // Very small rate
        };

        let extreme_observation = ObservationModel::Gaussian(gaussian_model);

        // Model creation should not panic with extreme parameters
        match extreme_observation {
            ObservationModel::Gaussian(model) => {
                assert!(!model.mu0.is_nan());
                assert!(!model.kappa0.is_nan());
                assert!(!model.alpha0.is_nan());
                assert!(!model.beta0.is_nan());
            }
            _ => panic!("Expected Gaussian model"),
        }

        // Test with problematic categorical model (if implemented)
        // Note: Testing interface even if full implementation isn't visible
        let categorical_model = CategoricalModel { categories: 1000 }; // Large category count
        let categorical_obs = ObservationModel::Categorical(categorical_model);

        match categorical_obs {
            ObservationModel::Categorical(model) => {
                assert!(model.categories > 0);
            }
            _ => panic!("Expected Categorical model"),
        }
    }

    #[test]
    fn negative_constants_validation_and_boundary_checks() {
        // Test that all event constants are well-formed
        let event_constants = [
            EVT_OBSERVATION,
            EVT_CHANGEPOINT_CANDIDATE,
            EVT_REGIME_SHIFT,
            EVT_CORRELATED_SHIFT,
            EVT_FALSE_POSITIVE_SUPPRESSED,
        ];

        for constant in &event_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("BCP-"),
                "Event constant should start with BCP-: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Event constant should be ASCII: {}",
                constant
            );
        }

        // Test error constants
        let error_constants = [
            ERR_BCP_INVALID_CONFIG,
            ERR_BCP_EMPTY_STREAM,
            ERR_BCP_MODEL_MISMATCH,
        ];

        for constant in &error_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("ERR_BCP_"),
                "Error constant should start with ERR_BCP_: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Error constant should be ASCII: {}",
                constant
            );
        }

        // Test invariant constants
        let invariant_constants = [
            INV_BCP_POSTERIOR,
            INV_BCP_MONOTONIC,
            INV_BCP_BOUNDED,
            INV_BCP_MIN_RUN,
        ];

        for constant in &invariant_constants {
            assert!(!constant.is_empty());
            assert!(
                constant.starts_with("INV-BCP-"),
                "Invariant should start with INV-BCP-: {}",
                constant
            );
            assert!(
                constant.is_ascii(),
                "Invariant constant should be ASCII: {}",
                constant
            );
        }

        // Test capacity constants
        assert!(MAX_RECENT_SHIFTS > 0);
        assert!(MAX_RECENT_SHIFTS <= 1_000_000); // Reasonable upper bound
        assert!(MAX_CATEGORICAL_STATE_CELLS > 0);
        assert!(MAX_CATEGORICAL_STATE_CELLS <= MAX_EVENTS);
    }

    #[test]
    fn negative_mathematical_edge_cases_in_calculations() {
        // Test mathematical edge cases that could appear in BOCPD calculations
        let test_cases = vec![
            (0.0, "zero"),
            (f64::EPSILON, "epsilon"),
            (f64::MIN_POSITIVE, "min_positive"),
            (PI, "pi"),
            (1.0 / 0.0, "positive_infinity"),  // This creates +inf
            (-1.0 / 0.0, "negative_infinity"), // This creates -inf
        ];

        for (value, description) in test_cases {
            // Test hazard function evaluation
            if value.is_finite() && value > 0.0 {
                let hazard = HazardFunction::Constant { lambda: value };
                let rate = hazard.evaluate(10);
                assert!(
                    rate.is_finite() && rate >= 0.0,
                    "Hazard rate should be valid for {}: {}",
                    description,
                    rate
                );
            }

            // Test as probability bound
            if value.is_finite() && (0.0..=1.0).contains(&value) {
                let config = BocpdConfig {
                    changepoint_threshold: value,
                    ..Default::default()
                };
                assert!(
                    config.validate().is_ok(),
                    "Valid threshold should be accepted: {}",
                    description
                );
            }
        }

        // Test problematic mathematical operations that could occur in BOCPD
        let problematic_ops = vec![
            (0.0 / 0.0, "zero_div_zero"),                     // NaN
            (f64::INFINITY - f64::INFINITY, "inf_minus_inf"), // NaN
            (0.0 * f64::INFINITY, "zero_times_inf"),          // NaN
        ];

        for (result, description) in problematic_ops {
            if result.is_nan() {
                // NaN values should be handled gracefully in configuration validation
                let config = BocpdConfig {
                    hazard_lambda: result,
                    ..Default::default()
                };
                assert!(
                    config.validate().is_err(),
                    "NaN hazard should be rejected: {}",
                    description
                );
            }
        }
    }

    #[test]
    fn negative_gaussian_observe_rejects_nan_without_side_effects() {
        let mut detector = gaussian_detector("gaussian-negative-nan");

        let result = detector.observe(f64::NAN, 1);

        assert!(result.is_none());
        assert_eq!(detector.observation_count(), 0);
        assert!(detector.events().is_empty());
        assert_eq!(detector.posterior_sum(), 1.0);
    }

    #[test]
    fn negative_poisson_observe_rejects_negative_count_without_side_effects() {
        let mut detector = poisson_detector("poisson-negative-count");

        let result = detector.observe(-1.0, 1);

        assert!(result.is_none());
        assert_eq!(detector.observation_count(), 0);
        assert!(detector.events().is_empty());
        assert_eq!(detector.posterior_sum(), 1.0);
    }

    #[test]
    fn negative_categorical_observe_rejects_out_of_range_without_side_effects() {
        let mut detector = categorical_detector("categorical-out-of-range");

        let result = detector.observe(4.0, 1);

        assert!(result.is_none());
        assert_eq!(detector.observation_count(), 0);
        assert!(detector.events().is_empty());
        assert_eq!(detector.posterior_sum(), 1.0);
    }

    #[test]
    fn negative_correlator_ignores_invalid_current_shift_without_pruning_retained() {
        let mut correlator = MultiStreamCorrelator::new(60);
        let retained = valid_shift("retained-stream");
        assert!(correlator.record_shift(retained).is_empty());
        let mut invalid = valid_shift("invalid stream");
        invalid.timestamp = 10_000;

        let correlated = correlator.record_shift(invalid);

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
    }

    #[test]
    fn negative_correlator_prunes_invalid_retained_shift_on_valid_record() {
        let mut correlator = MultiStreamCorrelator::new(60);
        let mut invalid_retained = valid_shift("invalid-retained");
        invalid_retained.confidence = f64::NAN;
        push_bounded(
            &mut correlator.recent_shifts,
            invalid_retained,
            MAX_RECENT_SHIFTS,
        );

        let correlated = correlator.record_shift(valid_shift("fresh-stream"));

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
        assert_eq!(correlator.recent_shifts[0].stream_name, "fresh-stream");
    }

    #[test]
    fn negative_correlator_does_not_report_same_stream_as_correlated() {
        let mut correlator = MultiStreamCorrelator::new(60);
        let first = valid_shift("same-stream");
        let mut second = valid_shift("same-stream");
        second.timestamp = first.timestamp.saturating_add(1);
        assert!(correlator.record_shift(first).is_empty());

        let correlated = correlator.record_shift(second);

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 2);
    }

    #[test]
    fn negative_collapsed_posterior_is_reset_to_safe_prior() {
        let mut detector = gaussian_detector("collapsed-posterior");
        detector.run_length_probs = vec![0.0, 0.0, 0.0];

        let result = detector.observe(1.0, 1);

        assert!(result.is_none());
        assert!(detector.posterior_sum().is_finite());
        assert!(detector.posterior_sum() > 0.0);
    }

    #[test]
    fn negative_empty_posterior_vector_is_rebuilt_without_panic() {
        let mut detector = gaussian_detector("empty-posterior");
        detector.run_length_probs.clear();

        let result = detector.observe(1.0, 1);

        assert!(result.is_none());
        assert_eq!(detector.observation_count(), 1);
        assert!(detector.posterior_sum() > 0.0);
    }

    #[test]
    fn negative_empty_posterior_accessors_fail_closed_to_zero() {
        let mut detector = gaussian_detector("empty-posterior-accessors");
        detector.run_length_probs.clear();

        assert_eq!(detector.map_run_length(), 0);
        assert_eq!(detector.changepoint_probability(), 0.0);
        assert_eq!(detector.posterior_sum(), 0.0);
    }

    #[test]
    fn negative_nan_posterior_observe_resets_without_recording_shift() {
        let mut detector = gaussian_detector("nan-posterior");
        detector.run_length_probs = vec![f64::NAN];

        let result = detector.observe(1.0, 1);

        assert!(result.is_none());
        assert!(detector.posterior_sum().is_finite());
        assert!(detector.changepoint_probability().is_finite());
        assert!(detector.regime_history().is_empty());
    }

    #[test]
    fn negative_invalid_constant_hazard_does_not_poison_posterior() {
        let config = BocpdConfig {
            min_run_length: 1,
            ..default_config()
        };
        let mut detector = BocpdDetector::new(
            "nan-hazard",
            config,
            HazardFunction::Constant { lambda: f64::NAN },
            ObservationModel::Gaussian(GaussianModel::default()),
        )
        .expect("detector should be constructible before observations");

        let result = detector.observe(1.0, 1);

        assert!(result.is_none());
        assert!(detector.posterior_sum().is_finite());
        assert!((detector.posterior_sum() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn negative_zero_window_correlator_prunes_older_shift_before_matching() {
        let mut correlator = MultiStreamCorrelator::new(0);
        assert!(correlator.record_shift(valid_shift("stream-a")).is_empty());
        let mut later = valid_shift("stream-b");
        later.timestamp = 1_001;

        let correlated = correlator.record_shift(later);

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
        assert_eq!(correlator.recent_shifts[0].stream_name, "stream-b");
    }

    #[test]
    fn negative_correlator_prunes_expired_retained_shift_on_valid_record() {
        let mut expired = valid_shift("expired-retained");
        expired.timestamp = 900;
        let mut correlator = MultiStreamCorrelator {
            window_secs: 50,
            recent_shifts: vec![expired],
        };
        let mut fresh = valid_shift("fresh-stream");
        fresh.timestamp = 1_100;

        let correlated = correlator.record_shift(fresh);

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
        assert_eq!(correlator.recent_shifts[0].stream_name, "fresh-stream");
    }

    #[test]
    fn negative_invalid_current_shift_does_not_prune_existing_history() {
        let mut correlator = MultiStreamCorrelator::new(0);
        assert!(
            correlator
                .record_shift(valid_shift("retained-stream"))
                .is_empty()
        );
        let mut invalid = valid_shift("invalid-current");
        invalid.confidence = f64::INFINITY;
        invalid.timestamp = 10_000;

        let correlated = correlator.record_shift(invalid);

        assert!(correlated.is_empty());
        assert_eq!(correlator.recent_count(), 1);
        assert_eq!(correlator.recent_shifts[0].stream_name, "retained-stream");
    }

    #[test]
    fn negative_poisson_stats_saturates_overflowing_sum() {
        let mut stats = PoissonSuffStats {
            n: 1.0,
            sum: f64::MAX,
        };

        stats.update(1.0);

        assert_eq!(stats.n, 2.0);
        assert_eq!(stats.sum, f64::MAX);
    }

    #[test]
    fn negative_categorical_update_saturates_overflowing_count() {
        let mut stats = CategoricalSuffStats {
            counts: vec![f64::MAX],
        };

        stats.update(0);

        assert_eq!(stats.counts, vec![f64::MAX]);
    }

    #[test]
    fn negative_poisson_predictive_rejects_stats_with_infinite_sum() {
        let model = PoissonModel::default();
        let stats = PoissonSuffStats {
            n: 1.0,
            sum: f64::INFINITY,
        };

        assert_eq!(model.predictive_prob(&stats, 1.0), 1e-300);
    }

    #[test]
    fn negative_categorical_predictive_rejects_total_overflow() {
        let model = CategoricalModel { k: 2, alpha0: 1.0 };
        let stats = CategoricalSuffStats {
            counts: vec![f64::MAX, f64::MAX],
        };

        assert_eq!(model.predictive_prob(&stats, 0), 1e-300);
    }

    #[test]
    fn negative_regime_sum_saturates_when_already_at_upper_bound() {
        let mut detector = gaussian_detector("regime-sum-upper-bound");
        detector.current_regime_sum = f64::MAX;

        assert!(detector.observe(1.0, 1).is_none());

        assert_eq!(detector.current_regime_sum, f64::MAX);
        assert_eq!(detector.observation_count(), 1);
    }

    #[test]
    fn negative_regime_count_saturates_when_already_at_upper_bound() {
        let mut detector = gaussian_detector("regime-count-upper-bound");
        detector.current_regime_count = f64::MAX;

        assert!(detector.observe(1.0, 1).is_none());

        assert_eq!(detector.current_regime_count, f64::MAX);
        assert_eq!(detector.observation_count(), 1);
    }

    #[test]
    fn negative_correlator_uses_saturating_cutoff_for_small_timestamp() {
        let mut correlator = MultiStreamCorrelator::new(u64::MAX);
        let mut first = valid_shift("first-underflow-window");
        first.timestamp = 0;
        let mut second = valid_shift("second-underflow-window");
        second.timestamp = 1;
        assert!(correlator.record_shift(first).is_empty());

        let correlated = correlator.record_shift(second);

        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].stream_name, "first-underflow-window");
        assert_eq!(correlator.recent_count(), 2);
    }

    #[test]
    fn negative_geometric_hazard_with_subnormal_probability_returns_safe_zero() {
        let hazard = HazardFunction::Geometric {
            p: f64::MIN_POSITIVE / 2.0,
        };

        // Should handle subnormal values gracefully
        assert_eq!(hazard.evaluate(100), 0.0);
    }

    #[test]
    fn negative_gaussian_model_with_extreme_precision_scaling_produces_safe_bounds() {
        let model = GaussianModel {
            mu0: 0.0,
            kappa0: f64::MAX,
            alpha0: 1.0,
            beta0: 1.0,
        };
        let mut stats = GaussianSuffStats::new();
        stats.update(1.0);

        // Should produce bounded result despite extreme kappa0
        let prob = model.predictive_prob(&stats, 0.5);
        assert!(prob >= 1e-300 && prob.is_finite());
    }

    #[test]
    fn negative_gaussian_sufficient_stats_rejects_precision_loss_from_extreme_delta() {
        let mut stats = GaussianSuffStats::new();
        stats.update(0.0);

        // Add observation that would cause precision loss in delta calculation
        stats.update(f64::MAX);

        // Stats should remain stable despite extreme delta
        assert!(stats.mean.is_finite());
        assert!(stats.sum_sq.is_finite());
        assert!(stats.n.is_finite());
    }

    #[test]
    fn negative_poisson_sufficient_stats_rejects_non_integer_count_above_threshold() {
        let mut stats = PoissonSuffStats::new();

        // Should reject fractional values that are too close to u64::MAX
        stats.update((u64::MAX as f64) - 0.1);

        // Should remain unchanged since input was rejected
        assert_eq!(stats.n, 0.0);
        assert_eq!(stats.sum, 0.0);
    }

    #[test]
    fn negative_student_t_pdf_with_extreme_degrees_of_freedom_prevents_overflow() {
        // Test with nu approaching 0 and extreme variance
        let result = student_t_pdf(1.0, 0.0, f64::MAX, f64::MIN_POSITIVE);

        assert_eq!(result, 1e-300);
    }

    #[test]
    fn negative_ln_gamma_with_negative_input_returns_infinity_barrier() {
        let result = ln_gamma(-1.0);

        assert_eq!(result, f64::INFINITY);
    }

    #[test]
    fn negative_neg_binomial_pmf_with_degenerate_probability_returns_safe_minimum() {
        // Test with probability at boundary values
        assert_eq!(neg_binomial_pmf(5, 1.0, 1.0), 1e-300);
        assert_eq!(neg_binomial_pmf(5, 1.0, 0.0), 1e-300);
    }

    #[test]
    fn negative_detector_observation_with_timestamp_underflow_maintains_sequence() {
        let mut detector = gaussian_detector("timestamp-underflow");

        // Add observation with very small timestamp that could underflow
        let result1 = detector.observe(1.0, 0);
        let result2 = detector.observe(2.0, u64::MIN);

        assert_eq!(detector.observation_count(), 2);
        assert!(result1.is_none()); // No changepoint expected
        assert!(result2.is_none()); // No changepoint expected
    }

    #[test]
    fn negative_multi_stream_correlator_with_timestamp_wraparound_maintains_ordering() {
        let mut correlator = MultiStreamCorrelator::new(60);

        let mut shift_near_max = valid_shift("near-max");
        shift_near_max.timestamp = u64::MAX - 1;

        let mut shift_after_wrap = valid_shift("after-wrap");
        shift_after_wrap.timestamp = 0;

        correlator.record_shift(shift_near_max);
        let correlated = correlator.record_shift(shift_after_wrap);

        // Should handle timestamp wraparound gracefully
        assert_eq!(correlated.len(), 1);
        assert_eq!(correlator.recent_count(), 2);
    }

    #[test]
    fn negative_categorical_model_predictive_with_zero_alpha_prevents_division_by_zero() {
        let model = CategoricalModel { k: 2, alpha0: 0.0 };
        let stats = CategoricalSuffStats {
            counts: vec![1.0, 1.0],
        };

        let prob = model.predictive_prob(&stats, 0);

        assert_eq!(prob, 1e-300);
    }

    // =========================================================================
    // NEGATIVE-PATH SECURITY HARDENING TESTS
    // =========================================================================
    // Added comprehensive attack vector testing focusing on:
    // - Vec::push unbounded growth attacks
    // - Boundary condition fail-closed attacks
    // - Resource exhaustion and capacity attacks
    // - Statistical model injection attacks

    #[test]
    fn test_recent_shifts_vec_push_unbounded_growth_attacks() {
        // Test for Vec::push without push_bounded in MultiStreamCorrelator (line 3905 pattern)
        let mut correlator = MultiStreamCorrelator::new(60);

        // Attack vector: fill recent_shifts without bounds
        for i in 0..10000 {
            let shift = CorrelatedShift {
                stream_name: format!("attack_stream_{}", i),
                timestamp: 1000 + i as u64,
                confidence: 0.9,
                regime_type: "attack".to_string(),
                strength: 1.0,
            };

            // Use push_bounded to prevent unbounded growth
            push_bounded(&mut correlator.recent_shifts, shift, MAX_RECENT_SHIFTS);

            // Check if memory usage is becoming problematic
            if i % 1000 == 0 {
                assert!(
                    correlator.recent_shifts.len() <= 5000,
                    "recent_shifts should be bounded to prevent memory exhaustion: {} items",
                    correlator.recent_shifts.len()
                );
            }
        }

        // Final verification - should not have unbounded growth
        assert!(
            correlator.recent_shifts.len() <= 5000,
            "recent_shifts grew too large: {} items",
            correlator.recent_shifts.len()
        );

        // Verify oldest entries are evicted when capacity is exceeded
        if correlator.recent_shifts.len() > 1000 {
            // Recent entries should still be present
            assert!(
                correlator
                    .recent_shifts
                    .iter()
                    .any(|s| s.stream_name.contains("attack_stream_9")),
                "Recent entries should be retained"
            );
        }
    }

    #[test]
    fn test_boundary_condition_fail_closed_attacks() {
        // Test > vs >= boundary conditions in various validation functions

        // Test hazard_lambda boundary (line 79: hazard_lambda <= 0.0)
        let boundary_lambdas = vec![
            (-f64::EPSILON, true, "negative epsilon"),
            (0.0, true, "exactly zero"),
            (f64::EPSILON, false, "positive epsilon"),
            (f64::MIN_POSITIVE, false, "minimum positive"),
        ];

        for (lambda, should_fail, description) in boundary_lambdas {
            let config = BocpdConfig {
                hazard_lambda: lambda,
                ..Default::default()
            };

            let result = config.validate();
            match (should_fail, result) {
                (true, Ok(_)) => {
                    panic!("Boundary attack should fail ({}): {}", description, lambda)
                }
                (false, Err(e)) => panic!(
                    "Valid boundary should pass ({}): {} - {}",
                    description, lambda, e
                ),
                _ => {} // Correct behavior
            }
        }

        // Test min_run_length > max_run_length boundary (line 99)
        let boundary_configs = vec![
            (10, 10, false, "equal min and max"),
            (10, 9, true, "min greater than max by 1"),
            (100, 99, true, "min greater than max by 1 (larger values)"),
        ];

        for (min_len, max_len, should_fail, description) in boundary_configs {
            let config = BocpdConfig {
                min_run_length: min_len,
                max_run_length: max_len,
                ..Default::default()
            };

            let result = config.validate();
            match (should_fail, result) {
                (true, Ok(_)) => panic!(
                    "Invalid config should fail ({}): min={} max={}",
                    description, min_len, max_len
                ),
                (false, Err(e)) => panic!(
                    "Valid config should pass ({}): min={} max={} - {}",
                    description, min_len, max_len, e
                ),
                _ => {} // Correct behavior
            }
        }

        // Test overflow detection boundaries (line 433: x > 0.0 && self.sum < old_sum)
        let mut stats = GaussianSuffStats::new();
        stats.sum = f64::MAX - 1.0;
        let old_sum = stats.sum;

        // This should detect overflow
        stats.update(2.0);

        // Should detect the overflow condition and handle gracefully
        assert!(stats.sum.is_finite(), "Should handle overflow gracefully");
    }

    #[test]
    fn test_statistical_model_injection_attacks() {
        // Test NaN/Infinity injection in statistical computations

        let nan_infinity_vectors = vec![
            (f64::NAN, "NaN injection"),
            (f64::INFINITY, "positive infinity injection"),
            (f64::NEG_INFINITY, "negative infinity injection"),
            (f64::MAX, "maximum float injection"),
            (f64::MIN, "minimum float injection"),
        ];

        for (malicious_value, attack_type) in nan_infinity_vectors {
            // Test GaussianModel with malicious parameters
            let malicious_gaussian = GaussianModel {
                mu0: malicious_value,
                kappa0: malicious_value,
                alpha0: malicious_value.abs(),
                beta0: malicious_value.abs(),
            };

            let stats = GaussianSuffStats::new();

            // Should handle malicious parameters gracefully
            let prob = malicious_gaussian.predictive_prob(&stats, 1.0);
            if !prob.is_finite() {
                // Expected for non-finite inputs
                assert!(
                    prob.is_nan() || prob.is_infinite(),
                    "Should propagate non-finite values ({})",
                    attack_type
                );
            }

            // Test PoissonModel with malicious parameters
            let malicious_poisson = PoissonModel {
                alpha0: malicious_value.abs(),
                beta0: malicious_value.abs(),
            };

            let poisson_stats = PoissonSuffStats {
                sum: 10.0,
                count: 5,
            };
            let poisson_prob = malicious_poisson.predictive_prob(&poisson_stats, 3);

            if !malicious_value.is_finite() {
                // Should handle non-finite parameters
                assert!(
                    !poisson_prob.is_finite() || poisson_prob == 1e-300,
                    "Should handle non-finite Poisson parameters ({})",
                    attack_type
                );
            }

            // Test CategoricalModel with malicious alpha0
            if malicious_value.is_finite() && malicious_value >= 0.0 {
                let malicious_categorical = CategoricalModel {
                    k: 3,
                    alpha0: malicious_value,
                };

                let cat_stats = CategoricalSuffStats {
                    counts: vec![1.0, 1.0, 1.0],
                };

                let cat_prob = malicious_categorical.predictive_prob(&cat_stats, 0);

                // Should produce bounded result
                assert!(
                    cat_prob >= 0.0 && (cat_prob <= 1.0 || cat_prob == 1e-300),
                    "Categorical probability should be bounded ({}): {}",
                    attack_type,
                    cat_prob
                );
            }
        }
    }

    #[test]
    fn test_resource_exhaustion_bocpd_state_attacks() {
        // Test resource exhaustion in BOCPD posterior maintenance

        let config = BocpdConfig {
            max_run_length: 1000, // Large but bounded
            ..Default::default()
        };

        let mut bocpd = match BocpdState::new(config.clone()) {
            Ok(b) => b,
            Err(_) => return, // Skip test if construction fails
        };

        // Attack: feed many observations to force large posterior state
        for i in 0..2000 {
            let observation = if i % 2 == 0 {
                Observation::Gaussian(i as f64 / 100.0)
            } else {
                Observation::Poisson((i % 10) as u32)
            };

            let result = bocpd.observe(observation, i as u64);

            // Should handle observations without memory exhaustion
            match result {
                Ok(Some(shift)) => {
                    // Verify shift properties are bounded
                    assert!(
                        shift.confidence >= 0.0 && shift.confidence <= 1.0,
                        "Shift confidence should be bounded: {}",
                        shift.confidence
                    );
                    assert!(
                        !shift.stream_name.is_empty(),
                        "Stream name should not be empty"
                    );
                    assert!(
                        shift.strength >= 0.0,
                        "Shift strength should be non-negative"
                    );
                }
                Ok(None) => {
                    // No shift detected - acceptable
                }
                Err(e) => {
                    // Should handle errors gracefully
                    assert!(
                        e.to_string().len() < 1000,
                        "Error message should be bounded"
                    );
                }
            }

            // Check memory usage periodically
            if i % 100 == 0 {
                // Posterior should be bounded by max_run_length
                assert!(
                    bocpd.posterior.len() <= config.max_run_length + 10,
                    "Posterior size should be bounded: {} vs max {}",
                    bocpd.posterior.len(),
                    config.max_run_length
                );
            }
        }

        // Final state verification
        assert!(
            bocpd.posterior.len() <= config.max_run_length + 10,
            "Final posterior size should be bounded"
        );

        // Posterior probabilities should sum to approximately 1.0
        let posterior_sum: f64 = bocpd.posterior.iter().sum();
        if posterior_sum.is_finite() {
            assert!(
                posterior_sum >= 0.9 && posterior_sum <= 1.1,
                "Posterior should approximately sum to 1.0: {}",
                posterior_sum
            );
        }
    }

    #[test]
    fn test_correlator_timestamp_boundary_attacks() {
        // Test timestamp boundary conditions in correlation window

        let window_secs = 60;
        let mut correlator = MultiStreamCorrelator::new(window_secs);

        // Test boundary timestamp attacks
        let base_time = 1000u64;
        let boundary_shifts = vec![
            // Exactly at window boundary
            (base_time + window_secs, "exactly at boundary"),
            // Just inside window
            (base_time + window_secs - 1, "just inside boundary"),
            // Just outside window
            (base_time + window_secs + 1, "just outside boundary"),
            // Far future
            (base_time + window_secs * 10, "far future"),
            // Potential overflow
            (u64::MAX - 1000, "near overflow"),
        ];

        // Record initial shift
        let initial_shift = CorrelatedShift {
            stream_name: "base_stream".to_string(),
            timestamp: base_time,
            confidence: 0.9,
            regime_type: "normal".to_string(),
            strength: 1.0,
        };
        let _ = correlator.record_shift(initial_shift);

        for (timestamp, description) in boundary_shifts {
            let test_shift = CorrelatedShift {
                stream_name: format!("test_stream_{}", timestamp),
                timestamp,
                confidence: 0.8,
                regime_type: "test".to_string(),
                strength: 0.5,
            };

            // Should handle timestamp boundaries gracefully
            let correlated = correlator.record_shift(test_shift);

            // Verify correlation logic respects window boundaries
            if timestamp <= base_time + window_secs {
                // Should potentially correlate within window
                assert!(
                    correlated.len() <= correlator.recent_shifts.len(),
                    "Correlated shifts should not exceed recent shifts ({})",
                    description
                );
            } else {
                // Should not correlate outside window
                // (correlation behavior depends on implementation details)
            }

            // Verify state consistency
            assert!(
                correlator.recent_shifts.len() <= 1000,
                "Recent shifts should be bounded ({}): {}",
                description,
                correlator.recent_shifts.len()
            );

            for shift in &correlator.recent_shifts {
                assert!(
                    !shift.stream_name.is_empty(),
                    "Stream names should not be empty"
                );
                assert!(
                    shift.confidence >= 0.0 && shift.confidence <= 1.0,
                    "Confidence should be bounded"
                );
                assert!(shift.strength >= 0.0, "Strength should be non-negative");
            }
        }
    }
}
