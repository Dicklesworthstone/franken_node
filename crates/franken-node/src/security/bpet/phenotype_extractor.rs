//! Deterministic BPET phenotype feature extraction.
//!
//! The extractor converts version-scoped runtime evidence, manifest metadata,
//! and code metrics into a stable seven-dimensional phenotype vector. Missing
//! evidence is represented explicitly as typed uncertainty, so downstream drift
//! and lineage stages can distinguish a measured zero from an unknown value.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::{MAX_AUDIT_LOG_ENTRIES, MAX_FIELDS};
use crate::push_bounded;

use super::drift_features::PhenotypeSample;

pub const PHENOTYPE_EXTRACTOR_SCHEMA_VERSION: &str = "bpet.phenotype_extractor.v1";
pub const DEFAULT_MAX_BATCH_VERSIONS: usize = 4096;

pub mod event_codes {
    pub const BPET_EXTRACT_INPUT_ACCEPTED: &str = "BPET-EXTRACT-001";
    pub const BPET_EXTRACT_INPUT_REJECTED: &str = "BPET-EXTRACT-002";
    pub const BPET_EXTRACT_FEATURE_KNOWN: &str = "BPET-EXTRACT-003";
    pub const BPET_EXTRACT_FEATURE_UNCERTAIN: &str = "BPET-EXTRACT-004";
    pub const BPET_EXTRACT_VECTOR_EMITTED: &str = "BPET-EXTRACT-005";
    pub const BPET_EXTRACT_BATCH_EMITTED: &str = "BPET-EXTRACT-006";
}

pub mod feature_names {
    pub const CAPABILITY_INVOCATION_INTENSITY: &str = "capability_invocation_intensity";
    pub const RESOURCE_ENVELOPE_PRESSURE: &str = "resource_envelope_pressure";
    pub const NETWORK_SURFACE_AREA: &str = "network_surface_area";
    pub const FILESYSTEM_SURFACE_AREA: &str = "filesystem_surface_area";
    pub const DECLARED_PERMISSION_SURFACE: &str = "declared_permission_surface";
    pub const CODE_COMPLEXITY: &str = "code_complexity";
    pub const DEPENDENCY_SURFACE: &str = "dependency_surface";
}

pub const GENOME_DIMENSIONS: [&str; 7] = [
    feature_names::CAPABILITY_INVOCATION_INTENSITY,
    feature_names::RESOURCE_ENVELOPE_PRESSURE,
    feature_names::NETWORK_SURFACE_AREA,
    feature_names::FILESYSTEM_SURFACE_AREA,
    feature_names::DECLARED_PERMISSION_SURFACE,
    feature_names::CODE_COMPLEXITY,
    feature_names::DEPENDENCY_SURFACE,
];

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum PhenotypeExtractionError {
    #[error("package name must not be empty")]
    EmptyPackageName,
    #[error("version must not be empty")]
    EmptyVersion,
    #[error("at least one version is required for batch extraction")]
    EmptyBatch,
    #[error("batch contains {len} versions, exceeding max {max}")]
    BatchTooLarge { len: usize, max: usize },
    #[error("duplicate package/version pair: {package_name}@{version}")]
    DuplicateVersion {
        package_name: String,
        version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    RuntimeEvidence,
    ManifestMetadata,
    CodeMetadata,
    Derived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyCode {
    SourceMissing,
    FieldMissing,
    PartialEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UncertaintyAnnotation {
    pub code: UncertaintyCode,
    pub source: EvidenceSource,
    pub detail: String,
}

impl UncertaintyAnnotation {
    fn source_missing(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self {
            code: UncertaintyCode::SourceMissing,
            source,
            detail: detail.into(),
        }
    }

    fn field_missing(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self {
            code: UncertaintyCode::FieldMissing,
            source,
            detail: detail.into(),
        }
    }

    fn partial(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self {
            code: UncertaintyCode::PartialEvidence,
            source,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ExtractedFeature {
    Known {
        value: f64,
    },
    Partial {
        value: f64,
        uncertainty: UncertaintyAnnotation,
    },
    Unknown {
        uncertainty: UncertaintyAnnotation,
    },
}

impl ExtractedFeature {
    pub fn value(&self) -> Option<f64> {
        match self {
            Self::Known { value } | Self::Partial { value, .. } => Some(*value),
            Self::Unknown { .. } => None,
        }
    }

    pub fn uncertainty(&self) -> Option<&UncertaintyAnnotation> {
        match self {
            Self::Known { .. } => None,
            Self::Partial { uncertainty, .. } | Self::Unknown { uncertainty } => Some(uncertainty),
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub feature: String,
    pub source: EvidenceSource,
    pub extraction_method: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhenotypeExtractionEvent {
    pub event_code: String,
    pub package_name: String,
    pub version: String,
    pub detail: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyDeclaration {
    pub name: String,
    pub version_requirement: Option<String>,
    pub direct: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RuntimeEvidence {
    pub capability_invocations: Option<BTreeMap<String, u64>>,
    pub cpu_time_ms: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub network_accesses: Option<BTreeMap<String, u64>>,
    pub network_egress_bytes: Option<u64>,
    pub filesystem_read_ops: Option<u64>,
    pub filesystem_write_ops: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManifestEvidence {
    pub declared_permissions: Option<Vec<String>>,
    pub dependency_declarations: Option<Vec<DependencyDeclaration>>,
    pub api_surface_declarations: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CodeMetadata {
    pub cyclomatic_complexity: Option<u64>,
    pub binary_size_bytes: Option<u64>,
    pub exported_symbol_count: Option<u64>,
    pub dependency_tree_depth: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionEvidence {
    pub package_name: String,
    pub version: String,
    pub runtime: Option<RuntimeEvidence>,
    pub manifest: Option<ManifestEvidence>,
    pub code: Option<CodeMetadata>,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhenotypeFeatureVector {
    pub schema_version: String,
    pub package_name: String,
    pub version: String,
    pub features: BTreeMap<String, ExtractedFeature>,
    pub provenance: BTreeMap<String, ProvenanceRecord>,
    pub events: Vec<PhenotypeExtractionEvent>,
}

impl PhenotypeFeatureVector {
    pub fn known_feature_values(&self) -> BTreeMap<String, f64> {
        self.features
            .iter()
            .filter_map(|(name, feature)| feature.value().map(|value| (name.clone(), value)))
            .collect()
    }

    pub fn uncertainty_annotations(&self) -> BTreeMap<String, UncertaintyAnnotation> {
        self.features
            .iter()
            .filter_map(|(name, feature)| {
                feature
                    .uncertainty()
                    .map(|uncertainty| (name.clone(), uncertainty.clone()))
            })
            .collect()
    }

    pub fn to_drift_sample(&self, ts: i64) -> PhenotypeSample {
        PhenotypeSample::new(ts, self.known_feature_values())
    }
}

#[derive(Debug, Clone)]
pub struct PhenotypeExtractor {
    max_batch_versions: usize,
    audit_log: Vec<PhenotypeExtractionEvent>,
}

impl Default for PhenotypeExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PhenotypeExtractor {
    pub fn new() -> Self {
        Self {
            max_batch_versions: DEFAULT_MAX_BATCH_VERSIONS,
            audit_log: Vec::new(),
        }
    }

    pub fn with_max_batch_versions(max_batch_versions: usize) -> Self {
        Self {
            max_batch_versions,
            audit_log: Vec::new(),
        }
    }

    pub fn audit_log(&self) -> &[PhenotypeExtractionEvent] {
        &self.audit_log
    }

    pub fn extract_version(
        &mut self,
        evidence: &VersionEvidence,
    ) -> Result<PhenotypeFeatureVector, PhenotypeExtractionError> {
        validate_version_identity(evidence)?;

        let mut events = Vec::new();
        let mut features = BTreeMap::new();
        let mut provenance = BTreeMap::new();

        events.push(self.record_event(
            event_codes::BPET_EXTRACT_INPUT_ACCEPTED,
            evidence,
            "version evidence accepted",
        ));

        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::CAPABILITY_INVOCATION_INTENSITY,
                feature: extract_capability_invocation_intensity(evidence.runtime.as_ref()),
                source: EvidenceSource::RuntimeEvidence,
                method: "sum capability invocations and unique capability names",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::RESOURCE_ENVELOPE_PRESSURE,
                feature: extract_resource_envelope_pressure(evidence.runtime.as_ref()),
                source: EvidenceSource::RuntimeEvidence,
                method: "normalize cpu time and peak memory envelope",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::NETWORK_SURFACE_AREA,
                feature: extract_network_surface_area(evidence.runtime.as_ref()),
                source: EvidenceSource::RuntimeEvidence,
                method: "normalize network destination and egress envelope",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::FILESYSTEM_SURFACE_AREA,
                feature: extract_filesystem_surface_area(evidence.runtime.as_ref()),
                source: EvidenceSource::RuntimeEvidence,
                method: "normalize filesystem read and write operation envelope",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::DECLARED_PERMISSION_SURFACE,
                feature: extract_declared_permission_surface(evidence.manifest.as_ref()),
                source: EvidenceSource::ManifestMetadata,
                method: "count declared permissions and public api declarations",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::CODE_COMPLEXITY,
                feature: extract_code_complexity(evidence.code.as_ref()),
                source: EvidenceSource::CodeMetadata,
                method: "normalize cyclomatic complexity, binary size, and exported symbols",
            },
        );
        insert_feature(
            &mut features,
            &mut provenance,
            &mut events,
            self,
            evidence,
            FeatureExtraction {
                name: feature_names::DEPENDENCY_SURFACE,
                feature: extract_dependency_surface(
                    evidence.manifest.as_ref(),
                    evidence.code.as_ref(),
                ),
                source: EvidenceSource::Derived,
                method: "combine manifest dependency declarations and code dependency depth",
            },
        );

        events.push(self.record_event(
            event_codes::BPET_EXTRACT_VECTOR_EMITTED,
            evidence,
            "phenotype vector emitted",
        ));

        Ok(PhenotypeFeatureVector {
            schema_version: PHENOTYPE_EXTRACTOR_SCHEMA_VERSION.to_string(),
            package_name: evidence.package_name.clone(),
            version: evidence.version.clone(),
            features,
            provenance,
            events,
        })
    }

    pub fn extract_batch(
        &mut self,
        versions: &[VersionEvidence],
    ) -> Result<Vec<PhenotypeFeatureVector>, PhenotypeExtractionError> {
        if versions.is_empty() {
            return Err(PhenotypeExtractionError::EmptyBatch);
        }
        if versions.len() > self.max_batch_versions {
            return Err(PhenotypeExtractionError::BatchTooLarge {
                len: versions.len(),
                max: self.max_batch_versions,
            });
        }

        let mut by_key = BTreeMap::new();
        let mut duplicate_key = None;
        for version in versions {
            validate_version_identity(version)?;
            let key = (version.package_name.as_str(), version.version.as_str());
            if by_key.contains_key(&key) {
                duplicate_key = Some(key);
                break;
            }
            by_key.insert(key, version);
        }
        if let Some((package_name, version)) = duplicate_key {
            return Err(PhenotypeExtractionError::DuplicateVersion {
                package_name: package_name.to_string(),
                version: version.to_string(),
            });
        }

        let mut vectors = Vec::with_capacity(by_key.len());
        for version in by_key.values() {
            vectors.push(self.extract_version(version)?);
        }

        if let Some(first) = versions.first() {
            self.record_event(
                event_codes::BPET_EXTRACT_BATCH_EMITTED,
                first,
                format!("batch emitted {} vectors", vectors.len()),
            );
        }

        Ok(vectors)
    }
}

struct FeatureExtraction {
    name: &'static str,
    feature: ExtractedFeature,
    source: EvidenceSource,
    method: &'static str,
}

fn insert_feature(
    features: &mut BTreeMap<String, ExtractedFeature>,
    provenance: &mut BTreeMap<String, ProvenanceRecord>,
    events: &mut Vec<PhenotypeExtractionEvent>,
    extractor: &mut PhenotypeExtractor,
    evidence: &VersionEvidence,
    extraction: FeatureExtraction,
) {
    let FeatureExtraction {
        name,
        feature,
        source,
        method,
    } = extraction;
    let confidence = match &feature {
        ExtractedFeature::Known { .. } => 1.0,
        ExtractedFeature::Partial { .. } => 0.6,
        ExtractedFeature::Unknown { .. } => 0.0,
    };
    let event_code = if feature.is_known() {
        event_codes::BPET_EXTRACT_FEATURE_KNOWN
    } else {
        event_codes::BPET_EXTRACT_FEATURE_UNCERTAIN
    };
    events.push(extractor.record_event(event_code, evidence, format!("feature {name}")));
    provenance.insert(
        name.to_string(),
        ProvenanceRecord {
            feature: name.to_string(),
            source,
            extraction_method: method.to_string(),
            confidence,
        },
    );
    features.insert(name.to_string(), feature);
}

fn validate_version_identity(evidence: &VersionEvidence) -> Result<(), PhenotypeExtractionError> {
    if evidence.package_name.trim().is_empty() {
        return Err(PhenotypeExtractionError::EmptyPackageName);
    }
    if evidence.version.trim().is_empty() {
        return Err(PhenotypeExtractionError::EmptyVersion);
    }
    Ok(())
}

impl PhenotypeExtractor {
    fn record_event(
        &mut self,
        event_code: &str,
        evidence: &VersionEvidence,
        detail: impl Into<String>,
    ) -> PhenotypeExtractionEvent {
        let event = PhenotypeExtractionEvent {
            event_code: event_code.to_string(),
            package_name: evidence.package_name.clone(),
            version: evidence.version.clone(),
            detail: detail.into(),
            trace_id: evidence.trace_id.clone(),
        };
        push_bounded(&mut self.audit_log, event.clone(), MAX_AUDIT_LOG_ENTRIES);
        event
    }
}

fn extract_capability_invocation_intensity(runtime: Option<&RuntimeEvidence>) -> ExtractedFeature {
    let Some(runtime) = runtime else {
        return unknown_runtime("runtime evidence missing for capability invocations");
    };
    let Some(invocations) = runtime.capability_invocations.as_ref() else {
        return unknown_runtime("capability invocation counts missing");
    };
    let unique = bounded_unique_map_len(invocations);
    let total = invocations
        .values()
        .copied()
        .fold(0_u64, u64::saturating_add);
    known_score(normalized(total, 10_000.0) * 0.70 + normalized(unique as u64, 128.0) * 0.30)
}

fn extract_resource_envelope_pressure(runtime: Option<&RuntimeEvidence>) -> ExtractedFeature {
    let Some(runtime) = runtime else {
        return unknown_runtime("runtime evidence missing for resource envelope");
    };
    partial_or_known(
        EvidenceSource::RuntimeEvidence,
        "cpu_time_ms or memory_peak_bytes missing",
        [
            runtime
                .cpu_time_ms
                .map(|value| normalized(value, 600_000.0)),
            runtime
                .memory_peak_bytes
                .map(|value| normalized(value, 1_073_741_824.0)),
        ],
    )
}

fn extract_network_surface_area(runtime: Option<&RuntimeEvidence>) -> ExtractedFeature {
    let Some(runtime) = runtime else {
        return unknown_runtime("runtime evidence missing for network surface");
    };
    let destinations = runtime
        .network_accesses
        .as_ref()
        .map(|accesses| normalized(bounded_unique_map_len(accesses) as u64, 128.0));
    let egress = runtime
        .network_egress_bytes
        .map(|bytes| normalized(bytes, 104_857_600.0));
    partial_or_known(
        EvidenceSource::RuntimeEvidence,
        "network destinations or egress bytes missing",
        [destinations, egress],
    )
}

fn extract_filesystem_surface_area(runtime: Option<&RuntimeEvidence>) -> ExtractedFeature {
    let Some(runtime) = runtime else {
        return unknown_runtime("runtime evidence missing for filesystem surface");
    };
    partial_or_known(
        EvidenceSource::RuntimeEvidence,
        "filesystem read or write operation counts missing",
        [
            runtime
                .filesystem_read_ops
                .map(|reads| normalized(reads, 50_000.0)),
            runtime
                .filesystem_write_ops
                .map(|writes| normalized(writes, 50_000.0)),
        ],
    )
}

fn extract_declared_permission_surface(manifest: Option<&ManifestEvidence>) -> ExtractedFeature {
    let Some(manifest) = manifest else {
        return unknown_manifest("manifest evidence missing for declared permissions");
    };
    let permissions = manifest
        .declared_permissions
        .as_ref()
        .map(|items| normalized(canonical_string_count(items) as u64, 128.0));
    let api_surface = manifest
        .api_surface_declarations
        .as_ref()
        .map(|items| normalized(canonical_string_count(items) as u64, 256.0));
    partial_or_known(
        EvidenceSource::ManifestMetadata,
        "declared permissions or api surface declarations missing",
        [permissions, api_surface],
    )
}

fn extract_code_complexity(code: Option<&CodeMetadata>) -> ExtractedFeature {
    let Some(code) = code else {
        return unknown_code("code metadata missing for complexity");
    };
    partial_or_known(
        EvidenceSource::CodeMetadata,
        "cyclomatic complexity, binary size, or exported symbols missing",
        [
            code.cyclomatic_complexity
                .map(|value| normalized(value, 2_000.0)),
            code.binary_size_bytes
                .map(|value| normalized(value, 104_857_600.0)),
            code.exported_symbol_count
                .map(|value| normalized(value, 10_000.0)),
        ],
    )
}

fn extract_dependency_surface(
    manifest: Option<&ManifestEvidence>,
    code: Option<&CodeMetadata>,
) -> ExtractedFeature {
    let dependency_count = manifest
        .and_then(|manifest| manifest.dependency_declarations.as_ref())
        .map(|deps| normalized(canonical_dependency_count(deps) as u64, 512.0));
    let tree_depth = code
        .and_then(|code| code.dependency_tree_depth)
        .map(|depth| normalized(depth, 64.0));

    partial_or_known(
        EvidenceSource::Derived,
        "manifest dependency declarations or dependency tree depth missing",
        [dependency_count, tree_depth],
    )
}

fn unknown_runtime(detail: &str) -> ExtractedFeature {
    ExtractedFeature::Unknown {
        uncertainty: UncertaintyAnnotation::source_missing(
            EvidenceSource::RuntimeEvidence,
            detail.to_string(),
        ),
    }
}

fn unknown_manifest(detail: &str) -> ExtractedFeature {
    ExtractedFeature::Unknown {
        uncertainty: UncertaintyAnnotation::source_missing(
            EvidenceSource::ManifestMetadata,
            detail.to_string(),
        ),
    }
}

fn unknown_code(detail: &str) -> ExtractedFeature {
    ExtractedFeature::Unknown {
        uncertainty: UncertaintyAnnotation::source_missing(
            EvidenceSource::CodeMetadata,
            detail.to_string(),
        ),
    }
}

fn partial_or_known<const N: usize>(
    source: EvidenceSource,
    detail: &str,
    values: [Option<f64>; N],
) -> ExtractedFeature {
    let present: Vec<f64> = values.into_iter().flatten().collect();
    if present.is_empty() {
        return ExtractedFeature::Unknown {
            uncertainty: UncertaintyAnnotation::field_missing(source, detail.to_string()),
        };
    }
    let value = present.iter().copied().sum::<f64>() / present.len() as f64;
    let value = clamp01(value);
    if present.len() == N {
        known_score(value)
    } else {
        ExtractedFeature::Partial {
            value,
            uncertainty: UncertaintyAnnotation::partial(source, detail.to_string()),
        }
    }
}

fn known_score(value: f64) -> ExtractedFeature {
    ExtractedFeature::Known {
        value: clamp01(value),
    }
}

fn normalized(value: u64, denominator: f64) -> f64 {
    clamp01(value as f64 / denominator)
}

fn clamp01(value: f64) -> f64 {
    if !value.is_finite() {
        return 1.0;
    }
    value.clamp(0.0, 1.0)
}

fn bounded_unique_map_len<T>(map: &BTreeMap<String, T>) -> usize {
    map.keys()
        .filter(|key| !key.trim().is_empty())
        .take(MAX_FIELDS)
        .count()
}

fn canonical_string_count(items: &[String]) -> usize {
    items
        .iter()
        .filter_map(|item| {
            let trimmed = item.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .take(MAX_FIELDS)
        .collect::<BTreeSet<_>>()
        .len()
}

fn canonical_dependency_count(items: &[DependencyDeclaration]) -> usize {
    items
        .iter()
        .filter_map(|item| {
            let name = item.name.trim();
            (!name.is_empty()).then(|| {
                (
                    name.to_string(),
                    item.version_requirement.clone().unwrap_or_default(),
                    item.direct,
                )
            })
        })
        .take(MAX_FIELDS)
        .collect::<BTreeSet<_>>()
        .len()
}
