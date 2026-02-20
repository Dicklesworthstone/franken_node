# bd-phf: Ecosystem Telemetry for Trust and Adoption Metrics

## Bead: bd-phf | Section: 10.4

## Purpose

Provides the quantitative feedback loop that drives reputation scoring,
certification decisions, policy tuning, and program success measurement.
Implements privacy-respecting aggregation, anomaly detection, and time-series
retention for ecosystem-level trust and adoption signals.

## Invariants

| ID | Statement |
|----|-----------|
| INV-TEL-OPT-IN | Telemetry collection is disabled by default and requires explicit opt-in. |
| INV-TEL-PRIVACY | All published metrics satisfy k-anonymity (min_aggregation_k >= 5). |
| INV-TEL-RETENTION | Time-series data respects retention policy: raw <= 7d, hourly <= 30d, daily <= 365d, weekly indefinite. |
| INV-TEL-ANOMALY | Anomaly detection activates only after minimum data points threshold and triggers on deviation above configured percentage. |
| INV-TEL-BUDGET | Resource budget enforces max in-memory points with eviction of raw data when exceeded. |
| INV-TEL-QUERY | Query filtering supports metric kind, time range, aggregation level, label dimensions, and result limiting. |
| INV-TEL-EXPORT | Ecosystem health export surfaces compatibility pass rate, migration velocity, provenance coverage, and active alerts. |
| INV-TEL-GOVERNANCE | Data governance configuration controls collected and published categories independently. |

## Metric Families

### Trust Metrics

| Metric | Description |
|--------|-------------|
| CertificationDistribution | Distribution of extensions across certification levels. |
| RevocationPropagationLatency | Time from revocation issue to fleet-wide propagation. |
| QuarantineResolutionTime | Time from quarantine to resolution (cleared or confirmed). |
| ProvenanceCoverageRate | Fraction of extensions with verified provenance chains. |
| ReputationDistribution | Distribution of publisher reputation scores. |

### Adoption Metrics

| Metric | Description |
|--------|-------------|
| ExtensionsPublished | Extensions published per time period. |
| ProvenanceLevelAdoption | Extensions using each provenance level. |
| TrustCardQueryVolume | Trust-card query volume by operators. |
| PolicyOverrideFrequency | Frequency of policy override usage. |
| QuarantineActionsPerPeriod | Operator-initiated quarantine actions per period. |

## Anomaly Types

| Type | Trigger |
|------|---------|
| ProvenanceCoverageDrop | Sudden drop in provenance coverage rate. |
| QuarantineSpike | Spike in quarantine events beyond threshold. |
| ReputationDistributionShift | Significant shift in reputation score distribution. |
| RevocationPropagationDelay | Unusual revocation propagation delay. |
| PublicationVolumeAnomaly | Abnormal extension publication volume (possible supply-chain attack). |

## Event Codes

| Code | When Emitted |
|------|--------------|
| TELEMETRY_INGESTED | Data point accepted into pipeline. |
| TELEMETRY_AGGREGATED | Aggregation cycle completed. |
| TELEMETRY_QUERY_SERVED | Query executed and results returned. |
| TELEMETRY_ANOMALY_DETECTED | Anomaly alert generated. |
| TELEMETRY_EXPORT_GENERATED | Health export produced. |
| TELEMETRY_PRIVACY_FILTER_APPLIED | Privacy filtering applied to query results. |

## Dependencies

- Upstream: bd-ml1 (publisher reputation), bd-273 (certification levels)
- Downstream: bd-261k (section gate), bd-1xg (plan tracker)
