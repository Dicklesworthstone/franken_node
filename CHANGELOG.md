# Changelog

All notable changes to franken_node are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-vector test data has its own log in [`vectors/CHANGELOG.md`](vectors/CHANGELOG.md).

## [Unreleased]

### Security
- Hardened atomic-write paths to fsync the containing directory after rename
  (`security/decision_receipt`, `control_plane/fleet_transport`).
- Bounded `AuthFailureLimiter` source-IP cardinality to defeat memory-DoS via
  unbounded source tracking.
- Added timestamp monotonicity validation in decision-receipt construction.
- Added `is_finite` guards to f64 equality assertions used in security tests.

### Added
- Fleet-decision contract conformance harness.
- Security challenge–response protocol conformance harness.
- Migration protocol conformance harness.
- Supply-chain attestation manifest golden test.
- VEF execution-receipt binary-format golden test.
- Authentication-failure visibility surface for incident response.

### Changed
- Replaced fleet-quarantine mock transport with real file-based persistence
  (`FileFleetTransport`).
- Replaced replay-bundle in-memory fixtures with real file-I/O roundtrips in
  end-to-end tests.
- Replaced mocks with real dependencies in trust/OSV integration tests.
- Switched `BTreeMap` control-lane assignment storage to a fixed-size array for
  predictable allocation and cache behavior (bd-17nu4).
- Hardened report generation against `chrono::Duration` conversion failure.

### Fixed
- Preserved `TempDir` lifetime across the fleet-quarantine test scope to avoid
  premature cleanup.
- Corrected JSON syntax in the decision-receipt golden fixture.
- Improved `usize → u64` conversion in VEF schema-conformance tests.

### Fuzzing
- Expanded `NetworkAllowlistEntry` TOML parsing fuzz coverage.
- Removed tautological `u64` assertions from the evidence-ledger fuzz harness.

[Unreleased]: https://github.com/anthropics/franken_node/compare/HEAD
