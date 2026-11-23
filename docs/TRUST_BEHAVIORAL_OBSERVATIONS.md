# Signed behavioral observations and trust cards

`franken-node trust observe` admits a collector's signed measurements of one
package artifact into the project's durable trust registry. Once a stream has
enough comparable samples, it runs the existing BPET camouflage detector and
records the resulting findings on the package's signed trust card.

The collector is responsible for isolating the package and measuring it under
a repeatable workload. A signature authenticates that collector's statement;
it does not establish that the experiment was correct. Native `run` records
application-level effects and can attach a package inventory with candidate
callers. The engine does not supply an authenticated calling-module witness,
so those effects cannot be copied into an observation for each dependency.

## Native run package inventory

When native `run --json` has a captured package inventory,
`receipt.package_attribution` uses
`franken-node/package-attribution-report/v2`. The same report appears in
`dispatch.engine_decision.package_attribution`.

Package metadata comes exclusively from manifests retained in that source
graph. Frozen and publisher-capsule execution retain those names, versions,
manifest commitments, and module hashes even if installed manifests change
or the original source directory is unavailable. Ordinary non-frozen runs
use a best-effort graph inventory; that snapshot does not prove that live
sources remained unchanged during execution.

| Field | Meaning |
|---|---|
| `graph_input_hash` | Commitment to the captured graph inputs used for the inventory. |
| Package `package_name`, `package_version` | Strings from the captured manifest, or `null` for missing, blank, or non-string fields. No version such as `0.0.0` is invented. |
| Package `manifest_identity` | `{"status":"captured","relative_path":"…","sha256":"sha256:…"}` identifies retained manifest bytes. `{"status":"not_captured","relative_path":"…"}` records missing captured metadata. |
| Package `package_id` | Unique known identities retain `app:<name>@<version>` or `npm:<name>@<version>`. Distinct dependency installations sharing a nominal ID use `npm-instance:<relative-package-directory>`, preserving each installation's manifest and sources. Unknown identities use `app-path:root` or `npm-path:<relative-package-directory>`. These path IDs are local to the graph. |
| Package `loaded_modules` | Module IDs, origin paths, and source hashes retained by the graph. Manifest identity and module hashes describe sources; they do not identify an effect's caller. |
| Effect `seq`, `receipt_hash`, `effect_kind`, `outcome` | Link to the corresponding host-effect ledger entry and its actual policy outcome. |
| Effect `attribution_basis`, `candidate_packages` | New reports use `candidate_loaded_packages` with known package candidates. `attributed_package` is omitted because no exact caller has been established. |
| Effect `capability_importing_packages`, `target_package_hint` | Separate import/source hints and the known package containing a filesystem target. Empty hints are omitted. Imports do not prove capability ownership or exclude delegated callers, and targeting another package's file does not make that package the caller. |

The package fields `exact_effect_seqs`, `allowed_effects`, `denied_effects`,
and `failed_effects` count exactly attributed effects. New v2 reports leave
the sequence list empty and those counters at zero until a calling-module
witness is available. Those zeros do not establish absence of package
activity. Use each effect's `outcome` for the recorded policy result and
`candidate_effect_seqs` to follow a package's candidate links to that ledger.
`declared_effect_kinds` also contains import/source hints, not authority grants.

Historical v1 reports remain readable with their original fields and inference
labels preserved. Reading an old report does not add captured-manifest
provenance or strengthen its historical caller inference.

## Admit an observation

Run from the project directory that owns the trust registry:

```bash
franken-node trust card npm:@acme/auth-guard --json
franken-node trust observe observation.json \
  --collector-key /trusted/collectors/package-lab.pub --json
franken-node trust card npm:@acme/auth-guard --json
```

The registry must already contain a verified card for the exact package
version and artifact digest in the observation. `trust scan` can populate
cards from a project's package manifest and lockfile. An unresolved version,
a card without the artifact hash, or a mismatched version is insufficient.
Admission does not create a new identity or trust a digest supplied only by
the collector.

`--collector-key` supplies an independently trusted Ed25519 public key. The
existing key parser accepts raw 32-byte public keys, hexadecimal public keys,
and SSH Ed25519 public-key files. A fingerprint embedded in the observation
does not authorize a collector. Both input files must be regular files;
observation JSON is limited to 1 MiB and the key file to 4 KiB.

Success returns `franken-node/behavioral-ingestion/v1` JSON, including:

- `status`: `accepted` or `duplicate`.
- `observation_id`, `stream_id`, `collector_key_id`, and `workload_id`.
- The admitted `extension_id`, `package_version`, and `artifact_hash`.
- `sample_count` and the detector's `hints` with sample indices and evidence.
- The resulting `card_version`, `card_hash`, `risk_level`, and `evidence_ref`.

The report and journal preserve the detector's complete bounded findings. The
trust card stores the strongest findings that fit its smaller hint limit, in
a deterministic order, so a noisy observation stream does not exceed the
card mutation API's input bound.

A duplicate returns the original admission's card version and hash, which
can be older than the current card. Use `trust card` for current state.
Invalid input exits unsuccessfully; `--json` errors use the existing
`franken-node/trust-error-cli/v1` schema with `command: "trust.observe"`.

## Collector measurement contract

The public Rust types are in
`frankenengine_node::supply_chain::behavioral_observation`.

| Observation field | Meaning and admission rule |
|---|---|
| `extension_id` | Exact identity of an existing card, such as `npm:@acme/auth-guard`. |
| `package_version` | Exact semantic version, including optional prerelease/build identifiers. Ranges and tags are refused. |
| `artifact_hash` | A canonical lowercase `sha256:<64 hex>` or `sha512:<128 hex>` digest already bound to that version's card. |
| `workload_id` | Stable identifier for the collector's repeatable experiment. Changing the experiment requires a new ID. |
| `measurement_scope` | Must be `isolated_package`; the collector attests that the observations belong to this package artifact. |
| `sequence` | Starts at zero and advances by exactly one within a stream. |
| `observed_at_epoch_secs` | Measurement timestamp; it must increase strictly and be no more than 300 seconds ahead of the ingestion clock. |
| `window_duration_ms` | Positive measurement window, at most one day; fixed within a stream. |
| `workload_iterations` | Number of repeated workload executions, from 1 to 1,000,000; fixed within a stream. |
| `previous_observation_id` | `null` for sequence zero, then the immediately preceding observation's content ID. |
| `observed_capabilities` | Integer event counts actually measured, indexed by capability dimension. A zero means a measured zero. |
| `declared_capabilities` | Positive expected event counts for exactly the same dimensions and experiment. Fixed within a stream. |

There must be 1–32 dimensions, with bounded names and counts no greater than
1,000,000,000. Unknown dimensions cannot be filled with zero. Duplicate JSON
dimension keys, missing dimensions, fractional counts, negative counts,
unknown fields, and non-finite values are refused.

A stream is identified by the extension, collector-key fingerprint, and
workload ID. The package version and artifact may change as the package
evolves, but each newly admitted observation must match the current verified
card. Measurement scope, window duration, workload repetitions, capability
dimensions, and declared counts remain constant across that stream. A new
collector key starts a separate stream.

For detector input, both observed and declared counts are converted to events
per workload iteration. The detector starts after four comparable samples
and applies its existing phase-shift, dropout, distribution-mismatch, and
gradual-creep rules. Its scores are heuristic findings; they are not
calibrated probabilities that the package is malicious, and repeated samples
are not claimed to be statistically independent.

## Signing and verification

Collectors should use the public signing helper with their protected key and
measurements collected under the contract above:

```rust
use ed25519_dalek::{SigningKey, VerifyingKey};
use frankenengine_node::supply_chain::behavioral_observation::{
    BehavioralObservation, SignedBehavioralObservation,
};

fn encode_observation(
    measured: BehavioralObservation,
    collector_key: &SigningKey,
) -> anyhow::Result<Vec<u8>> {
    let envelope = SignedBehavioralObservation::sign(measured, collector_key)?;
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

fn verify_observation(
    encoded: &[u8],
    trusted_collector: &VerifyingKey,
    now_secs: u64,
) -> anyhow::Result<String> {
    let envelope: SignedBehavioralObservation = serde_json::from_slice(encoded)?;
    envelope.verify(trusted_collector, now_secs)?;
    envelope.observation_id()
}
```

Standalone verification authenticates the envelope and its field constraints.
Registry admission additionally checks the artifact, stream continuity,
retained history, and the resulting trust-card transaction.

The envelope contains `schema_version`, `observation`, `collector_key_id`,
and `signature`. The schema is `franken-node/behavioral-observation/v1`.
The collector fingerprint is `ed25519:` followed by the lowercase SHA-256
digest of the raw public key. The signature is 64 bytes encoded as 128
lowercase hexadecimal characters.

For implementations in other languages, the signing preimage is the compact
typed JSON object containing, in order, `schema_version`, `observation`, and
`collector_key_id`. Observation field order is the order in the table above.
Capability maps sort keys lexicographically. The optional predecessor is
explicitly `null` for the first observation. Rust's `serde_json` string and
integer encoding defines the canonical bytes. The signature itself is absent.
Ed25519 signs this byte sequence with the following domain prefix prepended,
including the final NUL byte:

```text
franken-node/behavioral-observation-signature/v1\0
```

The observation ID is `sha256:` plus the lowercase SHA-256 digest of the
same preimage with the distinct prefix
`franken-node/behavioral-observation-id/v1\0`. Reformatting transport JSON
does not create a different observation. Signing the ID text instead of the
domain-prefixed preimage is incompatible.

## Durable behavior and risk decisions

Accepted envelopes and their reports live in the existing trust registry's
frankensqlite store. The observation journal, updated card, registry snapshot,
and signed high-water state commit in one transaction. A conflicting writer
fails and can retry the original command against the new head; it does not
overwrite another accepted measurement.

The registry snapshot retains authenticated stream-head commitments beyond
bounded card/audit history. Removing or rolling back a journal alone cannot
make its signed first observation new again. Empty historical snapshots keep
their previous encoding and hashes. This preserves the registry's existing
trust model; it does not provide an external witness against replacement of
the entire store with an older coherent copy.

Each stream admits at most 1,024 observations within a 16 MiB journal, and the
registry retains at most 4,096 stream identities. Capacity exhaustion fails
explicitly. Starting
a new workload epoch is an operator decision that also starts a new detector
history; it is not an automatic way to forget risk already recorded on a card.

Every accepted observation adds verification evidence to a new signed card
version, including before the detector has enough samples. Findings flow
through the existing camouflage assessment and can raise card risk. Admission
preserves revocation and quarantine state, and does not automatically
quarantine a package. Clean OSV refreshes preserve behavioral risk floors;
an answer about known vulnerabilities does not clear behavioral findings.
Because historical cards do not attribute every component of a risk rating
separately and hint history is bounded, a High/Critical card with retained
findings conservatively keeps its current rating during refreshes. This can
also retain a rating raised by another source. Automatic source-specific risk
remediation is not implemented by this command.

This command supplies the missing ingestion path for collector-attributed
measurements. It does not implement automatic per-dependency native
collection, fleet enforcement of these observations, or the separate BPET
migration admission gate.

## Assess observed history and dependency exposure

Run `franken-node trust graph --immunize --json` to combine the current trust
graph with the registry's admitted observation history. The immunization
section uses `franken-node/trust-graph-immunization/v2`.

The assessment authenticates the supplied registry snapshot and its durable
counterpart, validates each retained journal's admission MAC and stream-head
commitment, and reruns the detector on that stream's actual measurements.
Each collector/workload stream remains separate. Reading history authenticates
the registry's prior admission; it does not independently retrieve or
reauthorize the external collector key. Missing, rolled-back, or modified
journals and changed registry trust state cause an error.

Coverage distinguishes packages with no admitted observations, streams with
fewer than four comparable samples, and detector-ready streams. A clean
detector-ready stream can report zero severity; absent or insufficient
measurements cannot. The latest observation's version and artifact digest
must match the current verified card before that stream contributes behavioral
severity to current-artifact prioritization. A matching final observation
does not mean the entire trajectory came from that artifact: a stream may
include earlier versions under the same measurement contract. Historical
streams remain visible in the report.

Assessment reads are bounded to 64 MiB of journal data and 65,536 samples,
in addition to the existing per-stream limits. Exceeding a bound fails
explicitly instead of returning a partial assessment.

The trust graph and `trust-card reputation` consume the same bounded dependency
capture as runtime trust admission. Under the repository's npm <=11 contract,
`npm-shrinkwrap.json` takes precedence over `package-lock.json`; a malformed
selected file is an error, and a losing package-lock is not parsed. On Linux,
Bun text locks use the existing v1/v2 registry/workspace/catalog projection.
Mixed npm/Bun authorities and binary `bun.lockb` inputs require an explicit
project selection instead of silently falling back to incomplete metadata.

The projection resolves npm aliases to actual package identities, retains
transitive requirements and workspace links, and includes present peers and
optional dependencies. Absent optional requirements remain visible in coverage
without inventing installed package nodes. Required unresolved requirements,
workspace intent without a selected installation, incomplete legacy dependency
kinds, and unnamed packages prevent a complete-topology claim.

JSON reports include `dependency_capture`
(`franken-node/trust-dependency-capture/v1`). Its `source_graph_hash` and
`topology_hash` identify the semantic capture; `lockfile_source.path` and
`lockfile_source.sha256` identify the exact selected raw lockfile.
`placements` preserves each observed location, actual package name, version,
integrity and workspace-link target. `coverage` reports missing metadata
explicitly. These observations do not authenticate installed source bytes,
prove live JavaScript resolution, or authorize a runtime effect.

The dependency graph retains untracked packages, including bridges between
packages with trust cards. Known downstream trust ceilings propagate through
those bridges without assigning untracked packages an invented score.
Topology measurements count distinct dependency edges and transitive
dependents, compute directed shortest-path betweenness, and identify
articulation points in the undirected package graph. Publisher relations do
not contribute to those package metrics. The graph remains name-based:
installed versions or locations sharing a package name are merged.

Exact topology analysis is limited to 1,024 package nodes and 8,000,000
estimated work units. Missing topology, truncated input, exceeded analysis
budgets, and incomplete captured dependency metadata produce an explicit
unavailable status rather than measured zeros.
Invalid JSON and unsupported lockfile shapes are rejected. The planner ranks candidates by
estimated impact before applying its 18-node analysis limit, so alphabetical
ordering cannot discard a more consequential candidate.

Risk surfaces describe the current graph. The report does not invent
maintainer activity, proposed package updates, or post-update risk reductions.
Its trust-derived risk values, loss scenario, and candidate priorities are
documented model assumptions, not calibrated compromise probabilities or
measured financial loss. No quarantine, dependency update, migration gate, or
barrier enforcement is performed by this assessment command.
