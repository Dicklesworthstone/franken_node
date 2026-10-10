# Signed behavioral observations and trust cards

`franken-node trust observe` admits a collector's signed measurements of one
package artifact into the project's durable trust registry. Once a stream has
enough comparable samples, it runs the existing BPET camouflage detector and
records the resulting findings on the package's signed trust card.

The collector is responsible for isolating the package and measuring it under
a repeatable workload. A signature authenticates that collector's statement;
it does not establish that the experiment was correct. Native `run` currently
records application-level effects without package-origin attribution. Those
effects cannot be copied into an observation for each dependency.

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
