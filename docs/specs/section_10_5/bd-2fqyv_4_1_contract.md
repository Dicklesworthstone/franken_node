# bd-2fqyv.4.1 Contract: Authoritative Incident Evidence Source

## Scope

This contract defines the authoritative input surface for
`franken-node incident bundle --id <incident_id>`.

It replaces the current live shortcut where
`crates/franken-node/src/main.rs` calls
`crates/franken-node/src/tools/replay_bundle.rs::fixture_incident_events(...)`
to fabricate plausible replay input. The contract specifies:

- where operator-facing incident evidence is loaded from
- what schema the evidence package must satisfy
- how the package is validated before bundle generation
- how the package is translated into deterministic replay-bundle inputs
- how fixture-only incident timelines stay separate from live evidence

This document is the source/bootstrap companion to:

- `docs/specs/section_10_5/bd-vll_contract.md`
- `docs/specs/section_10_8/bd-f2y_contract.md`
- `docs/policy/incident_bundle_retention.md`

## Authoritative Source Location

Default authoritative source path:

`<project-root>/.franken-node/state/incidents/<incident-id-slug>/evidence.v1.json`

`<incident-id-slug>` is the sanitized path form of the requested incident id:
non-alphanumeric characters collapse to `_`, and an all-punctuation id falls
back to `incident`.

Resolution rules:

1. `<project-root>` is the directory containing a project-local
   `franken_node.toml`.
2. A user-global config under `~/.config/franken-node/config.toml` is not a
   valid anchor for project-scoped incident evidence by itself.
3. An explicit `--evidence-path <path>` override wins when provided.
4. If no project-local config exists and no explicit override is provided, the
   operator-facing `incident bundle` command MUST fail closed instead of
   loading sample/demo data.

The incident evidence source is project-scoped forensic state, not a global
cache and not a test fixture.

## Incident Source Directory Layout

The per-incident root is:

`<project-root>/.franken-node/state/incidents/<incident-id-slug>/`

Required contents:

- `evidence.v1.json` — authoritative incident-evidence package

The package may reference upstream evidence sources via stable refs/URIs; it
does not require every supporting artifact to be inlined into the JSON file.
What matters for the live CLI is that the package is authoritative, explicit,
and validated before replay-bundle generation.

## Evidence Package Schema

The canonical source payload is `IncidentEvidencePackage` with:

- `schema_version: "franken-node/incident-evidence-source/v1"`
- `incident_id: String`
- `collected_at: String` (RFC 3339)
- `trace_id: String`
- `severity: IncidentSeverity` (`low`, `medium`, `high`, `critical`, `unknown`)
- `incident_type: String`
- `detector: String`
- `policy_version: String`
- `initial_state_snapshot: serde_json::Value`
- `events: Vec<IncidentEvidenceEvent>`
- `evidence_refs: Vec<String>`
- `metadata: IncidentEvidenceMetadata`

`IncidentEvidenceMetadata` required fields:

- `title: String`
- `affected_components: Vec<String>`
- `tags: Vec<String>`

`IncidentEvidenceEvent` required fields:

- `event_id: String`
- `timestamp: String` (RFC 3339)
- `event_type: EventType`
- `payload: serde_json::Value`
- `provenance_ref: String`

`IncidentEvidenceEvent` optional fields:

- `parent_event_id: Option<String>`
- `state_snapshot: Option<serde_json::Value>`
- `policy_version: Option<String>`

The evidence package is richer than `tools::replay_bundle::RawEvent`.
`RawEvent` remains the internal replay-bundle construction type; it is not the
authoritative persisted evidence format.

## Load Validation Rules

Loading `evidence.v1.json` for live bundle generation MUST reject the package if
any of the following hold:

- `schema_version` is unknown
- `incident_id` is empty or does not match the CLI-requested incident id
- `collected_at` is not RFC-3339
- `trace_id`, `incident_type`, `detector`, `policy_version`, or
  `metadata.title` is empty
- `events` is empty
- `evidence_refs` is empty
- any `evidence_ref` is absolute, escapes the incident root with `..`, or is
  otherwise not relative to the incident root
- `initial_state_snapshot` cannot be canonically encoded
- any `event_id` is empty or duplicated
- any `provenance_ref` is empty or not present in `evidence_refs`
- any `parent_event_id` references a missing event or self-references the
  current event
- any event payload or snapshot contains floating-point values that would break
  deterministic replay-bundle canonicalization
- any event timestamp fails RFC-3339 parsing
- any event-specific `policy_version` is present but empty

Successful validation establishes that the package is authoritative enough to
produce a replay bundle. Missing or malformed evidence is a hard error, not an
occasion to synthesize substitute events.

## Translation Contract Into Replay Bundles

Bundle generation from `IncidentEvidencePackage` MUST be deterministic:

1. Validate the package before any replay-bundle work starts.
2. Sort `events` by `(timestamp, event_id)` ascending.
3. Convert the sorted events into `tools::replay_bundle::RawEvent`.
4. Translate `parent_event_id` links into `causal_parent` indices in the
   sorted order.
5. Copy `initial_state_snapshot` onto the first replay event so the current
   replay-bundle implementation has an authoritative initial snapshot.
6. Copy the selected policy version onto the first replay event, using the
   first event-specific override in sorted order when present, otherwise the
   top-level `policy_version`.
7. Call `generate_replay_bundle(package.incident_id, &event_log)`.

The evidence package is authoritative; any representation quirks of `RawEvent`
or the current bundle generator are downstream implementation details. The
implementation bead may adapt internal replay-bundle plumbing, but it must not
weaken this source contract.

## Missing-Data Behavior

Operator-facing `franken-node incident bundle` behavior is binary:

- valid authoritative evidence package present -> bundle generation proceeds
- package missing, malformed, or incomplete -> command fails with a clear error

The command MUST NOT:

- fall back to `fixture_incident_events(...)`
- invent placeholder metadata or provenance
- silently skip invalid package validation failures

For this forensic surface, no bundle is better than a fabricated one.

## Fixture Boundary

`fixture_incident_events(...)` and fixture evidence packages remain allowed only
for deterministic tests and examples.

Fixture-only source rules:

- fixture evidence packages belong under explicit fixture locations or temporary
  test directories
- tests/examples must inject fixture packages explicitly
- the live CLI path must never consult fixture packages implicitly
- production code must not call `fixture_incident_events(...)` in the live
  incident-bundle path

The fixture boundary must be obvious in naming, module placement, and docs.

## Required Verification For Follow-On Implementation

Minimum coverage for implementation bead `bd-2fqyv.4.2`:

- live path fails when project-local config is absent
- live path fails when the authoritative evidence file is missing
- validation rejects malformed schema, empty `evidence_refs`, broken
  `provenance_ref` / `parent_event_id` links, invalid timestamps, and
  non-deterministic float payloads
- identical authoritative evidence-package input yields byte-identical replay bundles
- the operator-facing command no longer calls `fixture_incident_events(...)`
- tests/docs distinguish authoritative project state from fixture-only evidence
