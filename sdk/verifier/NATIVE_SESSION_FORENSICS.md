# Portable native-session forensics

`native-session-forensics` verifies the original product-root-signed admission
and any retained supervisor outcome without the product workspace, engine,
identity capture files, local inventory database, or source tree. It supports
pending admissions, interrupted workers, retained panic evidence, and the other
typed supervisor outcomes. It uses the public product root supplied by the
auditor; an identity inside the export cannot choose its own trust anchor.

```sh
franken-verifier verify --format native-session-forensics \
  --trusted-key-hex "$TRUSTED_PRODUCT_ROOT_PUBLIC_KEY_HEX" \
  < INC-SESSION-UUID.fnforensics.json
```

The export is read from standard input. The existing CLI verdict, artifact
SHA-256, and exit-code conventions apply. Detached signatures,
`--trusted-run-key-hex`, and `--trusted-runtime-key-hex` are not options for this
format: its original signatures are embedded and both use the supplied product
root. The library entry point is
`native_session::verify_native_session_forensics(bytes, trusted_root)`.

## Requiring the intended session

One product root can sign many runs. To require evidence for a specific
admission, retain its session nonce and admission commitment independently
when that run is admitted, then supply both values:

```sh
franken-verifier verify --format native-session-forensics \
  --trusted-key-hex "$TRUSTED_PRODUCT_ROOT_PUBLIC_KEY_HEX" \
  --expected-session-nonce "$EXPECTED_SESSION_NONCE" \
  --expected-admission-sha256 "$EXPECTED_ADMISSION_SHA256" \
  < INC-SESSION-UUID.fnforensics.json
```

The nonce must be a nonzero, lowercase UUID. The commitment is the receipt's
`admission_sha256`: exactly 64 lowercase hexadecimal characters, without a
`sha256:` prefix. It commits to the domain-separated, length-framed admission
described below, including its project, entrypoint, epoch and authority. It is
**not** the plain SHA-256 of the admission JSON or the exported file. Copying
these expected values from the candidate export does not establish an
independent expectation.

The verifier authenticates the complete evidence before comparing its identity.
An otherwise valid export from another admission fails with
`EXPECTED_NATIVE_IDENTITY_MISMATCH`. Missing one of the two options, malformed
values, or using these options with another format fails with
`EXPECTED_NATIVE_IDENTITY_INVALID`. Omitting both preserves unrestricted
verification under the supplied product root.

Rust callers use `NativeSessionExpectedIdentity` and
`native_session::verify_native_session_forensics_with_expected_identity`.
Python's `verify_artifact` accepts `expected_session_nonce` and
`expected_admission_sha256`; JavaScript and TypeScript's `verifyArtifact`
accept `expectedSessionNonce` and `expectedAdmissionSha256`. The language
bindings also compare the returned identity with the caller's expectation.

These pins apply to v1, v2 and v3 exports, including pending admissions and
interrupted or panicked outcomes. They identify the requested admission;
they do not establish that its retained outcome is the newest one. Replay,
quiescence and historical-completeness claims remain unchanged.

## What a successful result means

The verification scope is `authenticated_supervisor_observations`. The result
reports the authenticated session, project, entrypoint, security epoch, outcome
kind, and observed process/effect state. Provider-call counts are present only
when the signed observation supplies a WAL or explicitly observes no admitted
effects. Counts remain `null` for pending, unknown, and final-ledger-only
observations. Final ledger counts and journal completeness have their own
nullable fields.

All results explicitly retain these limits:

- `replay_certified: false`: no guest execution or native replay occurs.
- `quiescence_certified: false`: worker reap, containment observations, and
  provider return markers do not certify completed external effects or fleet
  quiescence.
- `historical_completeness: false`: the export does not establish that it is the
  newest observation, that all sessions were exported, or that an omitted
  outcome does not exist elsewhere.

A valid admission with `outcome: null` reports `outcome_kind: "pending"`. It
does not become successful because a PID vanished, the source files are absent,
or time passed. A validated panic WAL authenticates provider return markers;
it is not a finalized engine ledger. The CLI summary and `Debug` implementations
do not echo panic text, raw WAL entries, or dependency inventory. The export
itself intentionally contains the original evidence and can contain private
paths and diagnostic text.

## Transport and unchanged signatures

The v1 envelope has exactly four fields:

```json
{
  "schema_version": "franken-node/native-session-forensics/v1",
  "admission_json": "<original admission JSON>",
  "admission_receipt": {
    "schema_version": "franken-node/native-session-admission-receipt/v1",
    "session_nonce": "<session UUID>",
    "product_root_key_id": "ed25519:<trusted public key hex>",
    "admission_sha256": "<lowercase SHA-256 hex>",
    "signature_hex": "<original signature hex>"
  },
  "outcome": null
}
```

For a retained outcome, `outcome` is instead an object with `payload_json` and
`signature_hex`. The payload string contains the original ordered signing
object with fields `schema_version`, `session_nonce`, `product_root_key_id`,
`admission_sha256`, and `outcome`; the original signature is carried unchanged.
The payload does not include a signature field, domain prefix, or byte length.

The verifier reproduces the existing receipt protocols. Each frame consists
of the domain bytes below, a big-endian unsigned 64-bit payload byte length,
and the exact payload bytes. The notation `\0` means one zero byte.

| Check | Domain | Payload |
| --- | --- | --- |
| Admission SHA-256 | `franken-node/native-session-admission/v1\0` | Exact UTF-8 `admission_json` bytes |
| Admission Ed25519 signature | `franken-node/native-session-admission-signature/v1\0` | Ordered receipt fields: schema, nonce, product root ID, admission SHA-256 |
| Outcome Ed25519 signature | `franken-node/native-session-outcome-signature/v1\0` | Exact UTF-8 `outcome.payload_json` bytes |

The admission and outcome must name the same session, root, and admission
commitment. The outcome is parsed as the existing typed supervisor observation;
valid signatures cannot excuse impossible state combinations, bad counts,
invalid commitments, noncontiguous WAL sequences, mixed session identities,
unsupported terminal states, or a missing spawn-authority observation needed
to justify a no-effects panic.

## Durable provider admission journal (v2)

An export carrying a retained effect journal uses schema
`franken-node/native-session-forensics/v2` and adds `journal_jsonl`, a string
containing the original newline-delimited signed records. V2 requires that
field; v1 refuses an attached journal. The original admission and outcome
signature protocols remain unchanged. Historical v1 exports remain supported.

`verify_native_session_effect_journal(bytes, trusted_root, expected_nonce,
admission_sha256)` verifies this journal independently. The containing forensic
verifier obtains the expected nonce and admission digest from the authenticated
admission receipt. It returns a separate `durable_journal` summary: record and
event counts, admitted and returned provider calls, the unmatched admission
count, the final retained record commitment, and a `trailing_partial_record`
flag. Existing outcome metadata continues to describe the retained outcome.
In particular, a signed journal with no outcome leaves the session `pending`
and the outcome-derived provider counts `null`.

Each JSONL record has only `payload_json` and `signature_hex`. The payload is
the exact signed JSON object containing, in producer order:

```text
schema_version, session_nonce, product_root_key_id, admission_sha256,
event_index, previous_record_sha256, event
```

The record schema is `franken-node/native-effect-journal-record/v1`. The first
record has index zero, a previous commitment of 64 zeroes, and a `header` event
declaring scope `host_io_provider_calls`, event cap 2,048 and byte cap 4,194,304.
Subsequent `admitted` events carry a contiguous provider-call sequence, effect
kind and request commitment; `provider_returned` must match the one pending
admission before another call can be admitted. A provider call reserves both
events, permitting at most 1,024 admitted calls.

Each payload signature uses domain
`franken-node/native-effect-journal-signature/v1\0`, the big-endian u64 payload
byte length, and the original payload bytes. Each chain commitment is SHA-256
of domain `franken-node/native-effect-journal-record/v1\0`, the big-endian u64
record byte length, and the exact JSONL record bytes **excluding its newline**.
Reordering, omission within the retained chain, changed envelope spelling, or
mixed session/admission bindings fails verification.

A final non-newline suffix can be a torn append. The verifier ignores that
suffix only after authenticating a complete signed header and every preceding
record, and reports `trailing_partial_record: true`. It rejects every malformed
or invalidly signed newline-terminated record. A valid older prefix remains
valid retained evidence; neither its last newline nor a matching chain proves
that no newer records exist.

When an export also contains a signed panic WAL or a complete interrupted WAL,
the durable prefix must agree with that outcome's request identities and
provider-return observations. A no-effects or unspawned outcome cannot carry
durable admissions. An incomplete response drain can end before a journal
append finishes: incomplete or unknown outcomes therefore allow a longer or
more advanced durable prefix, while overlapping request identities must still
agree. These observations remain separately reported.

The journal describes supported host-I/O provider crossings. An admission can
survive cancellation before the provider starts; it is conservatively
indeterminate. A provider return does not certify an external transaction's
completion. Process-spawn operations, direct environment snapshot reads,
guest execution history, and worker cleanup are outside this journal's scope.
Replay certification, quiescence certification and historical completeness
remain false, including for an empty signed header or an all-returned prefix.

## Sources retained before guest entry (v3)

Frozen and publisher-capsule native launches retain the existing `FNSGCAP1`
source capsule before the supervisor starts the worker. The private,
content-addressed copy is immutable and its identity is included in the
original signed admission as `source_capsule`:

```json
{
  "capsule_digest": "sha256:<domain-separated capsule digest>",
  "graph_input_hash": "sha256:<captured graph commitment>",
  "capsule_bytes": 1234
}
```

The digest is SHA-256 over `franken-node/module-source-capsule/v1\0`, the
unsigned 64-bit **little-endian** capsule length, and the exact capsule bytes.
The admission receipt authenticates this binding using its existing protocol.
Historical admissions omit the field and keep their original signature bytes.

The producer reuses identical private source objects and bounds retained sources
to 256 MiB per protected state root. Partial and orphaned objects still count.
It refuses a new launch when retention is full or conflicting; it never repairs
damaged evidence by overwriting it or silently recapturing the current project.

An export of such an admission uses
`franken-node/native-session-forensics/v3` and includes the required
`source_capsule_base64` field. It may also carry `journal_jsonl` and a retained
outcome, but neither is required: a worker can die before it emits either.
The offline verifier authenticates the original admission, checks the capsule
length and digest, and verifies the capsule's canonical header, path bounds,
conditions, retained file/link digests and payload accounting. The header's
graph commitment and project-relative entrypoint must match the admission.
It never opens the original source tree or extracts or executes these bytes.

The result adds `source_capsule`, a source-free summary of byte and input
counts and the authenticated graph commitment. `graph_hash_recomputed` remains
`false`: the SDK checks retained byte integrity and the signed graph identity;
it does not independently reconstruct module-resolution semantics. The
existing replay, quiescence and historical-completeness flags remain false.
Missing, substituted, truncated or inconsistent retained sources are errors,
including when an exporter tries to strip them and downgrade to v1 or v2.
Source data and base64 are redacted from diagnostic and `Debug` output; the
private export itself contains the retained source code.

### Verify a retained source-graph report

Rust and CLI callers can also supply the graph report captured for the admitted
source capsule. This works before any terminal outcome exists and after a worker
is interrupted. The report must describe the exact sources already authenticated
by the original admission; the verifier never recaptures the current project.

```sh
franken-verifier verify --format native-session-forensics \
  --trusted-key-hex "$TRUSTED_PRODUCT_ROOT_PUBLIC_KEY_HEX" \
  --expected-session-nonce "$EXPECTED_SESSION_NONCE" \
  --expected-admission-sha256 "$EXPECTED_ADMISSION_SHA256" \
  --graph-report captured-source-graph.json \
  < INC-SESSION-UUID.fnforensics.json
```

The expected session and admission options remain optional as a pair. When
supplied, they retain the same independent enrollment requirement described
above. The verifier authenticates the original admission, source capsule,
durable journal and outcome, and checks these identity pins before interpreting
the report. A valid graph report cannot replace any of these checks.

The report is separately bounded to 32 MiB. The CLI accepts a regular file,
including a symlink to one, with checks on the opened descriptor and the actual
bytes read. The Rust API accepts the report bytes directly:

```rust,ignore
let verified = native_session::verify_native_session_forensics_with_graph_report(
    &export_bytes,
    &trusted_product_root,
    expected_identity.as_ref(), // Option<&NativeSessionExpectedIdentity>
    &graph_report_bytes,
)?;
```

This verifies the report's strict schema, canonical graph commitment, retained
input observations, module and resolution targets, edges, and source byte
commitments against the pre-entry capsule. It adds `graph_report` with a
source-free digest and count summary. `graph_report.graph_hash_recomputed` is
`true`; `graph_report.graph_semantics_reconstructed` remains `false`. The
existing byte-only `source_capsule.graph_hash_recomputed` remains `false`.
`report_sha256` identifies the exact supplied report bytes. The summary does
not include graph paths, module specifiers, dependency names or source code.

The verification scope remains `authenticated_supervisor_observations`.
Pending and interrupted observations keep their original process and effect
status. Rehashing the recorded graph does not independently reconstruct resolver
semantics, prove that execution completed, certify remote-effect cleanup or
show that the retained history is complete. The graph's
`declared_fully_resolved` is the producer's declaration, and all existing replay,
quiescence and historical-completeness flags remain false.

Requesting a graph check for an otherwise valid v1/v2 export without sources
fails with `GRAPH_REPORT_MISSING`. A malformed, ambiguous, modified or foreign
report fails with `GRAPH_REPORT_INVALID`; unavailable or nonregular report files
fail with `GRAPH_REPORT_IO`, and oversized CLI files with `INPUT_TOO_LARGE`.
Missing or damaged v3 source data still fails its original schema or source
check. An explicit graph requirement never falls back to byte-only success.
Omitting `--graph-report` preserves the existing output without a
`graph_report` field. Native-session graph verification is currently exposed
through Rust and the CLI; the Python, JavaScript and TypeScript clients do not
expose this native graph option.

## Bounded, unambiguous parsing

The complete v1 export is limited to 16 MiB, v2 to 32 MiB and v3 to 96 MiB.
The v3 source capsule is limited to 40 MiB plus its 12-byte prefix: at most
8 MiB of canonical header and 32 MiB of retained payload, with at most 1,024
input observations. Its base64 transport must be canonical. Admission JSON is
limited to 4 MiB, and the
outcome signing payload to 5 MiB plus 1 KiB of receipt framing. WAL evidence
retains the producer's 4 MiB and 2,048 event limits; a completed provider call
consumes two events. Panic message text retains the 4,096-byte limit, original
byte count, truncation flag, and SHA-256 commitment.

The durable journal has a separate 4 MiB total limit and a 4 KiB limit per
record, excluding its newline, including a final partial record. At most 2,048
effect events follow the signed header. Duplicate members and unknown fields
are rejected in both each record envelope and its embedded payload. The CLI
reads at most 96 MiB and then applies the schema's narrower limit; diagnostics
and `Debug` output do not echo raw journal data.

Duplicate object members are rejected recursively in the envelope and in each
embedded JSON document before typed deserialization. Unknown fields,
unsupported schemas, malformed identities, missing required fields, explicit
`panic_evidence: null`, truncated input, and trailing JSON data are rejected.
An absent panic-evidence field remains compatible with older signed outcomes.
Error output uses bounded diagnostic codes without echoing evidence contents.

## Independently enrolled fleet supervisor observations

The `fleet-quiescence-observations` format consumes the existing
`fleet certify-quiescence --json` output or the raw
`franken-node/fleet-http-api/v2` epoch-barrier response. It verifies every
supervisor's original Ed25519 drain signature against a separately supplied
enrollment policy. This makes the fleet's retained, held session populations
auditable without importing the product, opening its databases, contacting the
coordinator, or running guest code.

```sh
franken-verifier verify --format fleet-quiescence-observations \
  --trusted-fleet-policy /auditor/fleet-policy.json \
  < fleet-quiescence.json
```

This format takes its multiple public-key anchors from the policy file; it
does not take `--trusted-key-hex`. Obtain the policy independently from the
untrusted evidence. Never construct it by copying a response's embedded keys,
participant list or action hashes into a new supposedly trusted policy.

The Python and JavaScript clients use the same separate policy file and
verify its exact byte commitment in the CLI result:

```python
from pathlib import Path
from franken_verifier import verify_artifact

verified = verify_artifact(
    Path("fleet-quiescence.json").read_bytes(),
    None,
    verifier="/opt/franken-verifier/bin/franken-verifier",
    format="fleet-quiescence-observations",
    trusted_fleet_policy="/auditor/fleet-policy.json",
)
```

```javascript
import { readFile } from "node:fs/promises";
import { verifyArtifact } from "./franken_verifier.mjs";

const verified = await verifyArtifact(await readFile("fleet-quiescence.json"), null, {
  verifier: "/opt/franken-verifier/bin/franken-verifier",
  format: "fleet-quiescence-observations",
  trustedFleetPolicy: "/auditor/fleet-policy.json",
});
```

The policy schema is `franken-verifier/fleet-quiescence-policy/v1`:

| Field | Independent expectation |
| --- | --- |
| `evaluation_time` | Trusted evaluation time with a four-digit year and non-leap seconds, in canonical UTC RFC3339 ending in `Z` |
| `max_observation_age_secs` | Positive freshness limit, at most 300 seconds |
| `expected_action_log` | Full reviewed ordered action log's `action_count` and lowercase `actions_sha256` |
| `expected_pre_epoch` | Expected response context; this field is not authenticated by a supervisor signature |
| `expected_trace_id` | Expected request context |
| `participants` | Complete enrollment, strictly sorted by `(zone_id, node_id)` |

Each participant supplies `zone_id`, `node_id`, the independently enrolled
`supervisor_public_key_hex`, `project_root_sha256`, a positive retained
`minimum_generation`, `expected_applied_actions` (the reviewed per-zone ordered
action checkpoint), and sorted, unique `expected_active_hold_ids`. Nodes in the
same zone must have the same expected action checkpoint and active hold owners.
The policy must list 1–1,024 concrete node/zone identities. Empty populations,
duplicate identities, weak Ed25519 keys and wildcard `all` participants are
refused. The caller derives its checkpoint and hold pins from its own reviewed
action history; this SDK reader does not reconstruct that history.

The verifier rejects missing or extra participants, renamed identities, stale
or future observations, foreign project roots or signing keys, older drain
generations, changed action checkpoints or hold owners, pending or indeterminate
sessions, released admission fences, and certificate summaries that disagree
with the signed observations. Refreshing a heartbeat or changing an unsigned
certificate timestamp cannot renew an expired supervisor signature. Freshness
is checked against the caller's evaluation time as well as the response's
claimed observation time. Counts use checked arithmetic; they cannot wrap when
the full population is aggregated.

Successful CLI results use scope `authenticated_fleet_supervisor_observations`
and include source-free counts, evidence and policy commitments, evaluation and
observation times, and these explicit facts:

- `supervisor_signatures_verified: true`
- `expected_population_complete: true`
- `expected_action_context_matched: true`
- `epoch_commit_authenticated: false`
- `current_quiescence_proven: false`

The last two limits are essential to this observations-only wire contract.
Legacy responses contain no public coordinator signature over the epoch
certificate; their durable HMAC-authenticated state is not a public trust anchor.
This format also accepts signed commit envelopes, but deliberately keeps its
observations-only scope. It does not authenticate the coordinator, prove the
action log's history, independently inventory all processes or remote effects,
or show that holds remain active after the signed instant.
`expected_population_complete` refers to the caller's supplied enrollment.
The JSON CLI emits aggregate session counts as decimal strings to preserve
full `u64` precision in JavaScript, and includes
`trusted_policy_input_sha256` over the exact policy-file bytes.

The response is capped at 8 MiB and the separate policy at 1 MiB. Duplicate
members and unknown fields fail before verification; diagnostics do not echo
untrusted node IDs, source paths, keys or evidence. Rust callers use
`fleet_quiescence::parse_fleet_quiescence_policy(bytes)` followed by
`fleet_quiescence::verify_fleet_quiescence_observations(response, &policy)`.
The protocol-only fixture in
`tests/fixtures/fleet_quiescence_observations.json` contains independently
generated signatures for two supervisors; it is not evidence of live fleet
execution or a completed distributed acceptance campaign.

## Independently authenticated coordinator epoch commits

The `fleet-epoch-commit` format verifies the retained coordinator commit in
addition to all supervisor, enrollment, action, count and freshness checks above.
It accepts `franken-node/fleet-epoch-commit-response/v1` from the HTTP API and
`franken-node/fleet-quiescence-cli/v2` from either `fleet certify-quiescence --json`
or `fleet export-epoch --epoch N --json`. Legacy unsigned responses fail with
`FLEET_EPOCH_PROOF_MISSING`; this format never falls back to observations-only
verification.

Supply the coordinator's identity and Ed25519 public key from independent
enrollment, alongside the existing supervisor policy:

```sh
franken-verifier verify --format fleet-epoch-commit \
  --trusted-fleet-policy /auditor/fleet-policy.json \
  --trusted-coordinator-id production-east \
  --trusted-coordinator-key-hex "$ENROLLED_COORDINATOR_PUBLIC_KEY" \
  < fleet-epoch.json
```

The coordinator key is separate from HTTP bearer credentials and supervisor
roots. Do not accept the candidate artifact's advertised key as enrollment.
The policy's `expected_pre_epoch` and `expected_trace_id` must match the signed
certificate; the committed epoch must be exactly the expected predecessor plus
one, without overflow. Rust callers pass a `FleetCoordinatorTrust` to
`fleet_quiescence::verify_fleet_epoch_commit(response, &policy, &coordinator)`.

```python
verified = verify_artifact(
    Path("fleet-epoch.json").read_bytes(),
    None,
    verifier="/opt/franken-verifier/bin/franken-verifier",
    format="fleet-epoch-commit",
    trusted_fleet_policy="/auditor/fleet-policy.json",
    trusted_coordinator_id="production-east",
    trusted_coordinator_public_key_hex=enrolled_coordinator_public_key,
)
assert verified["facts"]["epoch_commit_authenticated"] is True
assert verified["facts"]["current_quiescence_proven"] is False
```

```javascript
const committed = await verifyArtifact(await readFile("fleet-epoch.json"), null, {
  verifier: "/opt/franken-verifier/bin/franken-verifier",
  format: "fleet-epoch-commit",
  trustedFleetPolicy: "/auditor/fleet-policy.json",
  trustedCoordinatorId: "production-east",
  trustedCoordinatorPublicKeyHex: enrolledCoordinatorPublicKey,
});
```

Successful results use scope `authenticated_fleet_epoch_commit` and facts schema
`franken-verifier/fleet-epoch-commit/v1`. They retain the observation facts, set
`epoch_commit_authenticated: true`, and add the independently pinned
`coordinator_id`, `coordinator_key_id`, exact decimal-string `committed_epoch`,
`transition_id`, and `statement_sha256`. The last field hashes the canonical
signed statement. Aggregate counts and the committed epoch preserve all 64 bits
in the CLI and language bindings; Rust returns native `u64` values.

The proof carries two Ed25519 signatures over the same canonical statement:
authorization retained inside the durable epoch transaction, and a separate
commit signature issued only after the committed row is read back. The domains
are `franken-node/fleet-epoch-authorization-signature/v1\0` and
`franken-node/fleet-epoch-commit-signature/v1\0`. Each signs its domain bytes,
the eight-byte big-endian statement length, and the compact recursively
key-sorted statement JSON. An authorization signature cannot serve as a commit
signature. The statement binds the coordinator identity/key, predecessor and
committed epochs, transition and trace IDs, and a domain-separated SHA-256 of
the exact canonical JSON array `[evidence, certificate]`. Duplicate members are
rejected before canonicalization, and timestamp spellings are committed before
typed timestamp normalization.

Export preserves the original evidence and certification time. Evaluate a
historical export at a separately trusted historical time appropriate to the
policy; exporting or re-signing cannot make stale supervisor observations fresh.
`current_quiescence_proven` remains false. The authenticated coordinator attests
that the retained epoch committed; this does not independently audit its storage,
reconstruct the full epoch/action history, or prove that admission holds remain
active now. The fixture `tests/fixtures/fleet_epoch_commit.json` was signed
independently using Node's Ed25519 implementation and includes canonical digest
expectations. It exercises the wire protocol, not a live multi-node campaign.

## Independently verify compacted native sessions

`ops session-inventory compact --archive-dir ...` retains completed clean
sessions in a product-root-signed `franken-node/native-session-cold-archive/v1`
archive. The standalone Rust SDK, CLI, and Python and JavaScript/TypeScript
clients can authenticate those portable archives without the product database
or the original session files:

```sh
franken-verifier verify --format native-session-cold-archive \
  --trusted-key-hex "$ENROLLED_PRODUCT_ROOT_PUBLIC_KEY" \
  --expected-archive-root-sha256 "$RECORDED_ARCHIVE_MERKLE_ROOT" \
  < native-session-archive.json
```

Supply the root public key from independent enrollment. The optional expected
Merkle root is a raw, lowercase, 64-character SHA-256 recorded separately from
the candidate archive. It pins the ordered session population. It does not pin
operator text or the archival timestamp, which may be re-attested over the
same population. `artifact_sha256` and `facts.archive_sha256` identify the exact
transported bytes.

Rust callers use `native_session::verify_native_session_cold_archive(bytes,
&trusted_root)` or
`native_session::verify_native_session_cold_archive_with_expected_root(bytes,
&trusted_root, expected_merkle_root)`.

The language clients use the same explicit product root and optional population
pin. Keep the input as original bytes so that full-width admission integers and
the transport digest remain exact:

```python
verified = verify_artifact(
    archive_bytes,
    enrolled_product_root_hex,
    verifier="/trusted/bin/franken-verifier",
    format="native-session-cold-archive",
    expected_archive_root_sha256=retained_population_root,
)
assert verified["facts"]["original_receipt_signatures_verified"] is False
```

```typescript
const verified = await verifyArtifact(archiveBytes, enrolledProductRootHex, {
  verifier: "/trusted/bin/franken-verifier",
  format: "native-session-cold-archive",
  expectedArchiveRootSha256: retainedPopulationRoot,
});
if (verified.format === "native-session-cold-archive") {
  const replayCertified: false = verified.facts.replay_certified;
  console.log(verified.facts.session_count, verified.facts.merkle_root_sha256);
}
```

Both clients reject malformed or misapplied root pins before launching the
verifier. They require the returned scope, root identity, digest encodings,
population bounds and false proof flags to match the archive contract. Returned
archive facts must bind to the exact supplied bytes, and a requested population
root must match even if a faulty verifier ignores the command-line option.

Verification rejects duplicate JSON members, unknown fields, duplicate session
nonces, entry/root identity disagreement, invalid admission paths and metadata,
and outcomes that are not completed, worker-reaped, non-panic observations with
a consistent final-ledger summary and zero denied/failed effects. It recomputes
each leaf from the producer's ordered typed JSON, including UTC timestamp
normalization and historical optional-field omission. Leaf components use
eight-byte big-endian UTF-8 byte lengths. Merkle nodes hash the lowercase hex
children separated by `:`, duplicating the final child at each odd level.
The strict Ed25519 signature authenticates the domain-prefixed ordered archive
metadata; this signature protocol has no length prefix.

Success uses scope `authenticated_archived_supervisor_observations`. Returned
facts contain the trusted root identity, archive timestamp, session count,
source-bound session count, Merkle root, and exact archive digest. They omit
operator text, project paths, dependency names, and individual session records.
Captured paths are never opened.

The archive contains a compaction-time statement, not the original signed
admission/outcome receipts, source capsule bytes, final effect ledger, or durable
effect journal. Therefore `original_receipt_signatures_verified`,
`replay_certified`, `quiescence_certified`, and `historical_completeness` remain
false. A source-binding count only describes retained commitments. An archived
clean supervisor outcome does not independently prove external-effect cleanup,
historical completeness, current freshness, or current revocation status.

The SDK accepts at most 64 MiB of archive JSON and 16,384 sessions, with canonical
admission/outcome limits of 4 MiB and 5 MiB per entry. The 64 MiB outer limit is
an explicit standalone-verifier bound; the producer can create larger archives.
Use smaller `--max-sessions-to-archive` compaction batches for those populations.
Oversized input fails with `INPUT_TOO_LARGE`; wrong population pins fail with
`EXPECTED_ARCHIVE_ROOT_MISMATCH`. Signature, session, leaf, and Merkle failures
have distinct stable codes without captured values in diagnostics.

`tests/fixtures/native_session_cold_archives.json` contains synthetic protocol
vectors generated independently with Python `hashlib` and `cryptography` using
the public RFC 8032 test key. It covers singleton and odd-sized trees, alternate
timestamp spellings, full-width integers, Windows paths, historical option
omission, and validly signed semantic failures. It establishes wire-protocol
compatibility, not live compaction or recovery qualification.
