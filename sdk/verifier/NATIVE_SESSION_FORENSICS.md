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

## Bounded, unambiguous parsing

The complete v1 export is limited to 16 MiB and v2 to 32 MiB. Admission JSON is
limited to 4 MiB, and the
outcome signing payload to 5 MiB plus 1 KiB of receipt framing. WAL evidence
retains the producer's 4 MiB and 2,048 event limits; a completed provider call
consumes two events. Panic message text retains the 4,096-byte limit, original
byte count, truncation flag, and SHA-256 commitment.

The durable journal has a separate 4 MiB total limit and a 4 KiB limit per
record, excluding its newline, including a final partial record. At most 2,048
effect events follow the signed header. Duplicate members and unknown fields
are rejected in both each record envelope and its embedded payload. The CLI
reads at most 32 MiB and then applies the schema's narrower limit; diagnostics
and `Debug` output do not echo raw journal data.

Duplicate object members are rejected recursively in the envelope and in each
embedded JSON document before typed deserialization. Unknown fields,
unsupported schemas, malformed identities, missing required fields, explicit
`panic_evidence: null`, truncated input, and trailing JSON data are rejected.
An absent panic-evidence field remains compatible with older signed outcomes.
Error output uses bounded diagnostic codes without echoing evidence contents.
