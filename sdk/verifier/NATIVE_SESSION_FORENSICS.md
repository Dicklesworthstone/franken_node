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

The envelope has exactly four fields:

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

## Bounded, unambiguous parsing

The complete export is limited to 16 MiB, admission JSON to 4 MiB, and the
outcome signing payload to 5 MiB plus 1 KiB of receipt framing. WAL evidence
retains the producer's 4 MiB and 2,048 event limits; a completed provider call
consumes two events. Panic message text retains the 4,096-byte limit, original
byte count, truncation flag, and SHA-256 commitment.

Duplicate object members are rejected recursively in the envelope and in each
embedded JSON document before typed deserialization. Unknown fields,
unsupported schemas, malformed identities, missing required fields, explicit
`panic_evidence: null`, truncated input, and trailing JSON data are rejected.
An absent panic-evidence field remains compatible with older signed outcomes.
Error output uses bounded diagnostic codes without echoing evidence contents.
