# Production signature protocol fixture

`producer-run.fnbundle` contains synthetic execution metadata sealed by the
actual production implementations in `crates/franken-node`. It is a protocol
interoperability vector, **not evidence that a native guest executed**.

The focused producer compiled the complete original source files for
`tools/replay_bundle`, `runtime/effect_receipt`, `storage/cas`,
`supply_chain/artifact_signing`, and their cryptographic dependencies. It called
`EffectReceiptChain::append`, `sign_run_ledger_record`,
`parse_verified_run_ledger_record`, `generate_replay_bundle`,
`sign_replay_bundle`, `verify_replay_bundle_signature`, and
`to_canonical_json`. Only noncryptographic bounded-read and vector-capacity
utilities were supplied by the host. No signer, hash canonicalizer, or verifier
implementation was substituted.

The record contains a synthetic filesystem-read receipt, distinct operator and
engine trace IDs, unknown signed metadata, and the difficult finite floating
values `51.248178375505404`, `-93.31137037688033`, and `52.314008204106244`.
The producer signs the whole generic JSON statement before retaining it as raw
text inside the separately signed incident bundle. These values catch number
parser differences that simple integer-valued or binary-exact floats miss.

The run key uses the explicit public test seed `41` repeated 32 bytes. The
exporter uses the published RFC 8032 section 7.1 TEST 1 seed. Neither key may be
trusted outside tests. The `.pub` files contain the corresponding independent
public anchors. `PROVENANCE.json` records the emitted fixture/record digests and
producer source hashes, and explicitly identifies the unproved execution,
typed receipt-identity and engine-session properties.

The SDK integration test uses the original producer signatures unchanged. The
language test matrix additionally creates altered exports with the separate
exporter test key, showing that a trusted exporter cannot silently rewrite or
strip the original authority's statement.
