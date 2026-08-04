#!/usr/bin/env python3
"""check_claims_manifest.py — recompute README headline claims from the tree.

Why this exists
---------------
The 2026-06 reality check (epic bd-5r99w) found the README's headline numbers had
drifted from what the tree actually contains (a "23k tests" badge that implied a
default `cargo test` runs them when ~21k are compiled out; "43 fuzz harnesses"
vs 146 on disk; "460+ validators" vs 436). bd-5r99w.5 corrected them; this gate
makes them *stay* correct: it recomputes each claim from the committed tree and
fails CI when the manifest (and therefore the README, which the manifest backs)
drifts beyond tolerance. It is the recompute foundation that the signed,
SDK-recomputable Honesty Manifest (bd-5r99w.9) builds on.

Claims recomputed
-----------------
  integration_tests_run_by_cargo_test   #[test] under tests/ + crates/**/tests/
  inline_tests_behind_inline_lane       #[test] under crates/**/src + sdk/**/src
  fuzz_targets_registered               [[bin]] paths into fuzz_targets/ in fuzz/Cargo.toml
  validators                            scripts/check_*.py
  unsafe_blocks                         real `unsafe {`/`unsafe fn`/`unsafe impl` in src (must be 0)
  license                               [workspace.package] license in Cargo.toml
  replay_verdict_load_bearing           incident-replay recompute is NOT debug-only (bd-5r99w.3)

Usage
-----
    python scripts/check_claims_manifest.py            # recompute + compare to manifest
    python scripts/check_claims_manifest.py --json      # robot output (claim/expected/actual)
    python scripts/check_claims_manifest.py --ci         # exit 1 on any drift
    python scripts/check_claims_manifest.py --update      # regenerate docs/claims_manifest.json
    python scripts/check_claims_manifest.py --self-test   # comparison/tolerance unit tests

Exit codes
----------
    0   no drift (or --warn-only)
    1   --ci/--strict and >= 1 claim drifted
    2   execution error
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from scripts.lib.test_logger import configure_test_logging
except Exception:  # pragma: no cover
    def configure_test_logging(_name):  # type: ignore
        import logging

        return logging.getLogger(_name)

ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = ROOT / "docs" / "claims_manifest.json"
MANIFEST_SCHEMA = "franken-node/claims-manifest/v1"
TEST_ATTR_RE = re.compile(r"#\[\s*(?:tokio::)?test\s*\]")
UNSAFE_RE = re.compile(r"\bunsafe\s+(?:\{|fn\b|impl\b)")
LICENSE_RE = re.compile(r'^\s*license\s*=\s*"([^"]+)"', re.MULTILINE)

# --------------------------------------------------------------------------- #
# Honesty Manifest (bd-5r99w.9): the signed, SDK-recomputable elevation of the
# claims manifest. These constants MUST stay byte-compatible with the verifier
# SDK at sdk/verifier/src/honesty_manifest.rs (canonical JSON + domains + the
# deterministic Ed25519 harness key).
# --------------------------------------------------------------------------- #
HONESTY_MANIFEST_PATH = ROOT / "docs" / "honesty_manifest.json"
HONESTY_EVIDENCE_PATH = ROOT / "docs" / "honesty_manifest_evidence.json"
HONESTY_MANIFEST_SCHEMA = "franken-node/honesty-manifest/v1"
HONESTY_EVIDENCE_SCHEMA = "franken-node/honesty-manifest-evidence/v1"
HONESTY_SIGNATURE_ALGORITHM = "ed25519"
HONESTY_HARNESS_KEY_ID = "franken-node-honesty-manifest-harness-v1"
HONESTY_SIGNATURE_DOMAIN = b"frankenengine-verifier-sdk:honesty-manifest-signature:v1:"
HONESTY_CLAIM_EVIDENCE_DOMAIN = b"frankenengine-verifier-sdk:honesty-claim-evidence:v1:"
HONESTY_CORPUS_DOMAIN = b"frankenengine-verifier-sdk:honesty-corpus:v1:"
HONESTY_HARNESS_SEED_PREIMAGE = b"frankenengine-verifier-sdk:honesty-manifest-harness-key:v1"
HONESTY_GENERATED_AT = "1970-01-01T00:00:00Z"
SHA256_PREFIX = "sha256:"

# Map claim_id -> (kind, census fn, scalar fn). Counts/exacts use a census of
# per-source items; string/bool claims use a scalar recompute.
INLINE_SRC_DIRS = [
    "crates/franken-node/src",
    "sdk/verifier/src",
    "crates/franken-security-macros/src",
]
INTEGRATION_TEST_DIRS = ["tests", "crates/franken-node/tests", "sdk/verifier/tests"]


def _strip_line_comment(line: str) -> str:
    """Drop a // line comment (naive: ignores // inside strings, fine for the
    unsafe scan which only needs to avoid flagging commented mentions)."""
    in_str = False
    i = 0
    while i < len(line) - 1:
        c = line[i]
        if c == '"' and (i == 0 or line[i - 1] != "\\"):
            in_str = not in_str
        elif not in_str and c == "/" and line[i + 1] == "/":
            return line[:i]
        i += 1
    return line


def _count_attr_in_dirs(dirs, attr_re) -> int:
    total = 0
    for d in dirs:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            try:
                total += len(attr_re.findall(f.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                pass
    return total


def recompute_integration_tests() -> int:
    return _count_attr_in_dirs(
        ["tests", "crates/franken-node/tests", "sdk/verifier/tests"], TEST_ATTR_RE
    )


def recompute_inline_tests() -> int:
    return _count_attr_in_dirs(
        ["crates/franken-node/src", "sdk/verifier/src", "crates/franken-security-macros/src"],
        TEST_ATTR_RE,
    )


def recompute_fuzz_targets() -> int:
    manifest = ROOT / "fuzz" / "Cargo.toml"
    if not manifest.exists():
        return 0
    return len(
        [
            ln
            for ln in manifest.read_text(encoding="utf-8", errors="replace").splitlines()
            if re.match(r'\s*path\s*=\s*"fuzz_targets/', ln)
        ]
    )


def recompute_validators() -> int:
    return len(list((ROOT / "scripts").glob("check_*.py")))


def recompute_unsafe_blocks() -> int:
    total = 0
    for d in ["crates/franken-node/src", "sdk/verifier/src", "crates/franken-security-macros/src"]:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    code = _strip_line_comment(line)
                    if UNSAFE_RE.search(code):
                        total += 1
            except OSError:
                pass
    return total


def recompute_license() -> str:
    cargo = ROOT / "Cargo.toml"
    if not cargo.exists():
        return ""
    text = cargo.read_text(encoding="utf-8", errors="replace")
    # Prefer the [workspace.package] license; fall back to the first license line.
    m = LICENSE_RE.search(text)
    return m.group(1) if m else ""


def recompute_replay_load_bearing() -> bool:
    """True iff incident-replay derives its verdict from a recompute that is NOT
    gated behind #[cfg(debug_assertions)] (the bd-5r99w.3 invariant), and the
    old clone-then-self-compare is absent from the verdict path."""
    f = ROOT / "crates" / "franken-node" / "src" / "tools" / "replay_bundle.rs"
    if not f.exists():
        return False
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    # locate the compute fn; ensure the line above it is not #[cfg(debug_assertions)]
    for i, ln in enumerate(lines):
        if re.match(r"\s*fn compute_decision_sequence_hash\(", ln):
            prev = lines[i - 1].strip() if i > 0 else ""
            if "cfg(debug_assertions)" in prev:
                return False
            break
    else:
        return False
    # ensure the verdict fn recomputes (not clones the manifest hash into the verdict)
    body = "\n".join(lines)
    fn_idx = body.find("fn replay_bundle_after_signature_verification")
    if fn_idx < 0:
        return False
    window = body[fn_idx : fn_idx + 1500]
    recomputes = "let replayed_sequence_hash = compute_decision_sequence_hash(" in window
    self_compares = "replayed_sequence_hash = bundle.manifest.decision_sequence_hash.clone()" in window
    return recomputes and not self_compares


RECOMPUTERS = {
    "integration_tests_run_by_cargo_test": recompute_integration_tests,
    "inline_tests_behind_inline_lane": recompute_inline_tests,
    "fuzz_targets_registered": recompute_fuzz_targets,
    "validators": recompute_validators,
    "unsafe_blocks": recompute_unsafe_blocks,
    "license": recompute_license,
    "replay_verdict_load_bearing": recompute_replay_load_bearing,
}


# --------------------------------------------------------------------------- #
# Honesty Manifest (bd-5r99w.9)
#
# The claims manifest above is a CI-local recompute. The Honesty Manifest
# elevates it into a SIGNED, granular, verifier-SDK-recomputable artifact: a
# per-source CENSUS of the committed tree (docs/honesty_manifest_evidence.json)
# plus a signed manifest (docs/honesty_manifest.json) binding each claim's value
# to that census via a digest and an Ed25519 signature over the canonical
# payload. The verifier SDK (sdk/verifier/src/honesty_manifest.rs) recomputes
# every claim from the census and verifies the signature with ZERO trust in the
# producing runtime. All hashing/canonicalization here is byte-compatible with
# that Rust module.
# --------------------------------------------------------------------------- #
HONESTY_CLAIM_KINDS = {
    "integration_tests_run_by_cargo_test": "count",
    "inline_tests_behind_inline_lane": "count",
    "fuzz_targets_registered": "count",
    "validators": "count",
    "unsafe_blocks": "exact",
    "license": "string",
    "replay_verdict_load_bearing": "bool",
}


def _census_attr_in_dirs(dirs, attr_re) -> list:
    """Per-file counts of attr matches, sorted by ROOT-relative source path."""
    items = []
    for d in dirs:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            try:
                count = len(attr_re.findall(f.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                count = 0
            if count > 0:
                items.append({"source": f.relative_to(ROOT).as_posix(), "count": count})
    items.sort(key=lambda i: i["source"])
    return items


def census_integration_tests() -> list:
    return _census_attr_in_dirs(INTEGRATION_TEST_DIRS, TEST_ATTR_RE)


def census_inline_tests() -> list:
    return _census_attr_in_dirs(INLINE_SRC_DIRS, TEST_ATTR_RE)


def census_fuzz_targets() -> list:
    manifest = ROOT / "fuzz" / "Cargo.toml"
    items = []
    if manifest.exists():
        for ln in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r'\s*path\s*=\s*"(fuzz_targets/[^"]+)"', ln)
            if m:
                items.append({"source": m.group(1), "count": 1})
    items.sort(key=lambda i: i["source"])
    return items


def census_validators() -> list:
    items = [
        {"source": f"scripts/{p.name}", "count": 1}
        for p in (ROOT / "scripts").glob("check_*.py")
    ]
    items.sort(key=lambda i: i["source"])
    return items


def census_unsafe_blocks() -> list:
    items = []
    for d in INLINE_SRC_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for f in base.rglob("*.rs"):
            count = 0
            try:
                for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                    if UNSAFE_RE.search(_strip_line_comment(line)):
                        count += 1
            except OSError:
                count = 0
            if count > 0:
                items.append({"source": f.relative_to(ROOT).as_posix(), "count": count})
    items.sort(key=lambda i: i["source"])
    return items


HONESTY_CENSUS = {
    "integration_tests_run_by_cargo_test": census_integration_tests,
    "inline_tests_behind_inline_lane": census_inline_tests,
    "fuzz_targets_registered": census_fuzz_targets,
    "validators": census_validators,
    "unsafe_blocks": census_unsafe_blocks,
}

HONESTY_SCALARS = {
    "license": recompute_license,
    "replay_verdict_load_bearing": lambda: "true" if recompute_replay_load_bearing() else "false",
}


def _canonical_bytes(obj) -> bytes:
    """Canonical JSON: recursively key-sorted, compact, UTF-8 — byte-identical
    to serde_json::to_vec(canonicalize_value(...)) in the verifier SDK."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_prefixed(domain: bytes, payload: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(len(payload).to_bytes(8, "little"))
    hasher.update(payload)
    return SHA256_PREFIX + hasher.hexdigest()


def _evidence_entry(claim_id: str, items: list, scalar) -> dict:
    return {"claim_id": claim_id, "items": items, "scalar": scalar}


def _evidence_digest(entry: dict) -> str:
    return _sha256_prefixed(HONESTY_CLAIM_EVIDENCE_DOMAIN, _canonical_bytes(entry))


def _corpus_digest(pairs: list) -> str:
    """Digest over (claim_id, evidence_digest) pairs in claim_id sort order."""
    hasher = hashlib.sha256()
    hasher.update(HONESTY_CORPUS_DOMAIN)
    for claim_id, digest in sorted(pairs):
        cid = claim_id.encode("utf-8")
        dig = digest.encode("utf-8")
        hasher.update(len(cid).to_bytes(8, "little"))
        hasher.update(cid)
        hasher.update(len(dig).to_bytes(8, "little"))
        hasher.update(dig)
    return SHA256_PREFIX + hasher.hexdigest()


def _signature_message(canonical_unsigned: bytes) -> bytes:
    return (
        HONESTY_SIGNATURE_DOMAIN
        + len(canonical_unsigned).to_bytes(8, "little")
        + canonical_unsigned
    )


def _harness_private_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = hashlib.sha256(HONESTY_HARNESS_SEED_PREIMAGE).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _harness_public_hex() -> str:
    from cryptography.hazmat.primitives import serialization

    raw = (
        _harness_private_key()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return raw.hex()


def _readme_pins() -> dict:
    """README-pinned values + tolerances from the .6 claims manifest."""
    if not MANIFEST_PATH.exists():
        return {}
    try:
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8")).get("claims", {})
    except (OSError, json.JSONDecodeError):
        return {}


def build_honesty_artifacts() -> tuple:
    """Build (evidence_dict, unsigned_manifest_dict) from the live tree."""
    pins = _readme_pins()
    evidence_claims = []
    manifest_claims = []
    for claim_id, kind in HONESTY_CLAIM_KINDS.items():
        if kind in ("count", "exact"):
            items = HONESTY_CENSUS[claim_id]()
            scalar = None
            recomputed = sum(i["count"] for i in items)
        elif kind == "string":
            items = []
            scalar = HONESTY_SCALARS[claim_id]()
            recomputed = scalar
        elif kind == "bool":
            items = []
            scalar = HONESTY_SCALARS[claim_id]()
            recomputed = scalar == "true"
        else:  # pragma: no cover - guarded by HONESTY_CLAIM_KINDS
            raise ValueError(f"unknown honesty claim kind {kind}")
        entry = _evidence_entry(claim_id, items, scalar)
        evidence_claims.append(entry)
        pin = pins.get(claim_id, {})
        readme_value = pin.get("value", recomputed)
        tolerance_bp = (
            int(round(float(pin.get("tolerance_pct", 0)) * 100)) if kind == "count" else 0
        )
        manifest_claims.append(
            {
                "claim_id": claim_id,
                "kind": kind,
                "recomputed_value": recomputed,
                "readme_value": readme_value,
                "tolerance_bp": tolerance_bp,
                "evidence_digest": _evidence_digest(entry),
                "readme_claim": pin.get("readme_claim", ""),
            }
        )
    evidence = {
        "schema_version": HONESTY_EVIDENCE_SCHEMA,
        "generated_at": HONESTY_GENERATED_AT,
        "claims": evidence_claims,
    }
    unsigned = {
        "schema_version": HONESTY_MANIFEST_SCHEMA,
        "generated_at": HONESTY_GENERATED_AT,
        "claims": manifest_claims,
        "corpus_digest": _corpus_digest(
            [(c["claim_id"], c["evidence_digest"]) for c in manifest_claims]
        ),
    }
    return evidence, unsigned


def sign_honesty_manifest(unsigned: dict) -> dict:
    canonical = _canonical_bytes(unsigned)
    signature = _harness_private_key().sign(_signature_message(canonical))
    manifest = dict(unsigned)
    manifest["signature"] = {
        "algorithm": HONESTY_SIGNATURE_ALGORITHM,
        "signer_key_id": HONESTY_HARNESS_KEY_ID,
        "signer_public_key_hex": _harness_public_hex(),
        "signature_hex": signature.hex(),
    }
    return manifest


def update_honesty() -> int:
    evidence, unsigned = build_honesty_artifacts()
    manifest = sign_honesty_manifest(unsigned)
    HONESTY_EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    HONESTY_EVIDENCE_PATH.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    HONESTY_MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    census_total = sum(len(e["items"]) for e in evidence["claims"])
    print(f"wrote {HONESTY_EVIDENCE_PATH.relative_to(ROOT)} ({census_total} census items)")
    print(f"wrote {HONESTY_MANIFEST_PATH.relative_to(ROOT)} (corpus {unsigned['corpus_digest']})")
    return 0


def check_honesty() -> tuple:
    """Verify the committed honesty manifest+evidence (no crypto required for
    the drift/consistency checks; Ed25519 verified when `cryptography` exists)."""
    ok_list, drift_list = [], []
    if not HONESTY_MANIFEST_PATH.exists() or not HONESTY_EVIDENCE_PATH.exists():
        drift_list.append(
            ("honesty_artifacts", "missing honesty manifest/evidence — run --update-honesty")
        )
        return ok_list, drift_list
    try:
        manifest = json.loads(HONESTY_MANIFEST_PATH.read_text(encoding="utf-8"))
        evidence = json.loads(HONESTY_EVIDENCE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        drift_list.append(("honesty_parse", str(exc)))
        return ok_list, drift_list

    if manifest.get("schema_version") != HONESTY_MANIFEST_SCHEMA:
        drift_list.append(("honesty_schema", f"manifest schema {manifest.get('schema_version')}"))
    if evidence.get("schema_version") != HONESTY_EVIDENCE_SCHEMA:
        drift_list.append(
            ("honesty_evidence_schema", f"evidence schema {evidence.get('schema_version')}")
        )

    ev_by_id = {e["claim_id"]: e for e in evidence.get("claims", [])}
    live_census = {cid: fn() for cid, fn in HONESTY_CENSUS.items()}

    for claim in manifest.get("claims", []):
        cid = claim["claim_id"]
        kind = claim["kind"]
        entry = ev_by_id.get(cid)
        if entry is None:
            drift_list.append((cid, "no committed census entry"))
            continue
        recomputed_digest = _evidence_digest(
            {"claim_id": entry["claim_id"], "items": entry["items"], "scalar": entry["scalar"]}
        )
        if recomputed_digest != claim["evidence_digest"]:
            drift_list.append((cid, "committed evidence digest mismatch"))
            continue
        if kind in ("count", "exact"):
            committed_sum = sum(i["count"] for i in entry["items"])
            if committed_sum != claim["recomputed_value"]:
                drift_list.append(
                    (cid, f"manifest value {claim['recomputed_value']} != census sum {committed_sum}")
                )
                continue
            live_sum = sum(i["count"] for i in live_census[cid])
            rv = claim["recomputed_value"]
            if kind == "exact":
                if live_sum != rv:
                    drift_list.append((cid, f"live {live_sum} != recorded exact {rv}"))
                    continue
            else:
                tol = claim.get("tolerance_bp", 0)
                drift_bp = abs(live_sum - rv) * 10000 // rv if rv else (0 if live_sum == 0 else 10**9)
                if drift_bp > tol:
                    drift_list.append(
                        (cid, f"live {live_sum} drifts {drift_bp}bp from recorded {rv} (tol {tol}bp)")
                    )
                    continue
            ok_list.append((cid, f"census sum {rv} (live {live_sum})"))
        elif kind == "string":
            if entry.get("scalar") != claim["recomputed_value"]:
                drift_list.append((cid, "committed scalar != manifest value"))
                continue
            live = HONESTY_SCALARS[cid]()
            if live != claim["recomputed_value"]:
                drift_list.append((cid, f"live scalar {live!r} != recorded"))
                continue
            ok_list.append((cid, f"scalar {claim['recomputed_value']!r}"))
        elif kind == "bool":
            expected_scalar = "true" if claim["recomputed_value"] else "false"
            if entry.get("scalar") != expected_scalar:
                drift_list.append((cid, "committed scalar != manifest bool"))
                continue
            if HONESTY_SCALARS[cid]() != expected_scalar:
                drift_list.append((cid, "live bool != recorded"))
                continue
            ok_list.append((cid, f"bool {expected_scalar}"))

    recomputed_corpus = _corpus_digest(
        [(c["claim_id"], c["evidence_digest"]) for c in manifest.get("claims", [])]
    )
    if recomputed_corpus != manifest.get("corpus_digest"):
        drift_list.append(("honesty_corpus", "corpus digest mismatch"))
    else:
        ok_list.append(("honesty_corpus", "ok"))

    # Defense-in-depth Ed25519 verification when crypto is available. The
    # load-bearing signature check is the Rust SDK conformance test, which
    # always runs under cargo; this is a best-effort cross-language confirmation.
    signature = manifest.get("signature", {})
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_hex = signature.get("signer_public_key_hex", "")
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        unsigned = {k: v for k, v in manifest.items() if k != "signature"}
        public_key.verify(
            bytes.fromhex(signature.get("signature_hex", "")),
            _signature_message(_canonical_bytes(unsigned)),
        )
        if pub_hex != _harness_public_hex():
            drift_list.append(("honesty_signature", "signer key is not the harness key"))
        else:
            ok_list.append(("honesty_signature", "ed25519 ok (harness key)"))
    except ImportError:
        ok_list.append(
            ("honesty_signature", "ed25519 verify skipped (no cryptography; SDK test enforces it)")
        )
    except Exception as exc:  # noqa: BLE001 - surface any verify failure as drift
        drift_list.append(("honesty_signature", f"ed25519 verify failed: {exc}"))

    return ok_list, drift_list


def build_manifest() -> dict:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "description": (
            "Machine-recomputable snapshot of README headline claims. Regenerate "
            "with `python scripts/check_claims_manifest.py --update` and reconcile "
            "the README when a rounded claim changes. Backs bd-5r99w.6 / bd-5r99w.9."
        ),
        "claims": {
            "integration_tests_run_by_cargo_test": {
                "value": recompute_integration_tests(),
                "kind": "count",
                "tolerance_pct": 30,
                "readme_claim": "~3.8k e2e (badge + Testing section)",
            },
            "inline_tests_behind_inline_lane": {
                "value": recompute_inline_tests(),
                "kind": "count",
                "tolerance_pct": 30,
                "readme_claim": "~21k inline (badge + Testing section)",
            },
            "fuzz_targets_registered": {
                "value": recompute_fuzz_targets(),
                "kind": "count",
                "tolerance_pct": 20,
                "readme_claim": "146 registered cargo-fuzz harnesses",
            },
            "validators": {
                "value": recompute_validators(),
                "kind": "count",
                "tolerance_pct": 20,
                "readme_claim": "430+ / ~436 scripts/check_*.py",
            },
            "unsafe_blocks": {
                "value": recompute_unsafe_blocks(),
                "kind": "exact",
                "readme_claim": "0 (#![forbid(unsafe_code)])",
            },
            "license": {
                "value": recompute_license(),
                "kind": "string",
                "readme_claim": "MIT + OpenAI/Anthropic Rider",
            },
            "replay_verdict_load_bearing": {
                "value": recompute_replay_load_bearing(),
                "kind": "bool",
                "readme_claim": "incident replay is integrity-verified / load-bearing (bd-5r99w.3)",
            },
        },
    }


def compare_claim(name: str, spec: dict, actual) -> tuple[bool, str]:
    """Return (ok, detail)."""
    kind = spec.get("kind", "count")
    expected = spec.get("value")
    if kind == "exact":
        ok = actual == expected
        return ok, f"expected {expected}, actual {actual}"
    if kind == "string":
        ok = str(actual) == str(expected)
        return ok, f"expected '{expected}', actual '{actual}'"
    if kind == "bool":
        ok = bool(actual) == bool(expected)
        return ok, f"expected {expected}, actual {actual}"
    # count: within tolerance band
    tol = float(spec.get("tolerance_pct", 20)) / 100.0
    if expected in (0, None):
        ok = actual == 0
        return ok, f"expected {expected}, actual {actual}"
    drift = abs(actual - expected) / float(expected)
    ok = drift <= tol
    return ok, f"expected {expected} ±{int(tol*100)}%, actual {actual} (drift {drift*100:.1f}%)"


def run_check(manifest: dict) -> tuple[list, list]:
    ok_list, drift_list = [], []
    for name, spec in manifest.get("claims", {}).items():
        recompute = RECOMPUTERS.get(name)
        if recompute is None:
            drift_list.append((name, f"no recomputer registered for claim '{name}'"))
            continue
        actual = recompute()
        ok, detail = compare_claim(name, spec, actual)
        (ok_list if ok else drift_list).append((name, detail))
    return ok_list, drift_list


# --------------------------------------------------------------------------- #
# Self-test (comparison/tolerance logic, deterministic — no tree dependency)
# --------------------------------------------------------------------------- #
def run_self_test() -> int:
    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got != want:
            print(f"SELFTEST FAIL [{label}]: got {got}, want {want}")
            failures += 1
        else:
            print(f"selftest ok  [{label}]")

    # count within tolerance
    check("count_within_tol", compare_claim("c", {"kind": "count", "value": 100, "tolerance_pct": 30}, 120)[0], True)
    check("count_outside_tol", compare_claim("c", {"kind": "count", "value": 100, "tolerance_pct": 30}, 140)[0], False)
    check("count_regression", compare_claim("c", {"kind": "count", "value": 146, "tolerance_pct": 20}, 80)[0], False)
    # exact
    check("exact_zero_ok", compare_claim("u", {"kind": "exact", "value": 0}, 0)[0], True)
    check("exact_nonzero_bad", compare_claim("u", {"kind": "exact", "value": 0}, 1)[0], False)
    # string
    check("string_ok", compare_claim("l", {"kind": "string", "value": "LicenseRef-MIT-OpenAI-Anthropic-Rider"}, "LicenseRef-MIT-OpenAI-Anthropic-Rider")[0], True)
    check("string_bare_mit_bad", compare_claim("l", {"kind": "string", "value": "LicenseRef-MIT-OpenAI-Anthropic-Rider"}, "MIT")[0], False)
    # bool
    check("bool_true_ok", compare_claim("r", {"kind": "bool", "value": True}, True)[0], True)
    check("bool_regressed_bad", compare_claim("r", {"kind": "bool", "value": True}, False)[0], False)
    # comment stripper does not see commented unsafe
    check("strip_comment_unsafe", bool(UNSAFE_RE.search(_strip_line_comment("// unsafe impl Send"))), False)
    check("strip_keeps_real_unsafe", bool(UNSAFE_RE.search(_strip_line_comment("unsafe { ptr }"))), True)

    # honesty: canonical JSON is recursively key-sorted + compact (must match
    # serde_json::to_vec(canonicalize_value(...)) in the verifier SDK)
    check("canonical_sorts_keys", _canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}')
    check(
        "canonical_nested_and_arrays",
        _canonical_bytes({"z": [{"y": 1, "x": 2}], "a": True}),
        b'{"a":true,"z":[{"x":2,"y":1}]}',
    )
    # honesty: digests are deterministic and stable
    entry = _evidence_entry("c", [{"source": "f.rs", "count": 3}], None)
    check("evidence_digest_stable", _evidence_digest(entry), _evidence_digest(entry))
    check("evidence_digest_prefixed", _evidence_digest(entry).startswith(SHA256_PREFIX), True)
    check(
        "corpus_digest_order_invariant",
        _corpus_digest([("a", "sha256:1"), ("b", "sha256:2")]),
        _corpus_digest([("b", "sha256:2"), ("a", "sha256:1")]),
    )
    # honesty: changing a count changes the digest (tamper-evidence)
    entry2 = _evidence_entry("c", [{"source": "f.rs", "count": 4}], None)
    check("evidence_digest_tamper", _evidence_digest(entry) != _evidence_digest(entry2), True)

    print(("\nself-test FAILED: %d" % failures) if failures else "\nself-test PASSED")
    return 1 if failures else 0


def main() -> int:
    logger = configure_test_logging("check_claims_manifest")
    ap = argparse.ArgumentParser(description="Recompute + gate README headline claims")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ci", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--warn-only", action="store_true")
    ap.add_argument("--update", action="store_true", help="regenerate docs/claims_manifest.json")
    ap.add_argument(
        "--update-honesty",
        action="store_true",
        help="regenerate the signed Honesty Manifest + evidence census (needs `cryptography`)",
    )
    ap.add_argument(
        "--check-honesty",
        action="store_true",
        help="verify the committed Honesty Manifest + evidence against the live tree",
    )
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()

    if args.update_honesty:
        return update_honesty()

    if args.check_honesty:
        ok_list, drift_list = check_honesty()
        if args.json:
            print(
                json.dumps(
                    {
                        "schema_version": HONESTY_MANIFEST_SCHEMA,
                        "ok_count": len(ok_list),
                        "drift_count": len(drift_list),
                        "ok": [{"claim": n, "detail": d} for n, d in ok_list],
                        "drift": [{"claim": n, "detail": d} for n, d in drift_list],
                    },
                    indent=2,
                )
            )
        else:
            for n, d in ok_list:
                print(f"ok    {n}: {d}")
            for n, d in drift_list:
                print(f"DRIFT {n}: {d}")
            print(f"\nhonesty: {len(ok_list)} ok, {len(drift_list)} drifted")
        logger.info("honesty-manifest: %d ok, %d drift", len(ok_list), len(drift_list))
        if drift_list and (args.ci or args.strict) and not args.warn_only:
            return 1
        return 0

    if args.update:
        manifest = build_manifest()
        MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {MANIFEST_PATH.relative_to(ROOT)}")
        print(json.dumps(manifest["claims"], indent=2))
        return 0

    if not MANIFEST_PATH.exists():
        print(f"manifest missing: {MANIFEST_PATH} — run --update first", file=sys.stderr)
        return 2
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error reading manifest: {exc}", file=sys.stderr)
        return 2

    ok_list, drift_list = run_check(manifest)

    if args.json:
        print(json.dumps({
            "schema_version": manifest.get("schema_version"),
            "ok_count": len(ok_list),
            "drift_count": len(drift_list),
            "ok": [{"claim": n, "detail": d} for n, d in ok_list],
            "drift": [{"claim": n, "detail": d} for n, d in drift_list],
        }, indent=2))
    else:
        for n, d in ok_list:
            print(f"ok    {n}: {d}")
        for n, d in drift_list:
            print(f"DRIFT {n}: {d}")
        print(f"\n{len(ok_list)} ok, {len(drift_list)} drifted")

    logger.info("claims-manifest: %d ok, %d drift", len(ok_list), len(drift_list))
    if drift_list and (args.ci or args.strict) and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
