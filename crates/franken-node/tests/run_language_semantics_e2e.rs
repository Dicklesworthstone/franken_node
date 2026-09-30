//! bd-reality-20260923-26n9r.6 (deliverable 2): an executable language-semantics
//! oracle. Each probe is a plain ES2015-ES2022 snippet with the output a real
//! Node.js prints; the test runs it through the embedded franken engine and
//! checks franken against Node.
//!
//! Two invariants are enforced as PASSING assertions:
//!   1. Supported-and-fixed constructs (async IIFE, generator spread, Node
//!      `console.log`/util.inspect formatting) produce Node-identical output.
//!   2. NO SILENT MISCOMPILE: for a supported-syntax probe, franken never
//!      produces output that DIFFERS from Node while exiting 0. A construct the
//!      engine cannot yet handle must fail closed (non-zero exit) -- never quietly
//!      return a wrong answer. This is the anti-regression for the worst bug
//!      class in the reality check (`class:this.#x`, exit 0).
//!
//! Node's expected strings are inlined (they are stable ECMAScript semantics),
//! so this test needs no `node`/`bun` on the host and runs under the normal
//! (rch) lane. Node was the reference used to capture them (v22.2.0, 2026-09-30).
//!
//! Known gaps that remain the engine's to close are documented as `#[ignore]`d
//! tests below (deliverable 4), so they are tracked in code and flip to failing
//! -- prompting promotion to the "must match Node" set -- the moment the engine
//! implements them.

use std::process::Command;

fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

/// Run one snippet through the embedded engine under `balanced`, console-only
/// (so only the guest's own stdout is captured -- no preflight banner or
/// receipt), and return (exit_code, stdout).
fn run_snippet(source: &str) -> (Option<i32>, String) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", "balanced", "--out-dir", "."])
        .current_dir(dir.path())
        .output()
        .expect("spawn franken-node init");
    assert!(
        init.status.success(),
        "init must bootstrap the workspace; stderr=\n{}",
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::write(dir.path().join("app.js"), source).expect("write snippet");
    let output = Command::new(franken_node_bin())
        .args([
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--console-only",
        ])
        .current_dir(dir.path())
        .output()
        .expect("spawn franken-node run");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// (snippet, exact output a real Node prints).
const FIXED_PROBES: &[(&str, &str)] = &[
    // Async IIFE with `await` (was `type error: expected function, got string`).
    (
        "(async()=>{ await null; console.log(\"async-ok\"); })();",
        "async-ok\n",
    ),
    // Generator + iterable spread (was `type error: expected iterable`).
    (
        "function* g(){yield 1; yield 2;} console.log([...g()].join(\"+\"))",
        "1+2\n",
    ),
    // Node console.log / util.inspect object+array formatting (was
    // `[object Object] 1,2,3`).
    ("console.log({a:1},[1,2,3])", "{ a: 1 } [ 1, 2, 3 ]\n"),
    // A few more stable ES semantics, to broaden the regression surface.
    (
        "const m = new Map([[1,'a'],[2,'b']]); console.log(m.get(2), m.size)",
        "b 2\n",
    ),
    (
        "console.log([3,1,2].sort((a,b)=>a-b).map(x=>x*2).join(','))",
        "2,4,6\n",
    ),
    (
        "const {a,...rest} = {a:1,b:2,c:3}; console.log(a, JSON.stringify(rest))",
        "1 {\"b\":2,\"c\":3}\n",
    ),
    (
        "console.log(`t${1+1}` , typeof Symbol.iterator)",
        "t2 symbol\n",
    ),
];

#[test]
fn fixed_language_semantics_match_node() {
    for (source, expected) in FIXED_PROBES {
        let (exit, stdout) = run_snippet(source);
        assert_eq!(
            exit,
            Some(0),
            "supported snippet must exit 0: {source:?}\ngot exit={exit:?} stdout=\n{stdout}"
        );
        assert_eq!(
            stdout, *expected,
            "franken output must match Node for: {source:?}"
        );
    }
}

/// The reality-check's worst bug was a SILENT wrong answer: ES2022 class fields
/// were accepted and `get x(){return this.#x}` returned the literal string
/// "this.#x" at exit 0. The engine now rejects class fields at parse time
/// (fail-closed), which is correct. This test pins the invariant: whatever the
/// engine does with a not-yet-supported construct, it must MATCH Node or FAIL
/// (non-zero exit) -- never a different answer at exit 0.
#[test]
fn no_silent_miscompile_on_supported_or_rejected_syntax() {
    // (snippet, the answer Node gives). The engine may match it, or fail closed;
    // it must never print something else at exit 0.
    const MISCOMPILE_GUARD_PROBES: &[(&str, &str)] = &[
        (
            "class A { #x=1; get x(){return this.#x;} } console.log(\"class:\"+new A().x)",
            "class:1\n",
        ),
        (
            "class C { static s=5; m(){return C.s;} } console.log(new C().m())",
            "5\n",
        ),
    ];
    for (source, node_output) in MISCOMPILE_GUARD_PROBES {
        let (exit, stdout) = run_snippet(source);
        if exit == Some(0) {
            assert_eq!(
                stdout, *node_output,
                "SILENT MISCOMPILE: franken exited 0 with output differing from Node for {source:?} \
                 (Node: {node_output:?}, franken: {stdout:?}). A construct the engine cannot \
                 evaluate correctly must fail closed, never return a wrong answer."
            );
        }
        // exit != 0 is an honest fail-closed rejection: acceptable.
    }
}

/// Deliverable 4 -- known gaps, tracked in code. These globals are absent
/// (`typeof` returns "undefined") or capability-gated in a way plain programs
/// cannot satisfy. Node provides them as pure builtins. `#[ignore]`d so the
/// suite is green; remove the ignore (and move the probe into FIXED_PROBES) once
/// the engine lands them. Filed as engine work: franken_engine bd-3l74k.
#[test]
#[ignore = "franken_engine bd-3l74k: globalThis is capability-gated and TextEncoder/structuredClone are unimplemented; un-ignore when they land as pure builtins"]
fn pure_global_builtins_are_provided_like_node() {
    for (source, expected) in &[
        (
            "console.log(typeof globalThis, globalThis === globalThis)",
            "object true\n",
        ),
        ("console.log(typeof TextEncoder)", "function\n"),
        ("console.log(typeof structuredClone)", "function\n"),
        (
            "console.log(new TextEncoder().encode('AB').join(','))",
            "65,66\n",
        ),
        (
            "const o={a:[1,2]}; const c=structuredClone(o); c.a.push(3); console.log(o.a.length, c.a.length)",
            "2 3\n",
        ),
    ] {
        let (exit, stdout) = run_snippet(source);
        assert_eq!(exit, Some(0), "{source:?} should run once implemented");
        assert_eq!(stdout, *expected, "{source:?} should match Node");
    }
}
