//! Bounded, native admission of npm registry version ranges.
//!
//! Derived from the public node-semver range grammar, not its implementation.
//! Supports exact/partial/x versions, comparisons, conjunctions, disjunctions,
//! caret, tilde and hyphen ranges with SemVer prerelease exclusion. Build
//! metadata never changes precedence. This is a metadata predicate, not a
//! dependency solver: registry tags, URLs, Git, workspace protocols, npm
//! overrides and loose/coerced versions are NOT resolved here.
//!
//! `None` means unverified input, never permission to accept it. Parse every
//! disjunct before evaluating, so an invalid suffix cannot hide behind a
//! matching prefix. Size, numeric and term bounds are independent of regexes.
//! Specification: https://github.com/npm/node-semver#ranges

use std::cmp::Ordering;

const MAX_RANGE_BYTES: usize = 4096;
const MAX_VERSION_BYTES: usize = 256;
const MAX_TERMS: usize = 256;
const MAX_ALTERNATIVES: usize = 64;
const MAX_COMPONENT: u64 = 9_007_199_254_740_991;

type Checked<T> = Result<T, ()>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    core: [u64; 3],
    pre: Vec<String>,
}

impl Version {
    fn release(core: [u64; 3]) -> Self { Self { core, pre: Vec::new() } }

    fn cmp(&self, other: &Self) -> Ordering {
        let core = self.core.cmp(&other.core);
        if core != Ordering::Equal { return core; }
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        for (left, right) in self.pre.iter().zip(&other.pre) {
            let numeric_left = left.bytes().all(|byte| byte.is_ascii_digit());
            let numeric_right = right.bytes().all(|byte| byte.is_ascii_digit());
            let order = match (numeric_left, numeric_right) {
                (true, true) => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => left.cmp(right),
            };
            if order != Ordering::Equal { return order; }
        }
        self.pre.len().cmp(&other.pre.len())
    }
}

#[derive(Debug)]
struct Partial {
    base: Version,
    specified: usize,
}

fn identifiers(text: &str, prerelease: bool) -> Checked<Vec<String>> {
    text.split('.').map(|part| {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err(());
        }
        if prerelease && part.bytes().all(|byte| byte.is_ascii_digit()) {
            // npm's numeric comparison can lose precision beyond its safe
            // integer domain. Refuse that ambiguity rather than certifying a
            // mathematically ordered pair the reference treats as equal.
            component(part)?;
        }
        Ok(part.to_owned())
    }).collect()
}

fn component(text: &str) -> Checked<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(());
    }
    let value: u64 = text.parse().map_err(|_| ())?;
    if value > MAX_COMPONENT { return Err(()); }
    Ok(value)
}

fn partial(text: &str) -> Checked<Partial> {
    if text.is_empty() || text.len() > MAX_VERSION_BYTES || !text.is_ascii() { return Err(()); }
    let text = text.strip_prefix('v').unwrap_or(text);
    let (text, build) = match text.split_once('+') {
        Some((text, build)) => (text, Some(build)),
        None => (text, None),
    };
    if let Some(build) = build { identifiers(build, false)?; }
    let (core, pre) = match text.split_once('-') {
        Some((core, pre)) => (core, identifiers(pre, true)?),
        None => (text, Vec::new()),
    };
    let mut version = Version::release([0; 3]);
    let mut specified = 0;
    let mut wildcard = false;
    let mut parts = 0;
    for (index, part) in core.split('.').enumerate() {
        if index >= 3 { return Err(()); }
        parts += 1;
        if matches!(part, "*" | "x" | "X") {
            wildcard = true;
        } else {
            // Deliberately do not guess what mixed wildcard/numeric forms
            // such as 1.x.3 mean. They require explicit review.
            if wildcard { return Err(()); }
            version.core[index] = component(part)?;
            specified += 1;
        }
    }
    if parts == 0 || ((!pre.is_empty() || build.is_some()) && specified != 3) { return Err(()); }
    version.pre = pre;
    Ok(Partial { base: version, specified })
}

fn upper(base: &Version, index: usize, prerelease_floor: bool) -> Checked<Version> {
    let mut result = Version::release(base.core);
    let next = result.core[index].checked_add(1).ok_or(())?;
    if next > MAX_COMPONENT { return Err(()); }
    result.core[index] = next;
    for component in &mut result.core[index + 1..] { *component = 0; }
    if prerelease_floor { result.pre.push("0".into()); }
    Ok(result)
}

#[derive(Clone, Copy, Debug)]
enum Op { Eq, Lt, Le, Gt, Ge }

#[derive(Debug)]
struct Comparator { op: Op, version: Version }

impl Comparator {
    fn accepts(&self, candidate: &Version) -> bool {
        match (self.op, candidate.cmp(&self.version)) {
            (Op::Eq, Ordering::Equal)
            | (Op::Lt, Ordering::Less)
            | (Op::Le, Ordering::Less | Ordering::Equal)
            | (Op::Gt, Ordering::Greater)
            | (Op::Ge, Ordering::Greater | Ordering::Equal) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Default)]
struct Conjunction { comparators: Vec<Comparator>, impossible: bool }

impl Conjunction {
    fn push(&mut self, op: Op, version: Version) -> Checked<()> {
        if self.comparators.len() >= MAX_TERMS * 2 { return Err(()); }
        self.comparators.push(Comparator { op, version });
        Ok(())
    }

    fn accepts(&self, candidate: &Version) -> bool {
        !self.impossible
            && self.comparators.iter().all(|comparison| comparison.accepts(candidate))
            && (candidate.pre.is_empty() || self.comparators.iter().any(|comparison| {
                !comparison.version.pre.is_empty() && comparison.version.core == candidate.core
            }))
    }

    fn term(&mut self, operator: &str, value: Partial) -> Checked<()> {
        if value.specified == 0 {
            if matches!(operator, ">" | "<") { self.impossible = true; }
            return Ok(());
        }
        if matches!(operator, "^" | "~" | "~>") {
            let index = if operator != "^" {
                if value.specified == 1 { 0 } else { 1 }
            } else if value.base.core[0] != 0 || value.specified == 1 {
                0
            } else if value.base.core[1] != 0 || value.specified == 2 {
                1
            } else { 2 };
            let end = upper(&value.base, index, true)?;
            self.push(Op::Ge, value.base)?;
            return self.push(Op::Lt, end);
        }
        let op = match operator {
            "" | "=" => Op::Eq,
            "<" => Op::Lt,
            "<=" => Op::Le,
            ">" => Op::Gt,
            ">=" => Op::Ge,
            _ => return Err(()),
        };
        if value.specified == 3 { return self.push(op, value.base); }
        match op {
            Op::Eq => {
                let end = upper(&value.base, value.specified - 1, true)?;
                self.push(Op::Ge, value.base)?;
                self.push(Op::Lt, end)
            }
            Op::Ge => self.push(Op::Ge, value.base),
            Op::Gt => self.push(Op::Ge, upper(&value.base, value.specified - 1, false)?),
            Op::Le => self.push(Op::Lt, upper(&value.base, value.specified - 1, true)?),
            Op::Lt => {
                let mut end = value.base;
                end.pre.push("0".into());
                self.push(Op::Lt, end)
            }
        }
    }

    fn hyphen(&mut self, start: Partial, end: Partial) -> Checked<()> {
        if start.specified > 0 { self.push(Op::Ge, start.base)?; }
        match end.specified {
            0 => Ok(()),
            3 => self.push(Op::Le, end.base),
            count => self.push(Op::Lt, upper(&end.base, count - 1, true)?),
        }
    }
}

fn operator(text: &str) -> (&str, &str) {
    for prefix in [">=", "<=", "~>", ">", "<", "=", "^", "~"] {
        if let Some(value) = text.strip_prefix(prefix) { return (prefix, value); }
    }
    ("", text)
}

fn parse_range(text: &str) -> Checked<Vec<Conjunction>> {
    if text.len() > MAX_RANGE_BYTES || !text.is_ascii() { return Err(()); }
    let mut result = Vec::new();
    let mut term_count = 0_usize;
    for arm in text.split("||") {
        if result.len() >= MAX_ALTERNATIVES { return Err(()); }
        // Bound the complete input before collecting borrowed tokens.
        let tokens: Vec<_> = arm.split_ascii_whitespace().collect();
        term_count = term_count.checked_add(tokens.len()).ok_or(())?;
        if term_count > MAX_TERMS { return Err(()); }
        let mut conjunction = Conjunction::default();
        let mut index = 0;
        while index < tokens.len() {
            if tokens.get(index + 1) == Some(&"-") {
                // npm admits a hyphen range only as the entire OR arm. A
                // conjunction such as `1 - 4 >=2` is invalid, not a broader
                // range we may silently interpret on the producer's behalf.
                if index != 0 || tokens.len() != 3 { return Err(()); }
                let last = tokens.get(index + 2).ok_or(())?;
                conjunction.hyphen(partial(tokens[index])?, partial(last)?)?;
                index += 3;
                continue;
            }
            let (op, mut value) = operator(tokens[index]);
            if value.is_empty() {
                index += 1;
                value = tokens.get(index).copied().ok_or(())?;
            }
            conjunction.term(op, partial(value)?)?;
            index += 1;
        }
        result.push(conjunction);
    }
    Ok(result)
}

/// `Some(false)` is an actual range mismatch; `None` is unverified syntax,
/// an opaque request, invalid pin, or a resource/numeric bound. Neither admits
/// execution. Callers must distinguish these in their review findings.
pub(super) fn matches(request: &str, locked_version: &str) -> Option<bool> {
    let candidate = partial(locked_version).ok()?;
    if candidate.specified != 3 { return None; }
    let range = parse_range(request).ok()?;
    Some(range.iter().any(|arm| arm.accepts(&candidate.base)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // These independent truth values are also checked against npm's semver
    // reference. Do not obtain expected results from this implementation.
    const CASES: &[(&str, &str, bool)] = &[
        ("1.2.3", "1.2.3", true),
        ("1.2.3", "1.2.4", false),
        ("1.2.3+build", "1.2.3+other", true),
        ("v1.2.3", "v1.2.3", true),
        ("=1.2.3", "1.2.3", true),
        ("1", "1.99.0", true),
        ("1.2", "1.3.0", false),
        ("1.x", "1.8.2", true),
        ("1.2.X", "1.2.9", true),
        ("*", "0.0.0", true),
        ("*", "1.0.0-alpha", false),
        ("^1.2.3", "1.9.9", true),
        ("^1.2.3", "2.0.0", false),
        ("^0.2.3", "0.2.99", true),
        ("^0.2.3", "0.3.0", false),
        ("^0.0.3", "0.0.4", false),
        ("^0.0", "0.0.9", true),
        ("^0.0", "0.1.0", false),
        ("^0", "0.9.9", true),
        ("~1.2.3", "1.2.99", true),
        ("~1.2.3", "1.3.0", false),
        ("~1", "1.9.9", true),
        ("~>1.2", "1.2.9", true),
        (">=1.2.3 <2.0.0", "1.9.0", true),
        (">=1.2.3 <2.0.0", "2.0.0", false),
        (">= 1.2.3 < 2", "1.9.0", true),
        (">1.x", "1.99.9", false),
        (">1.x", "2.0.0", true),
        ("<=1.2.x", "1.2.99", true),
        ("<=1.2.x", "1.3.0", false),
        ("<1.x", "0.9.9", true),
        ("<1.x", "1.0.0", false),
        (">*", "3.0.0", false),
        (">=*", "3.0.0", true),
        ("1.2.3 - 2.3.4", "2.3.4", true),
        ("1.2.3 - 2.3.4", "2.3.5", false),
        ("1.2 - 2.3", "2.3.99", true),
        ("1.2 - 2.3", "2.4.0", false),
        ("1 - 2", "2.99.0", true),
        ("^1 || ^3", "2.0.0", false),
        ("^1 || ^3", "3.2.1", true),
        (">=1.2.3-beta.2 <2.0.0", "1.2.3-beta.10", true),
        (">=1.2.3-beta.2 <2.0.0", "1.2.4-beta.10", false),
        ("^1.2.3-beta.2", "1.2.3-beta.10", true),
        ("^1.2.3-beta.2", "2.0.0-alpha", false),
        (">1.2.3-alpha.9", "1.2.3-alpha.10", true),
        (">1.2.3-9", "1.2.3-alpha", true),
        (">=1.2.3-alpha", "1.2.3", true),
        ("1.2.3-alpha", "1.2.3-alpha.1", false),
        ("1.2.3 - 1.2.4-beta", "1.2.4-alpha", true),
        ("^ 1.2.3", "1.8.0", true),
        ("~ 1.2.3", "1.2.8", true),
        ("1.2.3 ||", "99.0.0", true),
        ("", "1.0.0", true),
    ];

    #[test]
    fn supported_ranges_obey_independent_reference_truth_values() {
        for (request, version, expected) in CASES {
            assert_eq!(matches(request, version), Some(*expected), "{request:?} / {version:?}");
        }
    }

    #[test]
    fn opaque_requests_invalid_versions_and_invalid_alternatives_are_not_matches() {
        for request in ["latest", "next", "file:../x", "workspace:*", "git+https://x/repo",
            "npm:other@1", "https://x/a.tgz", "1.2.3 || garbage", "* || >=", "01.2.3",
            "1.2.3-alpha.01", "1.x.3", ">=", "1.2.3 -", "1.2.3+", "1.2.3 ||| 2",
            "1 - 4 2 - 3", "1 - 4 >=2", ">=1 1 - 4"]
        {
            assert_eq!(matches(request, "1.2.3"), None, "{request}");
        }
        for version in ["1", "1.x", "1.2.3.4", "1.2.3-alpha.01", "1.2.3+", "01.2.3", "latest"] {
            assert_eq!(matches("*", version), None, "{version}");
        }
    }

    #[test]
    fn prerelease_numeric_identifiers_never_use_lossy_comparison() {
        assert_eq!(matches(
            ">1.0.0-9007199254740992", "1.0.0-9007199254740993"
        ), None);
        assert_eq!(matches(
            ">1.0.0-999999999999999", "1.0.0-1000000000000000"
        ), Some(true));
        assert_eq!(matches("*", "1.0.0-alpha"), Some(false));
        assert_eq!(matches("<2.0.0", "1.9.0-alpha"), Some(false));
    }

    #[test]
    fn budgets_and_arithmetic_fail_closed() {
        assert_eq!(matches(&" ".repeat(MAX_RANGE_BYTES + 1), "1.0.0"), None);
        assert_eq!(matches("*", &format!("1.0.0+{}", "a".repeat(MAX_VERSION_BYTES))), None);
        assert_eq!(matches(&vec!["*"; MAX_ALTERNATIVES + 1].join(" || "), "1.0.0"), None);
        assert_eq!(matches(&vec!["1"; MAX_TERMS + 1].join(" "), "1.0.0"), None);
        assert_eq!(matches("^9007199254740991.0.0", "9007199254740991.0.0"), None);
        assert_eq!(matches("*", "9007199254740992.0.0"), None);
        assert_eq!(matches("π", "1.0.0"), None);
    }
}
