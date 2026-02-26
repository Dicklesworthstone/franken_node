/// Constant-time string comparison for signature verification.
///
/// Uses XOR-and-accumulate to avoid timing side-channels.  The comparison
/// always examines every byte of both inputs (after length check) so an
/// attacker cannot infer how many prefix bytes matched.
///
/// INV-CT-01: Comparison runtime depends only on string length, not content.
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte slice comparison.
///
/// INV-CT-02: Comparison runtime depends only on slice length, not content.
#[must_use]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings_match() {
        assert!(ct_eq("abc123", "abc123"));
    }

    #[test]
    fn different_strings_do_not_match() {
        assert!(!ct_eq("abc123", "abc124"));
    }

    #[test]
    fn different_lengths_do_not_match() {
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn empty_strings_match() {
        assert!(ct_eq("", ""));
    }

    #[test]
    fn first_byte_differs() {
        assert!(!ct_eq("xbc", "abc"));
    }

    #[test]
    fn last_byte_differs() {
        assert!(!ct_eq("abx", "abc"));
    }

    #[test]
    fn ct_eq_bytes_equal() {
        assert!(ct_eq_bytes(b"hello", b"hello"));
    }

    #[test]
    fn ct_eq_bytes_differ() {
        assert!(!ct_eq_bytes(b"hello", b"hellx"));
    }

    #[test]
    fn ct_eq_bytes_different_len() {
        assert!(!ct_eq_bytes(b"abc", b"abcd"));
    }

    #[test]
    fn ct_eq_bytes_empty() {
        assert!(ct_eq_bytes(b"", b""));
    }

    #[test]
    fn ct_eq_bytes_32_equal() {
        let a = [0xABu8; 32];
        assert!(ct_eq_bytes(&a, &a));
    }

    #[test]
    fn ct_eq_bytes_32_last_differs() {
        let a = [0xABu8; 32];
        let mut b = a;
        b[31] = 0xAC;
        assert!(!ct_eq_bytes(&a, &b));
    }
}
