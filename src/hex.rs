//! Minimal hex helpers so the crate does not need another dependency.

use std::fmt::Write;

/// Decodes upper- or lowercase hex. Returns `None` on odd length, non-hex
/// characters, or non-ASCII input.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    // Decode nibble by nibble instead of `u8::from_str_radix`, which accepts a
    // leading `+` and would turn "+f" into 0x0f.
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encodes bytes as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_mixed_case() {
        assert_eq!(decode("dEaDbEeF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode(""), Some(vec![]));
    }

    #[test]
    fn rejects_odd_length_and_bad_chars() {
        assert_eq!(decode("abc"), None);
        assert_eq!(decode("zz"), None);
        assert_eq!(decode("+1"), None);
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        assert_eq!(decode("€€"), None);
        assert_eq!(decode("aé"), None);
        assert_eq!(decode("aaé"), None);
        assert_eq!(decode("ÿÿ"), None);
    }

    proptest::proptest! {
        #[test]
        fn roundtrip(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..128)) {
            proptest::prop_assert_eq!(decode(&encode(&bytes)), Some(bytes));
        }

        #[test]
        fn decode_never_panics(s in "\\PC*") {
            let _ = decode(&s);
        }
    }
}
