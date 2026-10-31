//! Wire-format parser for `ECHConfigList`.
//!
//! ```text
//! ECHConfig ECHConfigList<4..2^16-1>;
//! struct { uint16 version; uint16 length; ECHConfigContents contents; } ECHConfig;
//! struct {
//!     HpkeKeyConfig key_config;          // u8 id, u16 kem, opaque pk<1..2^16-1>,
//!                                        // suites<4..2^16-4> of (u16 kdf, u16 aead)
//!     uint8 maximum_name_length;
//!     opaque public_name<1..255>;
//!     Extension extensions<0..2^16-1>;   // u16 type, opaque data<0..2^16-1>
//! } ECHConfigContents;
//! ```

use super::{EchConfig, EchError, HpkeSymmetricSuite, ECH_VERSION};

/// Extension types with the high bit set are mandatory (RFC 9849, 4.2).
const MANDATORY_EXTENSION_BIT: u16 = 0x8000;

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], EchError> {
        if n > self.buf.len() {
            return Err(EchError::Truncated);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, EchError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, EchError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn vec_u8(&mut self) -> Result<&'a [u8], EchError> {
        let len = self.u8()?;
        self.take(usize::from(len))
    }

    fn vec_u16(&mut self) -> Result<&'a [u8], EchError> {
        let len = self.u16()?;
        self.take(usize::from(len))
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn finish(self, what: &'static str) -> Result<(), EchError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(EchError::Malformed(what))
        }
    }
}

/// Returns the usable configs and how many entries were ignored.
pub(super) fn config_list(bytes: &[u8]) -> Result<(Vec<EchConfig>, usize), EchError> {
    let mut outer = Reader::new(bytes);
    let list = outer.vec_u16()?;
    outer.finish("trailing bytes after ECHConfigList")?;
    if list.is_empty() {
        return Err(EchError::Malformed("empty ECHConfigList"));
    }

    let mut reader = Reader::new(list);
    let mut configs = Vec::new();
    let mut skipped = 0;
    while !reader.is_empty() {
        let version = reader.u16()?;
        let body = reader.vec_u16()?;
        if version != ECH_VERSION {
            skipped += 1;
            continue;
        }
        match contents(body)? {
            Some(config) => configs.push(config),
            None => skipped += 1,
        }
    }
    Ok((configs, skipped))
}

/// Parses `ECHConfigContents`. `Ok(None)` means "valid framing, but a client
/// must ignore this entry".
fn contents(body: &[u8]) -> Result<Option<EchConfig>, EchError> {
    let mut r = Reader::new(body);
    let config_id = r.u8()?;
    let kem_id = r.u16()?;
    let public_key = r.vec_u16()?;
    if public_key.is_empty() {
        return Err(EchError::Malformed("empty HPKE public key"));
    }
    let suites = r.vec_u16()?;
    if suites.is_empty() || !suites.len().is_multiple_of(4) {
        return Err(EchError::Malformed("bad HPKE cipher suite list length"));
    }
    let cipher_suites = suites
        .chunks_exact(4)
        .map(|s| HpkeSymmetricSuite {
            kdf_id: u16::from_be_bytes([s[0], s[1]]),
            aead_id: u16::from_be_bytes([s[2], s[3]]),
        })
        .collect();
    let maximum_name_length = r.u8()?;
    let public_name = r.vec_u8()?;
    if public_name.is_empty() {
        return Err(EchError::Malformed("empty public_name"));
    }
    let has_mandatory_extension = extensions(r.vec_u16()?)?;
    r.finish("trailing bytes in ECHConfigContents")?;

    // We understand no extensions, so any mandatory one makes the entry
    // unusable. An invalid public_name must be ignored as well.
    let Some(public_name) = valid_public_name(public_name) else {
        return Ok(None);
    };
    if has_mandatory_extension {
        return Ok(None);
    }
    Ok(Some(EchConfig {
        config_id,
        kem_id,
        public_key: public_key.to_vec(),
        cipher_suites,
        maximum_name_length,
        public_name,
    }))
}

/// Walks the extension list and reports whether any mandatory one is present.
fn extensions(list: &[u8]) -> Result<bool, EchError> {
    let mut r = Reader::new(list);
    let mut mandatory = false;
    while !r.is_empty() {
        let ext_type = r.u16()?;
        r.vec_u16()?;
        mandatory |= ext_type & MANDATORY_EXTENSION_BIT != 0;
    }
    Ok(mandatory)
}

/// RFC 9849, section 6.1.7: a dot-separated sequence of LDH labels of at most
/// 63 octets, no leading or trailing dot, and a last label that does not look
/// like an IPv4 literal (all digits, or `0x` followed by hex digits).
fn valid_public_name(raw: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(raw).ok()?;
    let labels: Vec<&str> = name.split('.').collect();
    if !labels.iter().all(|label| is_ldh_label(label)) {
        return None;
    }
    let last = labels.last()?;
    let all_digits = last.bytes().all(|b| b.is_ascii_digit());
    let hex_literal = last.len() >= 2
        && last[..2].eq_ignore_ascii_case("0x")
        && last[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if all_digits || hex_literal {
        return None;
    }
    Some(name.to_owned())
}

fn is_ldh_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}
