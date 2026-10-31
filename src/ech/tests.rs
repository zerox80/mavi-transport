use super::*;

const X25519: u16 = 0x0020;
const HKDF_SHA256: u16 = 0x0001;
const AES_128_GCM: u16 = 0x0001;
const CHACHA20: u16 = 0x0003;

/// Test-only encoder for a single `ECHConfig`.
#[derive(Clone)]
struct Entry {
    version: u16,
    config_id: u8,
    kem: u16,
    public_key: Vec<u8>,
    suites: Vec<(u16, u16)>,
    max_name_len: u8,
    public_name: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Entry {
    fn new(public_name: &str) -> Self {
        Self {
            version: ECH_VERSION,
            config_id: 7,
            kem: X25519,
            public_key: (0u8..32).collect(),
            suites: vec![(HKDF_SHA256, AES_128_GCM)],
            max_name_len: 64,
            public_name: public_name.as_bytes().to_vec(),
            extensions: Vec::new(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut body = vec![self.config_id];
        body.extend(self.kem.to_be_bytes());
        push_u16_vec(&mut body, &self.public_key);
        let suites: Vec<u8> = self
            .suites
            .iter()
            .flat_map(|(kdf, aead)| [kdf.to_be_bytes(), aead.to_be_bytes()].concat())
            .collect();
        push_u16_vec(&mut body, &suites);
        body.push(self.max_name_len);
        body.push(u8::try_from(self.public_name.len()).unwrap());
        body.extend(&self.public_name);
        let mut exts = Vec::new();
        for (ty, data) in &self.extensions {
            exts.extend(ty.to_be_bytes());
            push_u16_vec(&mut exts, data);
        }
        push_u16_vec(&mut body, &exts);

        let mut out = self.version.to_be_bytes().to_vec();
        push_u16_vec(&mut out, &body);
        out
    }
}

fn push_u16_vec(out: &mut Vec<u8>, data: &[u8]) {
    out.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend(data);
}

fn list(entries: &[Entry]) -> Vec<u8> {
    let body: Vec<u8> = entries.iter().flat_map(Entry::encode).collect();
    let mut out = Vec::new();
    push_u16_vec(&mut out, &body);
    out
}

fn aws_lc() -> &'static [&'static dyn Hpke] {
    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
}

#[test]
fn parses_mavi_server_default() {
    let parsed = EchConfigList::parse(&list(&[Entry::new("cover.example.com")])).unwrap();
    assert_eq!(parsed.skipped(), 0);
    assert_eq!(parsed.outer_sni(), "cover.example.com");
    let config = &parsed.configs()[0];
    assert_eq!(config.config_id, 7);
    assert_eq!(config.kem_id, X25519);
    assert_eq!(config.public_key, (0u8..32).collect::<Vec<_>>());
    assert_eq!(
        config.cipher_suites,
        vec![HpkeSymmetricSuite {
            kdf_id: HKDF_SHA256,
            aead_id: AES_128_GCM
        }]
    );
    assert_eq!(config.maximum_name_length, 64);
}

#[test]
fn from_hex_accepts_surrounding_whitespace() {
    let bytes = list(&[Entry::new("cover.example.com")]);
    let text = format!("  {}\n", hex::encode(&bytes));
    assert_eq!(
        EchConfigList::from_hex(&text).unwrap(),
        EchConfigList::parse(&bytes).unwrap()
    );
    assert_eq!(
        text.parse::<EchConfigList>().unwrap().outer_sni(),
        "cover.example.com"
    );
    assert_eq!(EchConfigList::from_hex("zz"), Err(EchError::InvalidHex));
    assert_eq!(EchConfigList::from_hex("abc"), Err(EchError::InvalidHex));
}

#[test]
fn skips_unknown_versions() {
    let mut old = Entry::new("old.example.com");
    old.version = 0xfe0a;
    let parsed = EchConfigList::parse(&list(&[old, Entry::new("new.example.com")])).unwrap();
    assert_eq!(parsed.skipped(), 1);
    assert_eq!(parsed.outer_sni(), "new.example.com");
}

#[test]
fn skips_entries_with_unknown_mandatory_extension() {
    let mut mandatory = Entry::new("mandatory.example.com");
    mandatory.extensions = vec![(0x8001, vec![1, 2])];
    let mut optional = Entry::new("optional.example.com");
    optional.extensions = vec![(0x0001, vec![]), (0x7fff, vec![9; 3])];
    let parsed = EchConfigList::parse(&list(&[mandatory, optional])).unwrap();
    assert_eq!(parsed.skipped(), 1);
    assert_eq!(parsed.outer_sni(), "optional.example.com");
}

#[test]
fn ignores_invalid_public_names() {
    let invalid = [
        "-bad.example.com",
        "bad-.example.com",
        "a..b",
        ".leading.dot",
        "trailing.dot.",
        "under_score.com",
        "1.2.3.4",
        "example.123",
        "example.0x1f",
        "example.0X",
        "bücher.de",
        "has space.com",
    ];
    for name in invalid {
        let err = EchConfigList::parse(&list(&[Entry::new(name)])).unwrap_err();
        assert_eq!(err, EchError::NoSupportedConfig { skipped: 1 }, "{name}");
    }
    let too_long_label = format!("{}.com", "a".repeat(64));
    assert!(EchConfigList::parse(&list(&[Entry::new(&too_long_label)])).is_err());
}

#[test]
fn accepts_valid_public_names() {
    let max_label = format!("{}.com", "a".repeat(63));
    let valid = [
        "cover.example.com",
        "localhost",
        "a-b.c0m",
        "xn--bcher-kva.de",
        "123.example.com",
        "example.0xg",
        max_label.as_str(),
    ];
    for name in valid {
        let parsed = EchConfigList::parse(&list(&[Entry::new(name)])).unwrap();
        assert_eq!(parsed.outer_sni(), name);
        assert!(
            rustls::pki_types::ServerName::try_from(name).is_ok(),
            "{name} must be usable as a rustls server name"
        );
    }
}

#[test]
fn reports_when_every_entry_is_ignored() {
    let mut unknown = Entry::new("a.example.com");
    unknown.version = 0x0001;
    let err = EchConfigList::parse(&list(&[unknown, Entry::new("1.2.3.4")])).unwrap_err();
    assert_eq!(err, EchError::NoSupportedConfig { skipped: 2 });
}

#[test]
fn rejects_malformed_framing() {
    let good = list(&[Entry::new("cover.example.com")]);

    assert_eq!(EchConfigList::parse(&[]), Err(EchError::Truncated));
    assert_eq!(
        EchConfigList::parse(&[0xde, 0xad, 0xbe, 0xef]),
        Err(EchError::Truncated)
    );
    assert!(matches!(
        EchConfigList::parse(&[0, 0]),
        Err(EchError::Malformed(_))
    ));
    assert_eq!(
        EchConfigList::parse(&good[..good.len() - 1]),
        Err(EchError::Truncated)
    );

    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        EchConfigList::parse(&trailing),
        Err(EchError::Malformed(_))
    ));

    // An entry whose declared length is longer than its contents.
    let mut entry = Entry::new("cover.example.com").encode();
    entry.push(0);
    let len = u16::from_be_bytes([entry[2], entry[3]]) + 1;
    entry[2..4].copy_from_slice(&len.to_be_bytes());
    let mut padded = Vec::new();
    push_u16_vec(&mut padded, &entry);
    assert!(matches!(
        EchConfigList::parse(&padded),
        Err(EchError::Malformed(_))
    ));
}

#[test]
fn rejects_empty_or_misaligned_fields() {
    let mut no_key = Entry::new("cover.example.com");
    no_key.public_key.clear();
    let mut no_suites = Entry::new("cover.example.com");
    no_suites.suites.clear();
    let mut no_name = Entry::new("cover.example.com");
    no_name.public_name.clear();
    for entry in [no_key, no_suites, no_name] {
        assert!(matches!(
            EchConfigList::parse(&list(&[entry])),
            Err(EchError::Malformed(_))
        ));
    }
}

#[test]
fn grease_uses_first_supported_suite() {
    let mut entry = Entry::new("cover.example.com");
    entry.suites = vec![(0x7777, 0x7777), (HKDF_SHA256, CHACHA20)];
    let parsed = EchConfigList::parse(&list(&[entry])).unwrap();
    let grease = parsed
        .grease(aws_lc())
        .expect("aws-lc-rs supports X25519/SHA256/ChaCha20");
    assert_eq!(grease.outer_sni, "cover.example.com");
    assert!(parsed.configs()[0].grease_config(aws_lc()).is_some());
}

#[test]
fn grease_falls_back_to_next_config() {
    let mut unsupported = Entry::new("first.example.com");
    unsupported.kem = 0x9999;
    let parsed =
        EchConfigList::parse(&list(&[unsupported, Entry::new("second.example.com")])).unwrap();
    assert_eq!(parsed.outer_sni(), "first.example.com");
    assert_eq!(
        parsed.grease(aws_lc()).unwrap().outer_sni,
        "second.example.com"
    );
}

#[test]
fn grease_is_none_without_matching_hpke() {
    let mut entry = Entry::new("cover.example.com");
    entry.kem = 0x9999;
    let parsed = EchConfigList::parse(&list(&[entry])).unwrap();
    assert!(parsed.grease(aws_lc()).is_none());
    // ring has no HPKE in rustls 0.23: only the cover SNI is available.
    let parsed = EchConfigList::parse(&list(&[Entry::new("cover.example.com")])).unwrap();
    assert!(parsed.grease(&[]).is_none());
    assert_eq!(parsed.outer_sni(), "cover.example.com");
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn grease_aws_lc_rs_matches_explicit_suites() {
    let parsed = EchConfigList::parse(&list(&[Entry::new("cover.example.com")])).unwrap();
    assert_eq!(
        parsed.grease_aws_lc_rs().map(|g| g.outer_sni),
        parsed.grease(aws_lc()).map(|g| g.outer_sni)
    );
}

fn arb_label() -> impl proptest::strategy::Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,20}[a-z]"
}

proptest::proptest! {
    #[test]
    fn parse_never_panics(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
        let _ = EchConfigList::parse(&bytes);
    }

    #[test]
    fn parse_never_panics_on_valid_prefix(cut in 0usize..80, garbage in proptest::collection::vec(proptest::num::u8::ANY, 0..16)) {
        let mut bytes = list(&[Entry::new("cover.example.com")]);
        bytes.truncate(cut.min(bytes.len()));
        bytes.extend(garbage);
        let _ = EchConfigList::parse(&bytes);
    }

    #[test]
    fn roundtrips_valid_entries(
        labels in proptest::collection::vec(arb_label(), 1..4),
        config_id in proptest::num::u8::ANY,
        kem in proptest::num::u16::ANY,
        key in proptest::collection::vec(proptest::num::u8::ANY, 1..200),
        suites in proptest::collection::vec((proptest::num::u16::ANY, proptest::num::u16::ANY), 1..6),
        max_name_len in proptest::num::u8::ANY,
    ) {
        let name = labels.join(".");
        let entry = Entry { config_id, kem, public_key: key.clone(), suites: suites.clone(), max_name_len, ..Entry::new(&name) };
        let parsed = EchConfigList::parse(&list(&[entry])).unwrap();
        let config = &parsed.configs()[0];
        proptest::prop_assert_eq!(&config.public_name, &name);
        proptest::prop_assert_eq!(config.config_id, config_id);
        proptest::prop_assert_eq!(config.kem_id, kem);
        proptest::prop_assert_eq!(&config.public_key, &key);
        proptest::prop_assert_eq!(config.maximum_name_length, max_name_len);
        let expected: Vec<_> = suites.iter().map(|&(kdf_id, aead_id)| HpkeSymmetricSuite { kdf_id, aead_id }).collect();
        proptest::prop_assert_eq!(&config.cipher_suites, &expected);
    }
}
