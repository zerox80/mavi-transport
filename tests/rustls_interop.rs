//! Cross-checks the self-contained parser against rustls' own `ECHConfigList`
//! encoder, which is what the Mavi VPN server uses to generate its config.

mod common;

use mavi_transport::ech::{EchConfigList, HpkeSymmetricSuite, ECH_VERSION};

#[test]
fn parses_config_generated_like_mavi_server() {
    let bytes = common::mavi_server_ech_config("cover.example.com");
    let parsed = EchConfigList::parse(&bytes).unwrap();
    assert_eq!(parsed.skipped(), 0);
    assert_eq!(parsed.outer_sni(), "cover.example.com");

    let config = &parsed.configs()[0];
    assert_eq!(config.config_id, 0);
    assert_eq!(config.kem_id, 0x0020);
    assert_eq!(config.public_key.len(), 32);
    assert_eq!(config.maximum_name_length, 64);
    assert_eq!(
        config.cipher_suites,
        vec![HpkeSymmetricSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001
        }]
    );

    // Byte layout sanity check: list length, then the RFC 9849 version.
    assert_eq!(
        usize::from(u16::from_be_bytes([bytes[0], bytes[1]])),
        bytes.len() - 2
    );
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), ECH_VERSION);
}

#[test]
fn hex_file_format_matches_binary() {
    let bytes = common::mavi_server_ech_config("cover.example.com");
    let hex: String = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(
        EchConfigList::from_hex(&format!("{hex}\n")).unwrap(),
        EchConfigList::parse(&bytes).unwrap()
    );
}
