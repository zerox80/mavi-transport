//! End-to-end TLS handshakes between a `PinnedClientConfig` and a rustls
//! server with a self-signed certificate.

mod common;

use std::sync::Arc;

use common::{handshake, server, COVER_NAME, EXT_ECH, REAL_NAME};
use mavi_transport::ech::EchConfigList;
use mavi_transport::pin::{is_pin_mismatch, CertPin, PinError};
use mavi_transport::tls::{PinnedClientConfig, TlsConfigError};

fn aws_lc() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn tls13_server() -> common::TestServer {
    server(&[&rustls::version::TLS13])
}

#[test]
fn pinned_certificate_is_accepted() {
    let server = tls13_server();
    let pin = CertPin::of_certificate(&server.cert);
    let config = PinnedClientConfig::new(aws_lc(), vec![pin])
        .alpn(["h3"])
        .build()
        .unwrap();

    let outcome = handshake(config, &server, REAL_NAME);
    assert_eq!(outcome.result.unwrap(), Some(b"h3".to_vec()));
    assert_eq!(outcome.protocol, Some(rustls::ProtocolVersion::TLSv1_3));
}

#[test]
fn server_name_does_not_matter_when_pinned() {
    let server = tls13_server();
    let pin = CertPin::of_certificate(&server.cert);
    let config = PinnedClientConfig::new(aws_lc(), vec![pin])
        .build()
        .unwrap();
    assert!(handshake(config, &server, "unrelated.example.org")
        .result
        .is_ok());
}

#[test]
fn rotation_pair_accepts_either_certificate() {
    let server = tls13_server();
    let old = CertPin::from_bytes([0x11; 32]);
    let new = CertPin::of_certificate(&server.cert);
    let config = PinnedClientConfig::new(aws_lc(), vec![old, new])
        .build()
        .unwrap();
    assert!(handshake(config, &server, REAL_NAME).result.is_ok());
}

#[test]
fn unpinned_certificate_is_rejected() {
    let server = tls13_server();
    let config = PinnedClientConfig::new(aws_lc(), vec![CertPin::from_bytes([0; 32])])
        .build()
        .unwrap();
    let err = handshake(config, &server, REAL_NAME).result.unwrap_err();
    assert!(is_pin_mismatch(&err), "unexpected error: {err:?}");
}

#[test]
fn ring_client_works_without_ech() {
    let server = tls13_server();
    let pin = CertPin::of_certificate(&server.cert);
    let ring = Arc::new(rustls::crypto::ring::default_provider());
    let config = PinnedClientConfig::new(ring, vec![pin]).build().unwrap();
    assert!(handshake(config, &server, REAL_NAME).result.is_ok());
}

#[test]
fn ech_grease_hides_real_name_and_still_connects() {
    let server = tls13_server();
    let pin = CertPin::of_certificate(&server.cert);
    let ech = EchConfigList::parse(&common::mavi_server_ech_config(COVER_NAME)).unwrap();
    let grease = ech
        .grease(rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
        .unwrap();
    assert_eq!(grease.outer_sni, COVER_NAME);

    let config = PinnedClientConfig::new(aws_lc(), vec![pin])
        .ech_grease(grease.config)
        .alpn(["h3"])
        .build()
        .unwrap();
    let outcome = handshake(config, &server, &grease.outer_sni);

    let types: Vec<u16> = common::client_hello_extensions(&outcome.client_hello)
        .iter()
        .map(|(ty, _)| *ty)
        .collect();
    assert!(
        types.contains(&EXT_ECH),
        "missing ECH extension: {types:x?}"
    );
    assert_eq!(
        common::sni(&outcome.client_hello).as_deref(),
        Some(COVER_NAME)
    );
    assert!(!contains(&outcome.client_hello, REAL_NAME.as_bytes()));
    assert_eq!(outcome.result.unwrap(), Some(b"h3".to_vec()));
}

#[test]
fn no_ech_extension_without_grease() {
    let server = tls13_server();
    let pin = CertPin::of_certificate(&server.cert);
    let config = PinnedClientConfig::new(aws_lc(), vec![pin])
        .build()
        .unwrap();
    let outcome = handshake(config, &server, REAL_NAME);
    let extensions = common::client_hello_extensions(&outcome.client_hello);
    assert!(extensions.iter().all(|(ty, _)| *ty != EXT_ECH));
    assert_eq!(
        common::sni(&outcome.client_hello).as_deref(),
        Some(REAL_NAME)
    );
}

#[test]
fn empty_pin_list_is_a_config_error() {
    let err = PinnedClientConfig::new(aws_lc(), Vec::new())
        .build()
        .unwrap_err();
    assert!(
        matches!(err, TlsConfigError::Pin(PinError::Empty)),
        "{err:?}"
    );
}

#[cfg(feature = "tls12")]
#[test]
fn tls12_can_be_allowed_for_tcp_transports() {
    let server = server(&[&rustls::version::TLS12]);
    let pin = CertPin::of_certificate(&server.cert);

    let strict = PinnedClientConfig::new(aws_lc(), vec![pin])
        .build()
        .unwrap();
    assert!(handshake(strict, &server, REAL_NAME).result.is_err());

    let relaxed = PinnedClientConfig::new(aws_lc(), vec![pin])
        .allow_tls12()
        .alpn(["h2"])
        .build()
        .unwrap();
    let outcome = handshake(relaxed, &server, REAL_NAME);
    assert_eq!(outcome.result.unwrap(), Some(b"h2".to_vec()));
    assert_eq!(outcome.protocol, Some(rustls::ProtocolVersion::TLSv1_2));
}

#[cfg(feature = "tls12")]
#[test]
fn ech_and_tls12_are_mutually_exclusive() {
    let ech = EchConfigList::parse(&common::mavi_server_ech_config(COVER_NAME)).unwrap();
    let grease = ech
        .grease(rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
        .unwrap();
    let err = PinnedClientConfig::new(aws_lc(), vec![CertPin::from_bytes([1; 32])])
        .ech_grease(grease.config)
        .allow_tls12()
        .build()
        .unwrap_err();
    assert!(matches!(err, TlsConfigError::EchRequiresTls13), "{err:?}");
}

#[cfg(all(feature = "aws-lc-rs", feature = "ring"))]
#[test]
fn convenience_constructors_build() {
    let pin = CertPin::from_bytes([1; 32]);
    assert!(PinnedClientConfig::aws_lc_rs(vec![pin]).build().is_ok());
    assert!(PinnedClientConfig::ring(vec![pin]).build().is_ok());
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
