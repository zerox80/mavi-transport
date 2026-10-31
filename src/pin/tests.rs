use super::*;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

const CERT: &[u8] = b"dummy certificate";

fn pin_of(byte: u8) -> CertPin {
    CertPin::from_bytes([byte; PIN_LEN])
}

fn verify(
    verifier: &PinnedServerVerifier,
    cert: &[u8],
) -> Result<ServerCertVerified, rustls::Error> {
    let end_entity = CertificateDer::from(cert);
    let server_name = ServerName::try_from("example.com").unwrap();
    verifier.verify_server_cert(&end_entity, &[], &server_name, &[], UnixTime::now())
}

fn verifier(pins: Vec<CertPin>) -> PinnedServerVerifier {
    PinnedServerVerifier::with_provider(pins, &rustls::crypto::aws_lc_rs::default_provider())
        .unwrap()
}

#[test]
fn pin_of_certificate_is_sha256() {
    let expected: [u8; PIN_LEN] = Sha256::digest(CERT).into();
    assert_eq!(CertPin::of_certificate(CERT).as_bytes(), &expected);
    assert!(CertPin::of_certificate(CERT).matches(CERT));
    assert!(!pin_of(0).matches(CERT));
}

#[test]
fn display_and_from_str_roundtrip() {
    let pin = CertPin::of_certificate(CERT);
    let text = pin.to_string();
    assert_eq!(text.len(), 64);
    assert_eq!(text, text.to_lowercase());
    assert_eq!(text.parse::<CertPin>().unwrap(), pin);
    assert_eq!(text.to_uppercase().parse::<CertPin>().unwrap(), pin);
    assert_eq!(format!("{pin:?}"), format!("CertPin({text})"));
}

#[test]
fn from_str_rejects_bad_input() {
    assert_eq!(
        "".parse::<CertPin>(),
        Err(PinError::EmptyEntry { index: 0 })
    );
    assert_eq!(
        "zz".parse::<CertPin>(),
        Err(PinError::InvalidHex { index: 0 })
    );
    assert_eq!(
        "+f".repeat(32).parse::<CertPin>(),
        Err(PinError::InvalidHex { index: 0 })
    );
    assert_eq!(
        "aa".repeat(31).parse::<CertPin>(),
        Err(PinError::WrongLength { index: 0, len: 31 })
    );
}

#[test]
fn try_from_slice_checks_length() {
    assert_eq!(CertPin::try_from(&[7u8; 32][..]), Ok(pin_of(7)));
    assert_eq!(
        CertPin::try_from(&[7u8; 33][..]),
        Err(PinError::WrongLength { index: 0, len: 33 })
    );
}

#[test]
fn parse_pins_single_and_rotation_pair() {
    let a = pin_of(0xaa);
    let b = pin_of(0xbb);
    assert_eq!(parse_pins(&a.to_string()), Ok(vec![a]));
    assert_eq!(parse_pins(&format!("{a},{b}")), Ok(vec![a, b]));
    assert_eq!(parse_pins(&format!(" {a} , {b} ")), Ok(vec![a, b]));
}

#[test]
fn parse_pins_fails_closed() {
    let a = pin_of(0xaa);
    assert_eq!(parse_pins(""), Err(PinError::Empty));
    assert_eq!(parse_pins("  "), Err(PinError::Empty));
    assert_eq!(
        parse_pins(&format!("{a},")),
        Err(PinError::EmptyEntry { index: 1 })
    );
    assert_eq!(
        parse_pins(&format!(",{a}")),
        Err(PinError::EmptyEntry { index: 0 })
    );
    assert_eq!(
        parse_pins(&format!("{a},,{a}")),
        Err(PinError::EmptyEntry { index: 1 })
    );
    assert_eq!(
        parse_pins(&format!("{a},{}", "zz".repeat(32))),
        Err(PinError::InvalidHex { index: 1 })
    );
    assert_eq!(
        parse_pins(&format!("{a},abcd")),
        Err(PinError::WrongLength { index: 1, len: 2 })
    );
}

#[test]
fn matches_any_handles_rotation_lists() {
    let good = CertPin::of_certificate(CERT);
    assert!(matches_any(CERT, &[good]));
    assert!(matches_any(CERT, &[pin_of(0), good]));
    assert!(matches_any(CERT, &[good, pin_of(0)]));
    assert!(!matches_any(CERT, &[pin_of(0), pin_of(1)]));
    assert!(!matches_any(CERT, &[]));
}

#[test]
fn verifier_requires_at_least_one_pin() {
    let err = PinnedServerVerifier::with_provider(
        Vec::new(),
        &rustls::crypto::aws_lc_rs::default_provider(),
    )
    .unwrap_err();
    assert_eq!(err, PinError::Empty);
}

#[test]
fn verifier_accepts_any_matching_pin() {
    let good = CertPin::of_certificate(CERT);
    assert!(verify(&verifier(vec![good]), CERT).is_ok());
    assert!(verify(&verifier(vec![pin_of(0), good]), CERT).is_ok());
}

#[test]
fn verifier_rejects_unpinned_certificate() {
    let err = verify(&verifier(vec![pin_of(0), pin_of(1)]), CERT).unwrap_err();
    assert!(is_pin_mismatch(&err), "unexpected error: {err:?}");
    assert!(
        err.to_string().contains("Certificate PIN mismatch"),
        "{err}"
    );
}

#[test]
fn is_pin_mismatch_ignores_other_errors() {
    assert!(!is_pin_mismatch(&rustls::Error::General("other".into())));
    assert!(!is_pin_mismatch(&rustls::Error::InvalidCertificate(
        CertificateError::Expired
    )));
}

#[test]
fn verifier_uses_provider_schemes() {
    let ring = rustls::crypto::ring::default_provider();
    let v = PinnedServerVerifier::with_provider(vec![pin_of(1)], &ring).unwrap();
    assert_eq!(
        v.supported_verify_schemes(),
        ring.signature_verification_algorithms.supported_schemes()
    );
    assert_eq!(v.pins(), &[pin_of(1)]);
}

proptest::proptest! {
    #[test]
    fn parse_pins_never_panics(s in "\\PC*") {
        let _ = parse_pins(&s);
    }

    #[test]
    fn parse_pins_roundtrips(raw in proptest::collection::vec(proptest::array::uniform32(proptest::num::u8::ANY), 1..4)) {
        let pins: Vec<CertPin> = raw.into_iter().map(CertPin::from_bytes).collect();
        let text = pins.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        proptest::prop_assert_eq!(parse_pins(&text), Ok(pins));
    }
}
