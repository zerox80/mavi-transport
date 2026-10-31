//! SHA-256 certificate pinning for rustls clients.
//!
//! A pin is the SHA-256 digest of the server's DER-encoded end-entity
//! certificate. [`PinnedServerVerifier`] accepts a server if its certificate
//! matches any configured pin and the handshake signature verifies against
//! that certificate's key. Configuring two pins allows a certificate rotation
//! without breaking already deployed clients.
//!
//! Pinning replaces `WebPKI` validation entirely: the server name, the chain and
//! the validity period are not checked. That is the point for self-signed VPN
//! servers, and it is also why the pins must come from a trusted channel.

use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use constant_time_eq::constant_time_eq_32;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::hex;

#[cfg(test)]
mod tests;

/// Length of a pin in bytes (a SHA-256 digest).
pub const PIN_LEN: usize = 32;

/// SHA-256 fingerprint of a DER-encoded certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CertPin([u8; PIN_LEN]);

impl CertPin {
    /// Wraps a raw 32-byte digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PIN_LEN]) -> Self {
        Self(bytes)
    }

    /// Computes the pin of a DER-encoded certificate.
    #[must_use]
    pub fn of_certificate(cert_der: &[u8]) -> Self {
        Self(Sha256::digest(cert_der).into())
    }

    /// Returns the raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PIN_LEN] {
        &self.0
    }

    /// Returns `true` if `cert_der` hashes to this pin.
    #[must_use]
    pub fn matches(&self, cert_der: &[u8]) -> bool {
        matches_any(cert_der, std::slice::from_ref(self))
    }
}

impl TryFrom<&[u8]> for CertPin {
    type Error = PinError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; PIN_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| PinError::WrongLength {
                index: 0,
                len: bytes.len(),
            })
    }
}

impl FromStr for CertPin {
    type Err = PinError;

    /// Parses exactly 64 hex characters (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_one(s, 0)
    }
}

impl fmt::Display for CertPin {
    /// Formats the pin as 64 lowercase hex characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

impl fmt::Debug for CertPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertPin({self})")
    }
}

/// Why a pin or pin list was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PinError {
    /// No pin was configured. A verifier without pins would reject every
    /// server, so this is reported up front instead.
    #[error("no certificate pin configured")]
    Empty,
    /// A comma-separated list contained an empty entry.
    #[error("certificate pin #{index} is empty")]
    EmptyEntry {
        /// Zero-based position in the list.
        index: usize,
    },
    /// An entry was not valid hex.
    #[error("certificate pin #{index} is not valid hex")]
    InvalidHex {
        /// Zero-based position in the list.
        index: usize,
    },
    /// An entry did not decode to 32 bytes.
    #[error("certificate pin #{index} has {len} bytes, expected 32")]
    WrongLength {
        /// Zero-based position in the list.
        index: usize,
        /// Decoded length in bytes.
        len: usize,
    },
}

/// Parses one or more comma-separated hex pins, e.g. `"<old>,<new>"` during a
/// certificate rotation. Whitespace around entries is ignored.
///
/// Fails closed: an empty string, an empty entry or any malformed entry
/// rejects the whole list rather than silently dropping a pin.
///
/// # Errors
///
/// Returns a [`PinError`] naming the first offending entry.
pub fn parse_pins(s: &str) -> Result<Vec<CertPin>, PinError> {
    if s.trim().is_empty() {
        return Err(PinError::Empty);
    }
    s.split(',')
        .enumerate()
        .map(|(index, entry)| parse_one(entry.trim(), index))
        .collect()
}

fn parse_one(s: &str, index: usize) -> Result<CertPin, PinError> {
    if s.is_empty() {
        return Err(PinError::EmptyEntry { index });
    }
    let bytes = hex::decode(s).ok_or(PinError::InvalidHex { index })?;
    <[u8; PIN_LEN]>::try_from(bytes.as_slice())
        .map(CertPin)
        .map_err(|_| PinError::WrongLength {
            index,
            len: bytes.len(),
        })
}

/// Returns `true` if the SHA-256 digest of `cert_der` equals any of `pins`.
/// Each comparison runs in constant time.
#[must_use]
pub fn matches_any(cert_der: &[u8], pins: &[CertPin]) -> bool {
    let digest: [u8; PIN_LEN] = Sha256::digest(cert_der).into();
    // Fold instead of `any` so the work does not depend on which pin matched.
    pins.iter().fold(false, |found, pin| {
        constant_time_eq_32(&digest, &pin.0) | found
    })
}

/// Error reported by [`PinnedServerVerifier`] when no pin matches.
///
/// It reaches callers wrapped as
/// `rustls::Error::InvalidCertificate(CertificateError::Other(..))`; use
/// [`is_pin_mismatch`] to detect it.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Certificate PIN mismatch")]
pub struct PinMismatch;

impl fmt::Debug for PinMismatch {
    // rustls formats `CertificateError::Other` with `Debug`, so this keeps the
    // human-readable text in `rustls::Error`'s `Display` output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Returns `true` if `err` was produced by a [`PinnedServerVerifier`]
/// rejecting the server certificate.
#[must_use]
pub fn is_pin_mismatch(err: &rustls::Error) -> bool {
    matches!(
        err,
        rustls::Error::InvalidCertificate(CertificateError::Other(other))
            if other.0.downcast_ref::<PinMismatch>().is_some()
    )
}

/// rustls server certificate verifier that trusts only pinned certificates.
///
/// Handshake signatures are still verified against the presented certificate,
/// so a server must hold the private key of a pinned certificate.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pins: Vec<CertPin>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    /// Creates a verifier that checks handshake signatures with `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Empty`] if `pins` is empty.
    pub fn new(
        pins: Vec<CertPin>,
        algorithms: WebPkiSupportedAlgorithms,
    ) -> Result<Self, PinError> {
        if pins.is_empty() {
            return Err(PinError::Empty);
        }
        Ok(Self { pins, algorithms })
    }

    /// Creates a verifier using the signature algorithms of `provider`.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Empty`] if `pins` is empty.
    pub fn with_provider(pins: Vec<CertPin>, provider: &CryptoProvider) -> Result<Self, PinError> {
        Self::new(pins, provider.signature_verification_algorithms)
    }

    /// Creates a verifier backed by the aws-lc-rs provider.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Empty`] if `pins` is empty.
    #[cfg(feature = "aws-lc-rs")]
    pub fn with_aws_lc_rs(pins: Vec<CertPin>) -> Result<Self, PinError> {
        Self::with_provider(pins, &rustls::crypto::aws_lc_rs::default_provider())
    }

    /// Creates a verifier backed by the ring provider.
    ///
    /// # Errors
    ///
    /// Returns [`PinError::Empty`] if `pins` is empty.
    #[cfg(feature = "ring")]
    pub fn with_ring(pins: Vec<CertPin>) -> Result<Self, PinError> {
        Self::with_provider(pins, &rustls::crypto::ring::default_provider())
    }

    /// The configured pins.
    #[must_use]
    pub fn pins(&self) -> &[CertPin] {
        &self.pins
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if matches_any(end_entity.as_ref(), &self.pins) {
            Ok(ServerCertVerified::assertion())
        } else {
            let source: Arc<dyn StdError + Send + Sync> = Arc::new(PinMismatch);
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(source),
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
