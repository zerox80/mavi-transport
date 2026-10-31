//! `ECHConfigList` parsing (RFC 9849, section 4) and ECH GREASE setup.
//!
//! A server publishes an `ECHConfigList` out of band. A client can use it to
//!
//! - send the config's `public_name` as the outer SNI (the "cover" name), and
//! - offer an ECH GREASE extension that mimics the server's HPKE suite and
//!   key length, so the `ClientHello` looks like a real ECH client.
//!
//! This is camouflage, not ECH confidentiality: rustls 0.23 cannot accept ECH
//! on the server side, so the inner `ClientHello` is never decrypted. It works
//! best combined with [`crate::pin`], because a pinning client does not need
//! the SNI to match the certificate.
//!
//! The parser is self-contained and does not rely on `rustls::internal`, so it
//! works with every crypto provider. Entries a client must ignore per RFC 9849
//! (unknown versions, invalid `public_name`, unknown mandatory extensions) are
//! skipped; structurally broken input is rejected.

use rustls::client::EchGreaseConfig;
use rustls::crypto::hpke::{Hpke, HpkePublicKey};

use crate::hex;

mod parse;
#[cfg(test)]
mod tests;

/// The only `ECHConfig` version this crate understands (RFC 9849).
pub const ECH_VERSION: u16 = 0xfe0d;

/// HPKE KDF and AEAD identifiers (RFC 9180, section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HpkeSymmetricSuite {
    /// KDF identifier, e.g. `0x0001` for HKDF-SHA256.
    pub kdf_id: u16,
    /// AEAD identifier, e.g. `0x0001` for AES-128-GCM.
    pub aead_id: u16,
}

/// One usable `ECHConfig` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct EchConfig {
    /// Server-chosen identifier for this config.
    pub config_id: u8,
    /// HPKE KEM identifier, e.g. `0x0020` for DHKEM(X25519, HKDF-SHA256).
    pub kem_id: u16,
    /// Encoded HPKE public key.
    pub public_key: Vec<u8>,
    /// Supported HPKE symmetric suites, in server preference order.
    pub cipher_suites: Vec<HpkeSymmetricSuite>,
    /// Largest inner server name the server expects, used for padding.
    pub maximum_name_length: u8,
    /// DNS name of the client-facing server, used as the outer SNI.
    pub public_name: String,
}

impl EchConfig {
    /// Builds an ECH GREASE config from the first of this config's suites that
    /// one of `suites` implements. Returns `None` if none is supported.
    #[must_use]
    pub fn grease_config(&self, suites: &[&'static dyn Hpke]) -> Option<EchGreaseConfig> {
        self.cipher_suites.iter().find_map(|wanted| {
            suites.iter().find_map(|hpke| {
                let s = hpke.suite();
                let supported = u16::from(s.kem) == self.kem_id
                    && u16::from(s.sym.kdf_id) == wanted.kdf_id
                    && u16::from(s.sym.aead_id) == wanted.aead_id;
                supported
                    .then(|| EchGreaseConfig::new(*hpke, HpkePublicKey(self.public_key.clone())))
            })
        })
    }
}

/// A parsed `ECHConfigList` with at least one usable entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchConfigList {
    configs: Vec<EchConfig>,
    skipped: usize,
}

/// Outer SNI plus GREASE config selected from an [`EchConfigList`].
#[derive(Clone, Debug)]
pub struct EchGrease {
    /// Name to connect to, so it appears as the SNI on the wire.
    pub outer_sni: String,
    /// Pass to `rustls::client::EchMode::Grease`.
    pub config: EchGreaseConfig,
}

/// Why an `ECHConfigList` was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EchError {
    /// The hex form contained non-hex characters or had odd length.
    #[error("ECHConfigList is not valid hex")]
    InvalidHex,
    /// The input ended in the middle of a field.
    #[error("ECHConfigList is truncated")]
    Truncated,
    /// A length field or value violates the wire format.
    #[error("malformed ECHConfigList: {0}")]
    Malformed(&'static str),
    /// The list parsed, but every entry had to be ignored.
    #[error("ECHConfigList has no supported entry ({skipped} ignored)")]
    NoSupportedConfig {
        /// Number of ignored entries.
        skipped: usize,
    },
}

impl EchConfigList {
    /// Parses a binary `ECHConfigList`.
    ///
    /// # Errors
    ///
    /// Returns an [`EchError`] if the input is malformed or contains no entry
    /// a client may use.
    pub fn parse(bytes: &[u8]) -> Result<Self, EchError> {
        let (configs, skipped) = parse::config_list(bytes)?;
        if configs.is_empty() {
            return Err(EchError::NoSupportedConfig { skipped });
        }
        Ok(Self { configs, skipped })
    }

    /// Parses a hex-encoded `ECHConfigList`, as written to
    /// `ech_config_hex.txt` by the Mavi VPN server. Surrounding whitespace is
    /// ignored.
    ///
    /// # Errors
    ///
    /// Same as [`EchConfigList::parse`], plus [`EchError::InvalidHex`].
    pub fn from_hex(s: &str) -> Result<Self, EchError> {
        Self::parse(&hex::decode(s.trim()).ok_or(EchError::InvalidHex)?)
    }

    /// Usable entries, in list order. Never empty.
    #[must_use]
    pub fn configs(&self) -> &[EchConfig] {
        &self.configs
    }

    /// Number of entries that were ignored while parsing.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// `public_name` of the first usable entry. Works with any crypto
    /// provider, including ring, which cannot do ECH GREASE.
    #[must_use]
    pub fn outer_sni(&self) -> &str {
        &self.configs[0].public_name
    }

    /// Picks the first entry and suite that one of `suites` implements and
    /// returns its outer SNI and GREASE config.
    #[must_use]
    pub fn grease(&self, suites: &[&'static dyn Hpke]) -> Option<EchGrease> {
        self.configs.iter().find_map(|config| {
            config.grease_config(suites).map(|grease| EchGrease {
                outer_sni: config.public_name.clone(),
                config: grease,
            })
        })
    }

    /// [`EchConfigList::grease`] with the HPKE suites of aws-lc-rs.
    #[cfg(feature = "aws-lc-rs")]
    #[must_use]
    pub fn grease_aws_lc_rs(&self) -> Option<EchGrease> {
        self.grease(rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
    }
}

impl std::str::FromStr for EchConfigList {
    type Err = EchError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}
