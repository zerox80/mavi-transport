//! One-stop builder for a pinned rustls [`ClientConfig`], optionally with ECH
//! GREASE. The resulting config works for QUIC (via `quinn`) and TLS over TCP.

use std::sync::Arc;

use rustls::client::{EchGreaseConfig, EchMode};
use rustls::crypto::CryptoProvider;
use rustls::ClientConfig;

use crate::pin::{CertPin, PinError, PinnedServerVerifier};

/// Why a [`PinnedClientConfig`] could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsConfigError {
    /// The pin list was rejected.
    #[error(transparent)]
    Pin(#[from] PinError),
    /// ECH GREASE was combined with TLS 1.2, which ECH does not support.
    #[error("ECH requires TLS 1.3, but TLS 1.2 was allowed")]
    EchRequiresTls13,
    /// rustls rejected the configuration, e.g. because the provider lacks
    /// TLS 1.3 cipher suites.
    #[error("rustls rejected the client configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Builder for a TLS client config that trusts only pinned certificates.
///
/// TLS 1.3 only by default. Set the server name used for the connection to
/// [`EchGrease::outer_sni`](crate::ech::EchGrease::outer_sni) when ECH GREASE
/// is enabled, so the cover name is what appears on the wire.
#[derive(Debug)]
#[must_use]
pub struct PinnedClientConfig {
    provider: Arc<CryptoProvider>,
    pins: Vec<CertPin>,
    ech: Option<EchGreaseConfig>,
    allow_tls12: bool,
    alpn: Vec<Vec<u8>>,
}

impl PinnedClientConfig {
    /// Starts a config for `provider` that trusts `pins`.
    pub fn new(provider: Arc<CryptoProvider>, pins: Vec<CertPin>) -> Self {
        Self {
            provider,
            pins,
            ech: None,
            allow_tls12: false,
            alpn: Vec::new(),
        }
    }

    /// Starts a config backed by the aws-lc-rs provider.
    #[cfg(feature = "aws-lc-rs")]
    pub fn aws_lc_rs(pins: Vec<CertPin>) -> Self {
        Self::new(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            pins,
        )
    }

    /// Starts a config backed by the ring provider (no ECH GREASE).
    #[cfg(feature = "ring")]
    pub fn ring(pins: Vec<CertPin>) -> Self {
        Self::new(Arc::new(rustls::crypto::ring::default_provider()), pins)
    }

    /// Offers ECH GREASE, see [`crate::ech`].
    pub fn ech_grease(mut self, config: EchGreaseConfig) -> Self {
        self.ech = Some(config);
        self
    }

    /// Also allows TLS 1.2, e.g. for HTTP/2 over TCP to older middleboxes.
    /// Cannot be combined with ECH GREASE.
    #[cfg(feature = "tls12")]
    pub fn allow_tls12(mut self) -> Self {
        self.allow_tls12 = true;
        self
    }

    /// Sets the ALPN protocols to offer, in preference order.
    pub fn alpn<I, P>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        self.alpn = protocols.into_iter().map(|p| p.as_ref().to_vec()).collect();
        self
    }

    /// Builds the config.
    ///
    /// # Errors
    ///
    /// See [`TlsConfigError`].
    pub fn build(self) -> Result<ClientConfig, TlsConfigError> {
        let verifier = Arc::new(PinnedServerVerifier::with_provider(
            self.pins,
            &self.provider,
        )?);
        let builder = ClientConfig::builder_with_provider(self.provider);
        let builder = match self.ech {
            Some(_) if self.allow_tls12 => return Err(TlsConfigError::EchRequiresTls13),
            // `with_ech` restricts the config to TLS 1.3 by itself.
            Some(grease) => builder.with_ech(EchMode::Grease(grease))?,
            None => builder.with_protocol_versions(protocol_versions(self.allow_tls12))?,
        };
        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = self.alpn;
        Ok(config)
    }
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

#[cfg(feature = "tls12")]
static TLS13_AND_TLS12: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

fn protocol_versions(allow_tls12: bool) -> &'static [&'static rustls::SupportedProtocolVersion] {
    #[cfg(feature = "tls12")]
    if allow_tls12 {
        return TLS13_AND_TLS12;
    }
    let _ = allow_tls12;
    TLS13_ONLY
}
