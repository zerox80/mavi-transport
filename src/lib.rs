//! Reusable TLS client building blocks extracted from
//! [Mavi VPN](https://github.com/zerox80/mavi).
//!
//! - [`pin`]: SHA-256 certificate pinning with a rustls verifier and support
//!   for two pins during certificate rotation.
//! - [`ech`]: a provider-independent `ECHConfigList` parser and ECH GREASE
//!   setup, for a cover SNI and a `ClientHello` that looks like real ECH.
//! - [`tls`]: a builder that combines both into a rustls `ClientConfig` for
//!   QUIC or TLS over TCP.
//!
//! The crate does not pick a crypto provider. Enable `aws-lc-rs` or `ring` for
//! convenience constructors, or pass your own `CryptoProvider`.
//!
//! ```
//! # #[cfg(feature = "aws-lc-rs")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use mavi_transport::{ech::EchConfigList, pin, tls::PinnedClientConfig};
//!
//! # let pin_text = "aa".repeat(32);
//! # let ech_hex = "0044fe0d004007002000200000000000000000000000000000000000000000000000000000000000\
//! #                0000000004000100014011636f7665722e6578616d706c652e636f6d0000";
//! let pins = pin::parse_pins(&pin_text)?;
//! let ech = EchConfigList::from_hex(ech_hex)?;
//! let grease = ech.grease_aws_lc_rs().expect("server uses an aws-lc-rs HPKE suite");
//!
//! let config = PinnedClientConfig::aws_lc_rs(pins)
//!     .ech_grease(grease.config)
//!     .alpn(["h3"])
//!     .build()?;
//!
//! // Connect with `grease.outer_sni` as the server name.
//! assert_eq!(grease.outer_sni, "cover.example.com");
//! # let _ = config;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "aws-lc-rs"))]
//! # fn main() {}
//! ```

pub mod ech;
mod hex;
pub mod pin;
pub mod tls;

pub use ech::{EchConfigList, EchError, EchGrease};
pub use pin::{CertPin, PinError, PinnedServerVerifier};
pub use tls::{PinnedClientConfig, TlsConfigError};
