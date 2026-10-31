# mavi-transport

TLS client building blocks for VPN and tunnel clients built on [rustls](https://github.com/rustls/rustls), extracted from [Mavi VPN](https://github.com/zerox80/mavi).

> **Status:** early release. The API may still change before 1.0, and nothing is published on crates.io yet.

## What it does

| Module | Purpose |
|---|---|
| `pin` | SHA-256 certificate pinning: a rustls `ServerCertVerifier` that trusts only pinned certificates, with support for two pins during a certificate rotation |
| `ech` | A self-contained `ECHConfigList` parser (RFC 9849) and ECH GREASE setup, for a cover SNI and a `ClientHello` that looks like a real ECH client |
| `tls` | `PinnedClientConfig`, a builder that combines both into a rustls `ClientConfig` usable with QUIC (quinn) or TLS over TCP |

The Linux, Windows and Android clients of Mavi VPN each carried their own copy of this code. This crate is the single, tested version they and other projects can share.

## Usage

```toml
[dependencies]
mavi-transport = { git = "https://github.com/zerox80/mavi-transport", features = ["aws-lc-rs"] }
```

```rust
use mavi_transport::{ech::EchConfigList, pin, tls::PinnedClientConfig};

// "<pin>" or "<old_pin>,<new_pin>" during a rotation.
let pins = pin::parse_pins(cert_pin_text)?;

// Hex ECHConfigList, e.g. the Mavi server's ech_config_hex.txt.
let ech = EchConfigList::from_hex(ech_config_hex)?;
let grease = ech.grease_aws_lc_rs().expect("server uses a supported HPKE suite");

let tls = PinnedClientConfig::aws_lc_rs(pins)
    .ech_grease(grease.config)
    .alpn(["h3"])
    .build()?;

// Use grease.outer_sni as the server name so the cover name is what goes on the wire.
```

Without ECH, skip `ech_grease` and connect with any server name: the pin, not the name, authenticates the server.

## Crate features

| Feature | Effect |
|---|---|
| `aws-lc-rs` | Convenience constructors using the aws-lc-rs provider, including its HPKE suites for ECH GREASE |
| `ring` | Convenience constructors using the ring provider. ring has no HPKE in rustls 0.23, so only the cover SNI is available, not GREASE |
| `tls12` | `PinnedClientConfig::allow_tls12()` for TLS-over-TCP transports. Cannot be combined with ECH |

No feature is enabled by default. Everything also works with your own `CryptoProvider` through `PinnedClientConfig::new` and `EchConfigList::grease`.

## Design notes

- **Pinning replaces WebPKI validation.** The server name, chain and validity period are not checked; the server must present a pinned certificate and prove possession of its key in the handshake. Pins must come from a trusted channel.
- **Pins fail closed.** An empty list, an empty entry or a malformed entry rejects the whole configuration instead of silently dropping a pin. Comparisons run in constant time.
- **Pin mismatches are typed.** The verifier returns `rustls::Error::InvalidCertificate`, and `pin::is_pin_mismatch` tells it apart from other TLS errors.
- **ECH here is camouflage, not confidentiality.** rustls 0.23 cannot accept ECH on the server, so the inner `ClientHello` is never decrypted. GREASE makes the `ClientHello` look like ECH and the outer SNI shows only the cover name.
- **No `rustls::internal`.** The `ECHConfigList` parser is independent of rustls internals and of the crypto provider. Following RFC 9849, entries with unknown versions, invalid `public_name` values or unknown mandatory extensions are skipped; broken framing is an error.

## Testing

```sh
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

The tests include real in-memory TLS handshakes against a rustls server, a check that the GREASE `ClientHello` carries the ECH extension and the cover SNI but not the real server name, a cross-check against the `ECHConfigList` encoder used by the Mavi VPN server, and property tests that the parsers never panic. The minimum supported Rust version is 1.95.

## Roadmap

- Move the HTTP/3 MASQUE CONNECT-IP and HTTP/2 CONNECT-IP client framing into this crate
- Switch the Mavi VPN clients to this crate
- Fuzzing targets for the parsers
- Full ECH (`EchMode::Enable`) once rustls supports it on the server

## Security

This code has not been independently security-audited. Do not rely on it for high-risk use cases. Report vulnerabilities as described in the [Mavi VPN security policy](https://github.com/zerox80/mavi/blob/main/SECURITY.md).

## License

[MIT](LICENSE)
