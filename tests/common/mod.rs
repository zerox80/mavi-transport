//! Shared helpers: self-signed server, in-memory handshake, `ClientHello`
//! inspection and a Mavi-server-style `ECHConfigList`.

#![allow(dead_code)]

use std::sync::Arc;

use rustls::crypto::hpke::Hpke;
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
};
use rustls::pki_types::{CertificateDer, DnsName, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};

pub const REAL_NAME: &str = "vpn.internal.example";
pub const COVER_NAME: &str = "cover.example.com";
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_ECH: u16 = 0xfe0d;

pub struct TestServer {
    pub cert: CertificateDer<'static>,
    pub config: Arc<ServerConfig>,
}

pub fn server(versions: &[&'static rustls::SupportedProtocolVersion]) -> TestServer {
    let generated = rcgen::generate_simple_self_signed(vec![REAL_NAME.to_owned()]).unwrap();
    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec()];
    TestServer {
        cert,
        config: Arc::new(config),
    }
}

pub struct Outcome {
    /// Raw TLS records of the client's first flight.
    pub client_hello: Vec<u8>,
    /// Negotiated ALPN on success, or the first error from either side.
    pub result: Result<Option<Vec<u8>>, rustls::Error>,
    pub protocol: Option<rustls::ProtocolVersion>,
}

pub fn handshake(client: ClientConfig, server: &TestServer, server_name: &str) -> Outcome {
    let name = ServerName::try_from(server_name.to_owned()).unwrap();
    let mut client = Connection::Client(ClientConnection::new(Arc::new(client), name).unwrap());
    let mut server = Connection::Server(ServerConnection::new(server.config.clone()).unwrap());

    let mut client_hello = Vec::new();
    for round in 0..10 {
        let sent = match transfer(&mut client, &mut server) {
            Ok(sent) => sent,
            Err(e) => return failed(client_hello, e),
        };
        if round == 0 {
            client_hello = sent;
        }
        if let Err(e) = transfer(&mut server, &mut client) {
            return failed(client_hello, e);
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return Outcome {
                client_hello,
                result: Ok(client.alpn_protocol().map(<[u8]>::to_vec)),
                protocol: client.protocol_version(),
            };
        }
    }
    panic!("handshake did not finish");
}

fn failed(client_hello: Vec<u8>, err: rustls::Error) -> Outcome {
    Outcome {
        client_hello,
        result: Err(err),
        protocol: None,
    }
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<Vec<u8>, rustls::Error> {
    let mut buf = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buf).unwrap();
    }
    let mut rest = &buf[..];
    while !rest.is_empty() {
        to.read_tls(&mut rest).unwrap();
        to.process_new_packets()?;
    }
    Ok(buf)
}

/// Extensions of the first `ClientHello` in `records`: `(type, data)`.
pub fn client_hello_extensions(records: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut r = records;
    let take = |r: &mut &[u8], n: usize| -> Vec<u8> {
        let (head, tail) = r.split_at(n);
        *r = tail;
        head.to_vec()
    };
    let u16_of = |b: Vec<u8>| u16::from_be_bytes([b[0], b[1]]);

    assert_eq!(take(&mut r, 1), [0x16], "handshake record");
    take(&mut r, 2);
    let record_len = usize::from(u16_of(take(&mut r, 2)));
    let mut h = &r[..record_len];
    assert_eq!(take(&mut h, 1), [0x01], "ClientHello");
    take(&mut h, 3 + 2 + 32);
    let sid = usize::from(take(&mut h, 1)[0]);
    take(&mut h, sid);
    let suites = usize::from(u16_of(take(&mut h, 2)));
    take(&mut h, suites);
    let compression = usize::from(take(&mut h, 1)[0]);
    take(&mut h, compression);
    let ext_len = usize::from(u16_of(take(&mut h, 2)));
    let mut e = &h[..ext_len];
    let mut out = Vec::new();
    while !e.is_empty() {
        let ty = u16_of(take(&mut e, 2));
        let len = usize::from(u16_of(take(&mut e, 2)));
        out.push((ty, take(&mut e, len)));
    }
    out
}

/// Host name from the `server_name` extension, if present.
pub fn sni(records: &[u8]) -> Option<String> {
    let (_, data) = client_hello_extensions(records)
        .into_iter()
        .find(|(ty, _)| *ty == EXT_SERVER_NAME)?;
    // list len (2) | name type (1) | name len (2) | name
    Some(String::from_utf8(data[5..].to_vec()).unwrap())
}

/// Builds an `ECHConfigList` exactly like the Mavi VPN server (`backend/src/ech.rs`),
/// with a fresh X25519 HPKE key, using rustls' own encoder.
pub fn mavi_server_ech_config(public_name: &str) -> Vec<u8> {
    let hpke: &dyn Hpke = rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public_key, _private_key) = hpke.generate_key_pair().unwrap();
    let contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id: 0,
            kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            public_key: PayloadU16::new(public_key.0),
            symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            }],
        },
        maximum_name_length: 64,
        public_name: DnsName::try_from(public_name).unwrap().to_owned(),
        extensions: Vec::new(),
    };
    let mut bytes = Vec::new();
    vec![EchConfigPayload::V18(contents)].encode(&mut bytes);
    bytes
}
