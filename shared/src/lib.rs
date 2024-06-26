use std::{
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

use num_enum::TryFromPrimitive;

/// Magic number for the default port.
pub const DEFAULT_PORT: NonZeroU16 = unsafe { std::num::NonZeroU16::new_unchecked(7828) };

/// Define a sane maximum payload size for the client-server messages.
pub const MAX_SERVER_COMMUNICATION_SIZE: usize = 1024;

/// Using SHA-256 for the hash; i.e., a 256 bit / 8 byte hash.
pub const HASH_BYTE_COUNT: usize = 32;

/// A block of raw SHA-256 bytes.
pub type HashBytes = [u8; HASH_BYTE_COUNT];

/// The maximum number of seconds of inactivity before a QUIC connection is closed.
/// Same for both the server and the client.
pub const QUIC_TIMEOUT_SECONDS: u64 = 120;

/// Code sent on a graceful disconnect.
pub const GOODBYE_CODE: quinn::VarInt = quinn::VarInt::from_u32(0);

/// Optional polite message on a graceful disconnect.
pub const GOODBYE_MESSAGE: &str = "Goodbye!";

/// A helper to access often used socket address info.
pub struct SocketAddrHelper {
    pub address: SocketAddr,
    pub hostname: String,
}

/// The type of API requests that can be made by clients.
/// Sent as a `u16` in QUIC requests to the server.
#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum ClientApiRequest {
    /// A ping request for the server to respond with the socket address they see the client as.
    SocketPing,

    /// A request specifying which port the server will direct peers to connect to.
    PortOverride,

    /// Specify a file hash that this client wants to publish.
    Publish,

    /// Specify a file hash that this client wants to subscribe to.
    Subscribe,

    /// Request to be introduced to a specific peer over a certain file hash.
    Introduction,
}
impl std::fmt::Display for ClientApiRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ClientApiRequest::SocketPing => "SOCKET_PING  ",
            ClientApiRequest::PortOverride => "PORT_OVERRIDE",
            ClientApiRequest::Publish => "PUBLISH      ",
            ClientApiRequest::Subscribe => "SUBSCRIBE    ",
            ClientApiRequest::Introduction => "INTRODUCTION ",
        };
        write!(f, "REQ: {str}")
    }
}

/// Helper to get either the socket address corresponding to the user's input, or the default of IPv4 localhost.
///
/// # Errors
/// If there is `Some(..)` non-empty server address, then it must be of the format `hostname:port`
/// to be able to parse into a socket address using `ToSocketAddrs`. If the address cannot be parsed, it will
/// fail with a `std::io::Error` instead of using the default.
pub fn get_server_or_default(
    server_address: Option<&str>,
    port: NonZeroU16,
) -> Result<SocketAddrHelper, std::io::Error> {
    // Parse the server address if one was specified.
    server_address
        .iter()
        .find_map(|&s| {
            if s.is_empty() {
                None
            } else {
                match (s, port.get()).to_socket_addrs() {
                    Ok(mut addrs) => addrs.next().map(|address| {
                        Ok(SocketAddrHelper {
                            address,
                            hostname: s.to_string(),
                        })
                    }),
                    Err(e) => Some(Err(e)),
                }
            }
        })
        .unwrap_or_else(|| {
            Ok(SocketAddrHelper {
                address: (Ipv4Addr::LOCALHOST, port.get()).into(),
                hostname: Ipv4Addr::LOCALHOST.to_string(),
            })
        })
}

/// Get the current local time in a human-readable, fixed length format.
#[must_use]
pub fn local_now_fmt() -> chrono::format::DelayedFormat<chrono::format::StrftimeItems<'static>> {
    // E.g., "2024-02-06 22:01:04.913"
    chrono::Local::now().format("%F %T%.3f")
}

/// Helper type for grouping a bi-directional stream, instead of the default tuple type.
#[derive(Debug)]
pub struct BiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}
impl From<(quinn::SendStream, quinn::RecvStream)> for BiStream {
    fn from((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self { send, recv }
    }
}

/// Set reasonable transport config defaults for the server as well as peers when receiving connections.
/// # Panics
/// If the conversion from `Duration` to `IdleTimeout` of the max idle timeout fails.
#[must_use]
pub fn server_transport_config() -> Arc<quinn::TransportConfig> {
    // Set custom keep alive policies.
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(QUIC_TIMEOUT_SECONDS)
            .try_into()
            .unwrap(),
    ));
    transport_config.keep_alive_interval(Some(Duration::from_secs(30)));
    Arc::new(transport_config)
}

/// Generate a self-signed certificate for use with QUIC.
/// # Errors
/// Fails if `rcgen` fails to generate a certificate or if `rustls` fails to parse the resulting certificate.
pub fn generate_self_signed_cert() -> anyhow::Result<(rustls::Certificate, rustls::PrivateKey)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let key = rustls::PrivateKey(cert.serialize_private_key_der());
    Ok((rustls::Certificate(cert.serialize_der()?), key))
}

// // Rustls 0.22.0 version of the above
// impl rustls::client::dangerous::ServerCertVerifier for SkipAllServerVerification {

//     /// Implementation of a verifier that does not verify the server certificate.
//     fn verify_server_cert(
//         &self,
//         _end_entity: &CertificateDer<'_>,
//         _intermediates: &[CertificateDer<'_>],
//         _server_name: &rustls::pki_types::ServerName<'_>,
//         _ocsp_response: &[u8],
//         _now: rustls::pki_types::UnixTime,
//     ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
//         Ok(rustls::client::danger::ServerCertVerified::assertion())
//     }

//     // Even when skipping validation, DJB reigns supreme.
//     fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
//         vec![rustls::SignatureScheme::ED25519]
//     }

//     fn verify_tls12_signature(
//         &self,
//         _message: &[u8],
//         _cert: &CertificateDer<'_>,
//         _dss: &rustls::DigitallySignedStruct,
//     ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
//         Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
//     }

//     fn verify_tls13_signature(
//         &self,
//         _message: &[u8],
//         _cert: &CertificateDer<'_>,
//         _dss: &rustls::DigitallySignedStruct,
//     ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
//         Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
//     }
// }

// /// Build a QUIC client config that will skip server verification.
// pub fn configure_peer_verification() -> rustls::ClientConfig {
//     rustls::ClientConfig::builder().dangerous()
//         .with_custom_certificate_verifier(Arc::new(SkipAllServerVerification {}))
//         .with_no_client_auth()
// }
