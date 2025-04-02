use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

use num_enum::TryFromPrimitive;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Magic number for the default port.
pub const DEFAULT_PORT: NonZeroU16 = unsafe { std::num::NonZeroU16::new_unchecked(7828) };

/// Define a sane maximum payload size for the client-server messages.
pub const MAX_SERVER_COMMUNICATION_SIZE: usize = 1024;

/// Using SHA-256 for the hash; i.e., a 256 bit / 8 byte hash.
pub const HASH_BYTE_COUNT: usize = 256 / 8;

/// The maximum number of seconds of inactivity before a QUIC connection is closed.
/// Same for both the server and the client.
pub const QUIC_TIMEOUT_SECONDS: u64 = 120;

/// Code sent on a graceful disconnect.
pub const GOODBYE_CODE: quinn::VarInt = quinn::VarInt::from_u32(0);

/// Optional polite message on a graceful disconnect.
pub const GOODBYE_MESSAGE: &str = "Goodbye!";

/// A block of raw SHA-256 bytes.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct HashBytes {
    pub bytes: [u8; HASH_BYTE_COUNT],
}
impl HashBytes {
    #[must_use]
    pub fn new(bytes: [u8; HASH_BYTE_COUNT]) -> Self {
        Self { bytes }
    }
}

/// Implement a reasonable `Debug` for the `HashBytes` type.
impl std::fmt::Debug for HashBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hexadecimal requires 2 characters per byte.
        let mut hex_str_bytes = [0u8; HASH_BYTE_COUNT << 1];

        // Encode the hash bytes into a hexadecimal string.
        let hex = faster_hex::hex_encode(&self.bytes, &mut hex_str_bytes)
            .expect("Hex encoding of hash failed");
        write!(f, "{hex}")
    }
}
/// Implement a reasonable `Display` for the `HashBytes` type.
impl std::fmt::Display for HashBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A helper to access often used socket address info.
#[derive(Clone, Debug)]
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
/// If `server_address` is empty, will use the `localhost` address for the server.
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
            // If no server address was specified, use the default localhost address.
            const LOCALHOST: &str = "localhost";
            if let Some(address) = (LOCALHOST, port.get())
                .to_socket_addrs()
                .map(|mut i| i.next())
                .ok()
                .flatten()
            {
                Ok(SocketAddrHelper {
                    address,
                    hostname: LOCALHOST.to_string(),
                })
            } else {
                // If the string "localhost" is not a valid address, use the IPv4 localhost as a fallback.
                Ok(SocketAddrHelper {
                    address: (Ipv4Addr::LOCALHOST, port.get()).into(),
                    hostname: Ipv4Addr::LOCALHOST.to_string(),
                })
            }
        })
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

/// Convert an IP address to an IPv6-mapped address.
/// This is an unambiguous way to represent either IPv4 or IPv6 addresses within an IPv6 address.
/// See <https://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses>
/// or <https://www.rfc-editor.org/rfc/rfc4291#section-2.5.5.2> for more information.
#[must_use]
pub fn ipv6_mapped(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

/// Write an IPv6 address and port to the stream as a fixed length.
pub fn write_ipv6_and_port(bb: &mut bytes::BytesMut, ipv6: Ipv6Addr, port: u16) {
    use bytes::BufMut as _;
    bb.put(&ipv6.octets()[..]);
    bb.put_u16(port);
}

/// Write an IP address and port to the stream as a fixed length.
pub fn write_ip_and_port(bb: &mut bytes::BytesMut, ip: IpAddr, port: u16) {
    write_ipv6_and_port(bb, ipv6_mapped(ip), port);
}

/// Errors that may occur when attempting to read a UTF-8 string from a connection.
#[derive(Debug, thiserror::Error)]
pub enum ExpectedSocketError {
    /// Failed to read the IP address from the stream.
    #[error("Failed to read IP: {0}")]
    ReadIp(#[from] quinn::ReadExactError),

    /// Failed to read the port from the stream.
    #[error("Failed to read port: {0}")]
    ReadPort(#[from] std::io::Error),

    /// The IP address received was empty.
    #[error("The received IP address was empty")]
    UnspecifiedAddress,
}

/// Try to read a valid IP address and port from the stream.
/// # Errors
/// Fails if the IP address is empty, or the address and port cannot be read from the stream.
pub async fn read_ip_and_port(
    stream: &mut quinn::RecvStream,
) -> Result<(IpAddr, u16), ExpectedSocketError> {
    use tokio::io::AsyncReadExt as _;

    // Read the requested IP address from the stream.
    let mut ip_octets = [0; 16];
    stream.read_exact(&mut ip_octets).await?;
    let mapped_ipv6 = Ipv6Addr::from(ip_octets);

    if mapped_ipv6.is_unspecified() {
        return Err(ExpectedSocketError::UnspecifiedAddress);
    }

    // Use mapped IPv6 addresses for a fixed length IP address without version ambiguity.
    let ip = if let Some(ipv4) = mapped_ipv6.to_ipv4_mapped() {
        if ipv4.is_unspecified() {
            return Err(ExpectedSocketError::UnspecifiedAddress);
        }

        IpAddr::V4(ipv4)
    } else {
        IpAddr::V6(mapped_ipv6)
    };

    // Read the requested port from the stream.
    let port = stream.read_u16().await?;

    Ok((ip, port))
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
pub fn generate_self_signed_cert<'a>(
) -> Result<(CertificateDer<'a>, PrivateKeyDer<'a>), rcgen::Error> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    Ok((cert_der, key.into()))
}
