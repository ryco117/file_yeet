use std::{
    collections::{hash_map, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::{NonZeroU16, NonZeroUsize},
    path::Path,
    sync::Arc,
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{BiStream, HashBytes, ReadIpPortError, SocketAddrHelper, GOODBYE_CODE};
use futures_util::TryFutureExt;
use rustls::pki_types::CertificateDer;
use sha2::Digest as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _},
    sync::RwLock,
};

pub mod intervals;

/// Type alias for SHA-256 hash state used by the client.
pub type Hasher = sha2::Sha256;

/// The name of the application.
pub static APP_TITLE: &str = env!("CARGO_PKG_NAME");

/// Lazily initialized regex for parsing hash hex strings.
/// Produces capture groups `hash` and `ext` for the hash and optional extension.
pub static HASH_EXT_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^\s*(?P<hash>[0-9a-fA-F]{64})(?::(?P<ext>\w+))?\s*$")
        .expect("Failed to compile the hash hex regex")
});

/// Use a sane default timeout for server connections.
pub const SERVER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
/// Sane default timeout for listening for a peer.
pub const PEER_LISTEN_TIMEOUT: Duration = Duration::from_millis(1500);
/// Sane default timeout for peer connection attempts. Should try to connect for a longer time than listening.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);

/// Define a sane number of maximum retries.
pub const MAX_PEER_CONNECTION_ATTEMPTS: NonZeroUsize = NonZeroUsize::new(10).unwrap();

/// Define the maximum size of a payload for peer communication.
/// QUIC may choose to fragment the payload when sending raw packets, but this isn't a concern.
/// The limit is mainly meant to set reasonable memory usage for a stream.
pub const MAX_PEER_COMMUNICATION_SIZE: usize = 16 * 1024;

/// Expected error indicating that a read operation failed because we closed the connection elsewhere.
pub const LOCALLY_CLOSED_READ: quinn::ReadError =
    quinn::ReadError::ConnectionLost(quinn::ConnectionError::LocallyClosed);

/// Expected error indicating that a write operation failed because we closed the connection elsewhere.
pub const LOCALLY_CLOSED_WRITE: quinn::WriteError =
    quinn::WriteError::ConnectionLost(quinn::ConnectionError::LocallyClosed);

/// Specify whether any existing port forwarding can be used or if a new mapping should be attempted.
#[derive(Debug)]
pub enum PortMappingConfig {
    /// No port forwarding is used, relies entirely on UDP hole punching.
    None,

    /// Use a port forward configured outside of this application.
    PortForwarding(NonZeroU16),

    /// Attempt to use PCP or NAT-PMP to create a port mapping.
    PcpNatPmp(Option<crab_nat::PortMapping>),
}

/// The command relationship between the two peers. Useful for asserting synchronization roles based on the command type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileYeetCommandType {
    Pub,
    Sub,
}

/// A prepared server connection with relevant server connection info.
#[derive(Clone, Debug)]
pub struct PreparedConnection {
    pub endpoint: quinn::Endpoint,
    pub server_connection: quinn::Connection,
    pub port_mapping: Option<crab_nat::PortMapping>,
    pub external_address: (SocketAddr, String),
}

/// Errors that may occur when preparing a server connection and endpoint to communicate with.
#[derive(Debug, thiserror::Error)]
pub enum PrepareConnectionError {
    #[error("Invalid server address: {0}")]
    ServerAddress(std::io::Error),

    #[error("Failed to create local endpoint: {0}")]
    EndpointCreation(std::io::Error),

    #[error("Failed to connect to server: {0}")]
    ConnectToServer(#[from] ConnectToServerError),

    #[error("Failed to determine our local address: {0}")]
    LocalAddress(#[from] ProbeLocalAddressError),

    #[error("Invalid gateway address: {0}")]
    InvalidGatewayAddress(std::net::AddrParseError),

    #[error("Unknown gateway address: {0}")]
    UnknownGatewayAddress(String),

    #[error("Socket ping request failed: {0}")]
    SocketPing(#[from] SocketPingError),

    #[error("Port override request failed: {0}")]
    PortOverride(#[from] PortOverrideError),
}

/// Create a QUIC endpoint connected to the server and perform basic setup.
/// Will attempt to infer optional arguments from the system if not specified.
#[tracing::instrument(skip_all)]
pub async fn prepare_server_connection(
    server_address: Option<&str>,
    server_port: NonZeroU16,
    suggested_gateway: Option<&str>,
    internal_port: Option<NonZeroU16>,
    external_port_config: PortMappingConfig,
    bb: &mut bytes::BytesMut,
) -> Result<PreparedConnection, PrepareConnectionError> {
    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()
        .expect("Failed to generate self-signed certificate");
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)
        .expect("Quinn failed to accept our generated certificates");

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Get the server address info.
    let server_socket = file_yeet_shared::get_server_or_default(server_address, server_port)
        .map_err(PrepareConnectionError::ServerAddress)?;
    tracing::debug!("Connecting to server {server_socket:?}");

    // Determine the local socket address to bind to. Use an unspecified address since we don't have any preference.
    let bind_port = internal_port.map_or(0, NonZeroU16::get);
    let bind_address = match &server_socket.address {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port)),
        SocketAddr::V6(_) => {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, bind_port, 0, 0))
        }
    };
    let mut endpoint = quinn::Endpoint::server(server_config, bind_address)
        .map_err(PrepareConnectionError::EndpointCreation)?;

    // Use an insecure client configuration when connecting to peers.
    endpoint.set_default_client_config(configure_peer_verification());

    // Connect to the specified `file_yeet` server.
    let connection = connect_to_server(&endpoint, server_socket).await?;

    // Share debug information about the QUIC endpoints.
    let mut local_address = endpoint
        .local_addr()
        .expect("Failed to get the local address of our QUIC endpoint");
    if local_address.ip().is_unspecified() {
        local_address.set_ip(probe_local_address(matches!(
            connection.remote_address(),
            SocketAddr::V4(_)
        ))?);
    }
    tracing::info!("QUIC endpoint created with local address: {local_address}");

    let (port_mapping, port_override) = match external_port_config {
        // Use a port that is explicitly set by the user without PCP/NAT-PMP.
        PortMappingConfig::PortForwarding(p) => (None, Some(p)),

        // Attempt PCP and NAT-PMP port mappings to the gateway.
        PortMappingConfig::PcpNatPmp(None) => {
            let gateway = if let Some(g) = suggested_gateway {
                // Parse the string to an IP address.
                g.parse()
                    .map_err(PrepareConnectionError::InvalidGatewayAddress)?
            } else {
                // Determine the default gateway.
                let gateway = netdev::get_default_gateway()
                    .map_err(PrepareConnectionError::UnknownGatewayAddress)?;

                // Use the local address as preference for which IP version to use.
                if local_address.is_ipv4() {
                    gateway
                        .ipv4
                        .first()
                        .map(|ip| IpAddr::V4(*ip))
                        .or_else(|| gateway.ipv6.first().map(|ip| IpAddr::V6(*ip)))
                } else {
                    gateway
                        .ipv6
                        .first()
                        .map(|ip| IpAddr::V6(*ip))
                        .or_else(|| gateway.ipv4.first().map(|ip| IpAddr::V4(*ip)))
                }
                .ok_or_else(|| {
                    PrepareConnectionError::UnknownGatewayAddress(
                        "Gateway has no associated IP address".to_owned(),
                    )
                })?
            };

            match try_port_mapping(gateway, local_address).await {
                Ok(m) => {
                    let external_port = m.external_port();
                    let internal_port = m.internal_port();
                    let expiration_time = instant_to_datetime_string(m.expiration());
                    tracing::info!("Mapped external port {external_port} -> internal {internal_port}, expiration at {expiration_time}");
                    (Some(m), Some(external_port))
                }
                Err(e) => {
                    tracing::warn!("Failed to create a port mapping: {e}");
                    (None, None)
                }
            }
        }

        // Re-using existing port mapping.
        PortMappingConfig::PcpNatPmp(Some(m)) => {
            let p = m.external_port();
            (Some(m), Some(p))
        }

        PortMappingConfig::None => (None, None),
    };

    // Read the server's response to the sanity check.
    let sanity_check = socket_ping_request(&connection).await?;
    let mut sanity_check = (sanity_check, sanity_check.to_string());

    // Only debug builds may log the public IP address of clients.
    #[cfg(debug_assertions)]
    tracing::info!("Server sees us as {}", sanity_check.1);

    if let Some(port) = port_override {
        // Only send a port override request if the server sees us through a different port.
        if sanity_check.0.port() != port.get() {
            port_override_request(&connection, port, bb).await?;
            sanity_check.0.set_port(port.get());
        }
    }

    Ok(PreparedConnection {
        endpoint,
        server_connection: connection,
        port_mapping,
        external_address: sanity_check,
    })
}

/// Errors that may occur when attempting to get the default interface's IP address.
#[derive(Debug, thiserror::Error)]
pub enum ProbeLocalAddressError {
    /// Failed to get the default interface.
    #[error("Failed to get a default interface: {0}")]
    DefaultInterface(String),

    /// Failed to get a default IPv4 address.
    #[error("Failed to get a default IPv4 address")]
    NoDefaultIpv4,

    /// Failed to get a default IPv6 address.
    #[error("Failed to get a default IPv6 address")]
    NoDefaultIpv6,
}

/// Helper to determine the default interface's IP address.
fn probe_local_address(using_ipv4: bool) -> Result<IpAddr, ProbeLocalAddressError> {
    let interface =
        netdev::get_default_interface().map_err(ProbeLocalAddressError::DefaultInterface)?;
    let ip = if using_ipv4 {
        IpAddr::V4(
            interface
                .ipv4
                .first()
                .ok_or(ProbeLocalAddressError::NoDefaultIpv4)?
                .addr(),
        )
    } else {
        IpAddr::V6(
            interface
                .ipv6
                .first()
                .ok_or(ProbeLocalAddressError::NoDefaultIpv6)?
                .addr(),
        )
    };

    Ok(ip)
}

/// Attempt to create a port mapping using NAT-PMP or PCP.
#[tracing::instrument]
async fn try_port_mapping(
    gateway: IpAddr,
    local_address: SocketAddr,
) -> Result<crab_nat::PortMapping, crab_nat::MappingFailure> {
    crab_nat::PortMapping::new(
        gateway,
        local_address.ip(),
        crab_nat::InternetProtocol::Udp,
        std::num::NonZeroU16::new(local_address.port()).expect("Socket address has no port"),
        crab_nat::PortMappingOptions {
            timeout_config: Some(crab_nat::natpmp::TIMEOUT_CONFIG_DEFAULT),
            ..Default::default()
        },
    )
    .await
}

/// Helper to convert an `Instant` into a `DateTime` string.
pub fn instant_to_datetime_string(i: std::time::Instant) -> String {
    chrono::TimeDelta::from_std(i.duration_since(std::time::Instant::now()))
        .ok()
        .and_then(|d| chrono::Local::now().checked_add_signed(d))
        .map_or_else(
            || String::from("UNKNOWN"),
            |t| t.format("%Y-%m-%d %H:%M:%S").to_string(),
        )
}

/// Helper to configure a waiting period based on a port mapping lifetime.
/// The interval is set to one-third of the lifetime, with a minimum of 120 seconds.
pub async fn new_renewal_interval(lifetime_seconds: u64) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(
        Duration::from_secs(lifetime_seconds)
            .div_f64(3.)
            .max(Duration::from_secs(120)),
    );
    interval.tick().await; // Skip the first tick.
    interval
}

/// Try to renew the port mapping.
/// On success, returns whether any mapping parameters changed.
#[tracing::instrument(skip_all)]
pub async fn renew_port_mapping(
    port_mapping: &mut crab_nat::PortMapping,
) -> Result<bool, crab_nat::MappingFailure> {
    tracing::debug!("Attempting port mapping renewal...");
    let last_lifetime = port_mapping.lifetime();
    let last_port = port_mapping.external_port();

    port_mapping.renew().await?;
    let mut mapping_changed = false;

    let lifetime = port_mapping.lifetime();
    if lifetime != last_lifetime {
        tracing::debug!(
            "Port mapping renewal changed lifetime from {last_lifetime} to {lifetime} seconds"
        );
        mapping_changed = true;
    }

    let port = port_mapping.external_port();
    if port != last_port {
        tracing::debug!("Port mapping renewal changed port from {last_port} to {port}");
        mapping_changed = true;
    }

    let expiration_time = instant_to_datetime_string(port_mapping.expiration());
    tracing::debug!("Port mapping renewal succeeded. Expiration at {expiration_time}");
    Ok(mapping_changed)
}

/// Error that may occur when attempting to connect to the server.
#[derive(Debug, thiserror::Error)]
pub enum ConnectToServerError {
    /// Failed to begin a QUIC connection to the server.
    #[error("Failed to begin a QUIC connection to the server: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// Failed to complete the QUIC connection to the server.
    #[error("Failed to complete a QUIC connection to the server: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// The connection attempt timed out without a specific error.
    #[error("Failed to establish a QUIC connection to the server: Timeout {0:#}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

/// Connect to the server using QUIC.
#[tracing::instrument(skip(endpoint))]
async fn connect_to_server(
    endpoint: &quinn::Endpoint,
    server_socket: SocketAddrHelper,
) -> Result<quinn::Connection, ConnectToServerError> {
    // Attempt to connect to the server using QUIC.
    let connection = tokio::time::timeout(
        SERVER_CONNECTION_TIMEOUT,
        endpoint.connect(server_socket.address, server_socket.hostname.as_str())?,
    )
    .await??;
    tracing::info!("QUIC connection made to the server");
    Ok(connection)
}

/// Errors that may occur when sending a ping request.
#[derive(Debug, thiserror::Error)]
pub enum SocketPingError {
    /// Failed to establish a new QUIC stream for the ping request.
    #[error("Failed to establish ping connection: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to send the ping request.
    #[error("Failed to send ping: {0}")]
    SendRequest(std::io::Error),

    /// Failed to read response text.
    #[error("Failed to read ping response text: {0}")]
    ResponseText(#[from] ReadIpPortError),

    /// Failed to parse the response socket address.
    #[error("Failed to parse the response address: {0}")]
    ParseAddress(#[from] std::net::AddrParseError),
}

/// Perform a socket ping request to the server and sanity check the response.
/// Returns the server's address and the string encoding it was sent as.
#[tracing::instrument(skip_all)]
pub async fn socket_ping_request(
    server_connection: &quinn::Connection,
) -> Result<SocketAddr, SocketPingError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Perform a sanity check by sending the server a socket ping request.
    // This allows us to verify that the server can determine our public address.
    server_streams
        .send
        .write_u16(file_yeet_shared::ClientApiRequest::SocketPing as u16)
        .map_err(SocketPingError::SendRequest)
        .await?;

    // Read the server's response to the ping request.
    let (ip, port) = file_yeet_shared::read_ip_and_port(&mut server_streams.recv).await?;
    Ok(SocketAddr::new(ip, port))
}

/// Errors that may occur when sending a port override request.
#[derive(Debug, thiserror::Error)]
pub enum PortOverrideError {
    /// Failed to establish a new QUIC stream for the port override request.
    #[error("{0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to send the port override request.
    #[error("{0}")]
    SendRequest(#[from] quinn::WriteError),
}

/// Perform a port override request to the server.
#[tracing::instrument(skip(server_connection, bb))]
pub async fn port_override_request(
    server_connection: &quinn::Connection,
    port: NonZeroU16,
    bb: &mut bytes::BytesMut,
) -> Result<(), PortOverrideError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Format a port override request.
    bb.clear();
    bb.put_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16);
    bb.put_u16(port.get());

    // Send the port override request to the server and clear the buffer.
    server_streams.send.write_all(bb).await?;

    Ok(())
}

// /// Errors that may occur when sending an introduction request.
// #[derive(Debug, thiserror::Error)]
// pub enum IntroductionError {
//     /// Failed to establish a new QUIC stream for the introduction request.
//     #[error("{0}")]
//     Connection(#[from] quinn::ConnectionError),

//     /// Failed to send the introduction request.
//     #[error("{0}")]
//     SendRequest(#[from] quinn::WriteError),
// }

// /// Perform an introduction request to the server for a specific peer and hash.
// #[tracing::instrument(skip(server_connection, bb, external_address))]
// pub async fn introduction(
//     server_connection: &quinn::Connection,
//     bb: &mut bytes::BytesMut,
//     hash: HashBytes,
//     external_address: SocketAddr,
// ) -> Result<(), IntroductionError> {
//     // Create a bi-directional stream to the server.
//     let mut server_streams: BiStream = server_connection.open_bi().await?.into();

//     // Send the server an introduction request.
//     bb.clear();
//     bb.put_u16(file_yeet_shared::ClientApiRequest::Introduction as u16);
//     bb.put(&hash.bytes[..]);
//     file_yeet_shared::write_ip_and_port(bb, external_address.ip(), external_address.port());
//     server_streams.send.write_all(bb).await?;

//     Ok(())
// }

/// Errors that may occur when sending a publish request to the server.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Failed to establish a new QUIC stream for the publish request.
    #[error("Failed to open request stream: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to send the publish request.
    #[error("Failed to send publish request: {0}")]
    SendRequest(#[from] quinn::WriteError),
}

/// Perform a publish request to the server.
#[tracing::instrument(skip(server_connection))]
pub async fn publish(
    server_connection: &quinn::Connection,
    hash: HashBytes,
    file_size: u64,
) -> Result<BiStream, PublishError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Format a publish request.
    let mut send_buffer = [0u8; 2 + file_yeet_shared::HASH_BYTE_COUNT + 8];
    let mut bb = &mut send_buffer[..];
    bb.put_u16(file_yeet_shared::ClientApiRequest::Publish as u16);
    bb.put(&hash.bytes[..]);
    bb.put_u64(file_size);

    // Send the server a publish request.
    server_streams.send.write_all(&send_buffer).await?;

    Ok(server_streams)
}

/// Errors that may occur when reading a subscriber address from the server.
#[derive(Debug, thiserror::Error)]
pub enum ReadSubscribingPeerError {
    /// Failed to get valid socket address from stream.
    #[error("Failed to read valid peer address from stream: {0}")]
    ReadSocket(#[from] ReadIpPortError),

    /// The server sent our address back to us.
    #[error("The server sent our address back to us")]
    SelfAddress,
}

/// Read a peer address from the server in response to a publish task.
#[tracing::instrument(skip_all)]
pub async fn read_subscribing_peer(
    server_recv: &mut quinn::RecvStream,
    our_external_address: Option<SocketAddr>,
) -> Result<SocketAddr, ReadSubscribingPeerError> {
    // Parse the response as a peer socket address or skip this message.
    let (ip, port) = file_yeet_shared::read_ip_and_port(server_recv).await?;
    let peer_address = SocketAddr::new(ip, port);

    // Ensure the server isn't sending us our own address.
    if our_external_address.is_some_and(|a| a == peer_address) {
        return Err(ReadSubscribingPeerError::SelfAddress);
    }

    Ok(peer_address)
}

/// Errors that may occur when attempting to subscribe to a file.
#[derive(Debug, thiserror::Error)]
pub enum SubscribeError {
    /// Failed to open a bi-directional QUIC stream for the subscribe request.
    #[error("Failed to open a stream for the subscribe request: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Failed to send a subscribe request to the server.
    #[error("Failed to send a subscribe request to the server: {0}")]
    SendRequest(#[from] quinn::WriteError),

    /// Failed to read response size from the server and got a `ReadError`.
    #[error("Failed to read response size from the server: {0}")]
    ReadSizeFailedWithError(#[from] quinn::ReadError),

    /// Failed to read response size from the server and got an `ErrorKind`.
    #[error("Failed to read response size from the server: {0}")]
    ReadSizeFailedWithKind(std::io::ErrorKind),

    /// Failed to read response from the server.
    #[error("Failed to read response from the server: {0}")]
    ReadResponse(#[from] ReadIpPortError),

    /// Failed to parse a peer address from the server response.
    #[error("Failed to parse a peer address from the server response: {0}")]
    ParseAddress(#[from] std::net::AddrParseError),
}

/// Perform a subscribe request to the server.
/// Returns a list of peers that are sharing the file and the file size they promise to send.
#[tracing::instrument(skip(server_connection, bb, our_external_address))]
pub async fn subscribe(
    server_connection: &quinn::Connection,
    bb: &mut bytes::BytesMut,
    hash: HashBytes,
    our_external_address: Option<SocketAddr>,
) -> Result<Vec<(SocketAddr, u64)>, SubscribeError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Send the server a subscribe request.
    bb.clear();
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash.bytes[..]);
    server_streams.send.write_all(bb).await?;

    tracing::info!("Requesting file with hash from the server...");

    // Determine if the server is responding with a success or failure.
    let response_count = server_streams.recv.read_u16().await.map_err(|e| {
        let kind = e.kind();
        if let Ok(e) = e.downcast::<quinn::ReadError>() {
            SubscribeError::ReadSizeFailedWithError(e)
        } else {
            SubscribeError::ReadSizeFailedWithKind(kind)
        }
    })?;

    if response_count == 0 {
        // No peers are sharing the file.
        return Ok(Vec::with_capacity(0));
    }

    // Warn if we do not know our external address.
    if our_external_address.is_none() {
        tracing::warn!("Cannot determine if the server sent our own address in subscribe response");
    }

    // Parse each peer socket address and file size.
    let mut peers = Vec::new();
    for _ in 0..response_count {
        // Read the incoming peer socket address.
        let (peer_ip, peer_port) =
            file_yeet_shared::read_ip_and_port(&mut server_streams.recv).await?;
        let peer_address = SocketAddr::new(peer_ip, peer_port);

        // Read the incoming file size.
        let file_size = server_streams.recv.read_u64().await.map_err(|e| {
            let kind = e.kind();
            if let Ok(e) = e.downcast::<quinn::ReadError>() {
                SubscribeError::ReadSizeFailedWithError(e)
            } else {
                SubscribeError::ReadSizeFailedWithKind(kind)
            }
        })?;

        if our_external_address.is_some_and(|a| a == peer_address) {
            tracing::debug!("Skipping our own address from the server response");
            continue;
        }

        peers.push((peer_address, file_size));
    }

    Ok(peers)
}

/// Attempt to connect to peer using UDP hole punching.
/// Specifically, both peers attempt outgoing connections while listening for incoming connections.
#[tracing::instrument(skip(endpoint, hash, peer_address))]
pub async fn udp_holepunch(
    cmd: FileYeetCommandType,
    hash: HashBytes,
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<(quinn::Connection, BiStream)> {
    // Poll incoming connections that are handled by a background task.
    let manager = ConnectionsManager::instance();
    let listen_future = manager.await_peer(peer_address, PEER_LISTEN_TIMEOUT);

    // Attempt to connect to the peer's public address.
    let connect_future = tokio::time::timeout(
        PEER_CONNECT_TIMEOUT,
        connect_to_peer(endpoint, peer_address),
    );

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    let connect_stream = connect_stream.ok().flatten();
    let connections =
        // TODO: It could be interesting and possible to create a more general stream negotiation.
        //       For example, if each peer sent a random nonce over each stream, and the nonces were XOR'd per stream,
        //       the result could be used to determine which stream to use (highest/lowest resulting nonce after XOR).
        match cmd {
            FileYeetCommandType::Pub => listen_stream.map(|c| (c, true)).into_iter().chain(connect_stream.map(|c| (c, false)).into_iter()),
            FileYeetCommandType::Sub => connect_stream.map(|c| (c, false)).into_iter().chain(listen_stream.map(|c| (c, true)).into_iter()),
        };

    for (connection, managed_connection) in connections {
        if let Ok(peer_streams) = peer_connection_into_stream(&connection, hash, cmd).await {
            // Let the user know that a connection is established. A bi-directional stream is ready to use.
            tracing::info!("Peer connection established");

            // If the connection is not managed, add it to the manager.
            if !managed_connection {
                manager.accept_peer(connection.clone()).await;
            }

            return Some((connection, peer_streams));
        }
    }
    None
}

/// Errors that may occur when turning a peer connection into a bi-directional stream.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionIntoStreamError {
    /// Failed to establish a QUIC connection to the peer.
    #[error("Failed to establish a QUIC connection to the peer: {0}")]
    ConnectionFailed(#[from] quinn::ConnectionError),

    /// Failed to read exact bytes from the peer stream. Only occurs with `FileYeetCommandType::Pub`.
    #[error("Failed to read from the peer stream: {0}")]
    ReadExactFailed(#[from] quinn::ReadExactError),

    /// The requested hash from the peer does not match the expected hash. Only occurs with `FileYeetCommandType::Pub`.
    #[error("Requested hash from the peer does not match the expected hash")]
    HashMismatch,

    /// Failed to write to the peer stream. Only occurs with `FileYeetCommandType::Sub`.
    #[error("Failed to write to the peer stream: {0}")]
    WriteFailed(#[from] quinn::WriteError),
}

/// Try to finalize a peer connection attempt by turning it into a bi-directional stream.
#[tracing::instrument(skip_all)]
pub async fn peer_connection_into_stream(
    connection: &quinn::Connection,
    expected_hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Result<BiStream, ConnectionIntoStreamError> {
    match cmd {
        FileYeetCommandType::Pub => {
            // Let the downloading peer initiate a bi-directional stream.
            let mut r = connection.accept_bi().await;
            if let Ok(s) = &mut r {
                let mut requested_hash = HashBytes::default();
                s.1.read_exact(&mut requested_hash.bytes).await?;

                // Ensure the requested hash matches the expected file hash.
                if requested_hash != expected_hash {
                    return Err(ConnectionIntoStreamError::HashMismatch);
                }
                tracing::debug!("New peer stream accepted");
            }
            r
        }
        FileYeetCommandType::Sub => {
            // Open a bi-directional stream to the publishing peer.
            let mut r = connection.open_bi().await;
            if let Ok(s) = &mut r {
                s.0.write_all(&expected_hash.bytes).await?;
                tracing::debug!("New peer stream opened");
            }
            r
        }
    }
    .map(std::convert::Into::into)
    .map_err(std::convert::Into::into)
}

/// Make an outgoing connection attempt to a peer at the given address.
#[tracing::instrument(skip_all)]
async fn connect_to_peer(
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<quinn::Connection> {
    // Set a sane number of connection attempts
    let mut connect_attempt = 0;

    // Ensure we have retries left and there isn't already a peer `Connection` to use.
    while connect_attempt < MAX_PEER_CONNECTION_ATTEMPTS.get() {
        let connect_attempt_print = connect_attempt + 1;
        if cfg!(debug_assertions) {
            tracing::debug!(
                "Connection attempt #{connect_attempt_print} to peer at {peer_address}"
            );
        } else {
            tracing::debug!("Connection attempt #{connect_attempt_print} to peer");
        }

        match endpoint.connect(peer_address, "peer") {
            Ok(connecting) => {
                let connection = match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Failed to connect to peer: {e}");
                        connect_attempt += 1;
                        continue;
                    }
                };

                if cfg!(debug_assertions) {
                    tracing::info!("Connected to peer at {peer_address}");
                } else {
                    tracing::info!("Connected to peer");
                }
                return Some(connection);
            }

            Err(e) => {
                tracing::warn!("Failed to connect to peer with unrecoverable error: {e}");
                return None;
            }
        }
    }

    tracing::debug!("Failed to connect to peer after all attempts");
    None
}

/// The range of bytes to download and an optional starting hash state.
/// If no hasher is provided, no hash will be computed or verified.
pub struct DownloadOffsetState {
    pub range: std::ops::Range<u64>,
    pub hasher: Option<(Hasher, HashBytes)>,
}
impl DownloadOffsetState {
    /// Create a new download offset state with a specific range and optional hasher.
    pub fn new(range: std::ops::Range<u64>, hasher: Option<(Hasher, HashBytes)>) -> Self {
        Self { range, hasher }
    }
}

/// Errors that may occur when downloading a file from a peer.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("A file access error occurred: {0}")]
    FileAccess(#[from] FileAccessError),

    #[error("An error occurred reading from peer: {0}")]
    QuicRead(#[from] quinn::ReadError),

    #[error("An error occurred sending to peer: {0}")]
    QuicWrite(#[from] quinn::WriteError),

    #[error("Unexpected end of file")]
    UnexpectedEof,

    #[error("The downloaded file hash does not match the expected hash")]
    HashMismatch,
}
impl DownloadError {
    /// Return whether the error is recoverable and the download can be retried.
    pub fn is_recoverable(&self) -> bool {
        match self {
            DownloadError::FileAccess(_)
            | DownloadError::QuicRead(_)
            | DownloadError::QuicWrite(_)
            | DownloadError::UnexpectedEof => true,

            DownloadError::HashMismatch => false,
        }
    }
}

/// Download a slice of a file from the peer. Initiates the download by specifying the range of bytes to download.
/// The caller is responsible for opening the file but this function will seek to the specified starting offset before writing.
/// The caller may optionally provide a `RwLock<u64>` to track the number of bytes downloaded so far.
/// If a hasher is provided in the `file_offsets`, the downloaded data will be hashed and verified against the expected hash.
#[tracing::instrument(skip(peer_streams, file, file_offsets, byte_progress))]
pub async fn download_partial_from_peer(
    peer_streams: &mut BiStream,
    file: &mut tokio::fs::File,
    file_offsets: DownloadOffsetState,
    byte_progress: Option<&RwLock<u64>>,
) -> Result<(), DownloadError> {
    // Determine the range of bytes to download and an existing hasher state.
    let DownloadOffsetState { range, mut hasher } = file_offsets;
    tracing::debug!("Downloading partial file from peer: Bytes {range:?}");

    // Seek to the requested offset.
    file.seek(std::io::SeekFrom::Start(range.start))
        .await
        .map_err(FileAccessError::Seek)?;

    // Get the number of bytes to download.
    let download_size = range.end.saturating_sub(range.start);

    // Let the peer know which range we want to download using this QUIC stream.
    let mut bb = [0u8; size_of::<u64>() * 2];
    bb[..size_of::<u64>()].copy_from_slice(range.start.to_be_bytes().as_slice());
    bb[size_of::<u64>()..].copy_from_slice(download_size.to_be_bytes().as_slice());
    peer_streams.send.write_all(&bb).await?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];

    // Read from the peer and write to the file.
    let mut bytes_written = 0;
    while bytes_written < download_size {
        // Read a natural amount of bytes from the peer.
        let size = peer_streams
            .recv
            .read(&mut buf)
            .await?
            .ok_or(DownloadError::UnexpectedEof)?;

        if size > 0 {
            // Ensure we don't write more bytes than were requested in the handshake.
            let size = usize::try_from(download_size - bytes_written)
                .map(|x| x.min(size))
                .unwrap_or(size);

            // Write the bytes to the file and update the hash.
            let bb = &buf[..size];

            // Update hash if requested.
            if let Some((hasher, _)) = hasher.as_mut() {
                hasher.update(bb);
            }

            // Write the bytes to the file.
            file.write_all(bb).await.map_err(FileAccessError::Write)?;

            // Update the number of bytes written.
            let size = size as u64;
            bytes_written += size;

            // Update the caller with the number of bytes written.
            if let Some(progress) = byte_progress.as_ref() {
                *progress.write().await = bytes_written;
            }
        }
    }

    // No more data is required from this stream.
    // Let the peer know they can close their end of the stream.
    if let Err(e) = peer_streams.recv.stop(GOODBYE_CODE) {
        tracing::debug!("Failed to close the peer stream gracefully: {e}");
    }

    if let Some((hasher, expected_hash)) = hasher.take() {
        // Ensure the file hash is correct.
        let downloaded_hash = HashBytes::new(hasher.finalize().into());
        if expected_hash == downloaded_hash {
            tracing::info!("Validated download hash");
        } else {
            return Err(DownloadError::HashMismatch);
        }
    }

    Ok(())
}

/// Reject a download request gracefully by sending a null download range to the peer.
#[tracing::instrument(skip_all)]
pub async fn reject_download_request(peer_streams: &mut BiStream) -> Result<(), DownloadError> {
    // Send a null download range to the peer to reject the download gracefully.
    let bytes = [0u8; size_of::<u64>() * 2];
    peer_streams.send.write_all(&bytes).await?;

    Ok(())
}

/// Download a file from the peer to the specified file path.
#[tracing::instrument(skip(peer_streams, byte_progress))]
pub async fn download_from_peer(
    expected_hash: HashBytes,
    peer_streams: &mut BiStream,
    file_size: u64,
    output_path: &Path,
    byte_progress: Option<&RwLock<u64>>,
) -> Result<(), DownloadError> {
    tracing::info!("Downloading entire file from peer...");

    // Specify that we want to download the entire file.
    let file_offsets =
        DownloadOffsetState::new(0..file_size, Some((Hasher::default(), expected_hash)));

    // Open the file for writing, truncating if the file already exists.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output_path)
        .await
        .map_err(FileAccessError::Open)?;

    Box::pin(download_partial_from_peer(
        peer_streams,
        &mut file,
        file_offsets,
        byte_progress,
    ))
    .await?;

    // Let the user know that the download is complete.
    tracing::info!("Download complete");
    Ok(())
}

/// Errors that may occur when making file access attempts.
#[derive(Debug, thiserror::Error)]
pub enum FileAccessError {
    /// Failed to open the file.
    #[error("Failed to open the file: {0}")]
    Open(std::io::Error),

    /// Failed to seek in the file.
    #[error("Failed to seek in the file: {0}")]
    Seek(std::io::Error),

    /// Failed to read from the file.
    #[error("Failed to read from the file: {0}")]
    Read(std::io::Error),

    /// Failed to write to the file.
    #[error("Failed to write to the file: {0}")]
    Write(std::io::Error),
}

/// Get access to a file with its size and its current hash state.
/// The file read position will be after the last byte that was read into the hasher.
pub async fn file_size_and_hasher(
    file_path: &Path,
    progress: Option<&RwLock<f32>>,
) -> Result<(tokio::fs::File, u64, Hasher), FileAccessError> {
    let mut hasher = Hasher::new();
    let mut file = tokio::fs::File::open(file_path)
        .await
        .map_err(FileAccessError::Open)?;

    // Get the file size so we can report progress.
    // It also lets us set a finite size to read.
    let file_size = file
        .seek(std::io::SeekFrom::End(0))
        .await
        .map_err(FileAccessError::Seek)?;

    // Reset the reader to the start of the file.
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(FileAccessError::Seek)?;

    let size_float = file_size as f32;
    let mut hash_byte_buffer = [0; 16_384];
    let mut bytes_hashed = 0;
    while bytes_hashed < file_size {
        let n = file
            .read(&mut hash_byte_buffer)
            .await
            .map_err(FileAccessError::Read)?;
        if n == 0 {
            break;
        }

        hasher.update(&hash_byte_buffer[..n]);
        bytes_hashed += n as u64;

        // Update the caller with the number of bytes read.
        if let Some(progress) = progress.as_ref() {
            *progress.write().await = bytes_hashed as f32 / size_float;
        }
    }

    // Return the number of bytes hashed.
    Ok((file, bytes_hashed, hasher))
}

/// Get a file's size and its SHA-256 hash.
#[tracing::instrument(skip(progress))]
pub async fn file_size_and_hash(
    file_path: &Path,
    progress: Option<&RwLock<f32>>,
) -> Result<(u64, HashBytes), FileAccessError> {
    let (_, size, hasher) = Box::pin(file_size_and_hasher(file_path, progress)).await?;
    Ok((size, HashBytes::new(hasher.finalize().into())))
}

/// Errors that may occur when uploading a file to a peer.
#[derive(Debug, thiserror::Error)]
pub enum ReadPubRangeError {
    /// Failed to read file index data and got a `ReadError`.
    #[error("Failed to read file index data: {0}")]
    ReadFileIndexFailedWithError(quinn::ReadError),

    /// Failed to read file index data and got an `ErrorKind`.
    #[error("Failed to read file index data: {0}")]
    ReadFileIndexFailedWithKind(std::io::ErrorKind),

    /// Peer requested an invalid range, exceeds file size.
    #[error("Peer requested an invalid range, exceeds file size")]
    InvalidRange,

    /// Peer requested an invalid range, 64-bit overflow 🫠.
    #[error("Peer requested an invalid range, 64-bit overflow 🫠")]
    RangeOverflow,
}

/// Read the upload range from the peer.
/// Guarantees the start index and range length can be safely used or returns an error.
#[tracing::instrument(skip(peer_streams))]
pub async fn read_publish_range(
    peer_streams: &mut BiStream,
    file_size: u64,
) -> Result<(u64, u64), ReadPubRangeError> {
    // Read the peer's desired upload range.
    let start_index = peer_streams.recv.read_u64().await.map_err(|e| {
        let kind = e.kind();
        if let Ok(e) = e.downcast::<quinn::ReadError>() {
            ReadPubRangeError::ReadFileIndexFailedWithError(e)
        } else {
            ReadPubRangeError::ReadFileIndexFailedWithKind(kind)
        }
    })?;
    let upload_length = peer_streams.recv.read_u64().await.map_err(|e| {
        let kind = e.kind();
        if let Ok(e) = e.downcast::<quinn::ReadError>() {
            ReadPubRangeError::ReadFileIndexFailedWithError(e)
        } else {
            ReadPubRangeError::ReadFileIndexFailedWithKind(kind)
        }
    })?;

    // Sanity check the upload range.
    let end_index = match start_index.checked_add(upload_length) {
        Some(end) if end > file_size => Err(ReadPubRangeError::InvalidRange),
        None => Err(ReadPubRangeError::RangeOverflow),
        Some(end) => Ok(end),
    }?;
    tracing::info!("Peer requested upload range: Bytes {start_index}..{end_index}");

    Ok((start_index, upload_length))
}

/// Errors that may occur when uploading a file to a peer.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// File access encountered an error.
    #[error("File access encountered an error: {0}")]
    FileAccess(#[from] FileAccessError),

    /// File read early EOF.
    #[error("File read encountered an early EOF")]
    EarlyEof,

    /// Failed to write to the peer.
    #[error("Failed to write to the peer: {0}")]
    Write(#[from] quinn::WriteError),
}

/// Upload the file to the peer. Ensure they consent to the file size before sending the file.
#[tracing::instrument(skip(peer_streams, reader, byte_progress))]
pub async fn upload_to_peer(
    peer_streams: &mut BiStream,
    start_index: u64,
    upload_length: u64,
    mut reader: tokio::io::BufReader<tokio::fs::File>,
    byte_progress: Option<&RwLock<u64>>,
) -> Result<(), UploadError> {
    // Ensure that the file reader is at the starting index for the upload.
    reader
        .seek(std::io::SeekFrom::Start(start_index))
        .await
        .map_err(FileAccessError::Seek)?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];
    let mut bytes_sent = 0;

    // Read from the file and write to the peer.
    while bytes_sent < upload_length {
        // Read a natural amount of bytes from the file.
        let mut n = reader.read(&mut buf).await.map_err(FileAccessError::Read)?;

        if n == 0 {
            // Ensure we bail out if we reach the end of the file before expected
            // since this indicates the file has likely changed underneath us.
            return Err(UploadError::EarlyEof);
        }

        // Ensure we don't send more bytes than were requested in the range.
        let remaining = upload_length - bytes_sent;
        if n as u64 > remaining {
            // `remaining` must be able to fit in `usize` since it is less than `n: usize`.
            #[allow(clippy::cast_possible_truncation)]
            let remaining = remaining as usize;

            n = remaining;
        }

        // Write the bytes to the peer.
        peer_streams.send.write_all(&buf[..n]).await?;

        // Update the number of bytes read.
        bytes_sent += n as u64;

        // Update the caller with the number of bytes sent to the peer.
        if let Some(progress) = byte_progress.as_ref() {
            *progress.write().await = bytes_sent;
        }
    }

    // Gracefully close our connection after all data has been sent.
    if let Err(e) = peer_streams.send.stopped().await {
        tracing::warn!("Failed to close the peer stream gracefully: {e}");
    }

    // Let the user know that the upload is complete.
    tracing::info!("Upload complete!");
    Ok(())
}

/// Turn a byte count into a human readable string.
#[allow(clippy::cast_precision_loss)]
pub fn humanize_bytes(bytes: u64) -> String {
    human_bytes::human_bytes(bytes as f64)
}

/// Type for determining whether a peer connection is being requested or has already been established.
pub enum IncomingPeerState {
    Awaiting(Vec<tokio::sync::oneshot::Sender<quinn::Connection>>),
    Connected(quinn::Connection),
}

/// A manager for incoming and connected peers.
//  TODO: Use a task master to spawn tasks for each connected peer.
#[derive(Clone, Default)]
pub struct ConnectionsManager {
    map: Arc<RwLock<HashMap<SocketAddr, IncomingPeerState>>>,
}

impl ConnectionsManager {
    /// Get a smart pointer to the `IncomingManager` singleton that maps incoming and connected peers.
    pub fn instance() -> Self {
        static MANAGER: std::sync::LazyLock<ConnectionsManager> =
            std::sync::LazyLock::<_>::new(ConnectionsManager::default);
        MANAGER.clone()
    }

    /// Await the connection of a peer from a specified socket address.
    #[tracing::instrument(skip(self, peer_address))]
    pub async fn await_peer(
        &self,
        peer_address: SocketAddr,
        timeout: Duration,
    ) -> Option<quinn::Connection> {
        let rx = {
            let mut map = self.map.write().await;
            match map.entry(peer_address) {
                // This peer has already been mapped, determine the state.
                hash_map::Entry::Occupied(mut e) => {
                    let rx = match e.get_mut() {
                        // If the peer is already connected, return the connection.
                        IncomingPeerState::Connected(c) => {
                            // Check if the connection is still alive.
                            if let Some(r) = c.close_reason() {
                                if cfg!(debug_assertions) {
                                    tracing::warn!(
                                        "Peer connection {peer_address} is already closed: {r}"
                                    );
                                } else {
                                    tracing::warn!("Peer connection is already closed: {r}");
                                }
                                None
                            } else {
                                if cfg!(debug_assertions) {
                                    tracing::debug!(
                                        "Awaited peer connection {peer_address} is already established"
                                    );
                                } else {
                                    tracing::debug!(
                                        "Awaited peer connection is already established"
                                    );
                                }
                                return Some(c.clone());
                            }
                        }

                        // Otherwise, append another receiver to the list.
                        IncomingPeerState::Awaiting(v) => {
                            if cfg!(debug_assertions) {
                                tracing::debug!(
                                    "Joining wait at index {} for peer connection {peer_address}",
                                    v.len()
                                );
                            } else {
                                tracing::debug!(
                                    "Joining wait at index {} for peer connection",
                                    v.len()
                                );
                            }

                            let (tx, rx) = tokio::sync::oneshot::channel();
                            v.push(tx);

                            // Return the receive channel for awaiting.
                            Some(rx)
                        }
                    };

                    if let Some(rx) = rx {
                        rx
                    } else {
                        if cfg!(debug_assertions) {
                            tracing::debug!("Creating wait for peer connection {peer_address}");
                        } else {
                            tracing::debug!("Creating wait for peer connection");
                        }
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        e.insert(IncomingPeerState::Awaiting(vec![tx]));
                        rx
                    }
                }

                // No mapping exists for this peer address, create one.
                hash_map::Entry::Vacant(e) => {
                    if cfg!(debug_assertions) {
                        tracing::debug!("Creating wait for peer connection {peer_address}");
                    } else {
                        tracing::debug!("Creating wait for peer connection");
                    }

                    let (tx, rx) = tokio::sync::oneshot::channel();
                    e.insert(IncomingPeerState::Awaiting(vec![tx]));

                    // Return the receive channel for awaiting.
                    rx
                }
            }
        };

        // Wait for the peer to connect or timeout.
        let incoming_connection = tokio::time::timeout(timeout, rx.into_future())
            .await
            .ok()
            .and_then(Result::ok);

        // Log the time when the incoming wait completes.
        tracing::debug!("Peer connection awaited");

        incoming_connection
    }

    /// Accept a peer connection and hand-off to any threads awaiting the connection.
    /// If a connection is mapped for the peer, it is replaced with the new connection.
    #[tracing::instrument(skip_all)]
    async fn accept_peer(&self, connection: quinn::Connection) {
        let mut map = self.map.write().await;
        let peer_address = connection.remote_address();
        match map.entry(peer_address) {
            // Update the entry and handle any waiting threads.
            hash_map::Entry::Occupied(mut e) => {
                let old = e.insert(IncomingPeerState::Connected(connection.clone()));

                // Let all waiting threads know that the peer has connected.
                if let IncomingPeerState::Awaiting(txs) = old {
                    for tx in txs {
                        // Fails if the receiver is no longer waiting for this message.
                        if tx.send(connection.clone()).is_err() {
                            tracing::warn!(
                                "Waiting thread closed before peer connection was accepted"
                            );
                        }
                    }
                }
            }

            // Create a new entry for the peer connection.
            hash_map::Entry::Vacant(e) => {
                e.insert(IncomingPeerState::Connected(connection));
            }
        }

        if cfg!(debug_assertions) {
            tracing::debug!("Peer connection accepted by manager: {peer_address}");
        } else {
            tracing::debug!("Peer connection accepted by manager");
        }
    }

    /// Remove a specific peer connection from the manager, with asynchronous lock behavior.
    #[tracing::instrument(skip(self, peer_address))]
    pub async fn remove_peer(&mut self, peer_address: SocketAddr, connection_id: usize) {
        // Remove entry for peer if the stable IDs match.
        match self.map.write().await.entry(peer_address) {
            hash_map::Entry::Occupied(e) => {
                if let IncomingPeerState::Connected(c) = e.get() {
                    if c.stable_id() == connection_id {
                        e.remove();
                        tracing::info!("Connection manager removed peer");
                    } else {
                        tracing::debug!(
                            "Connection manager found peer, but stable IDs did not match"
                        );
                    }
                }
            }

            hash_map::Entry::Vacant(_) => {
                tracing::warn!("Connection manager asked to remove a non-existent peer");
            }
        }
    }

    /// Create a new task to manage incoming peer connections in the background.
    #[tracing::instrument(skip_all)]
    pub async fn manage_incoming_loop(endpoint: quinn::Endpoint) {
        let manager = Self::instance();

        // Use a timer to avoid spamming logging in case of bad endpoint state.
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.tick().await; // Skip the first tick.

        while let Some(connecting) = endpoint.accept().await {
            let connecting = match connecting.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to accept an incoming peer connection: {e}");

                    // Skip incomplete connections.
                    interval.tick().await;
                    continue;
                }
            };
            let connection = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to complete a peer connection: {e}");

                    // Skip incomplete connections.
                    interval.tick().await;
                    continue;
                }
            };

            // Notify any thread waiting for this connection if available, and store it.
            manager.accept_peer(connection).await;
        }

        tracing::debug!("Incoming peer connection loop closed");
    }

    /// Iterate over all peers and collect the result.
    pub fn filter_map<F, T>(&self, map: F) -> Vec<T>
    where
        F: Fn((&SocketAddr, &IncomingPeerState)) -> Option<T>,
    {
        self.map.blocking_read().iter().filter_map(map).collect()
    }

    /// Get the connection state of a peer.
    /// # Panics
    /// Cannot be used in async contexts. Will panic if used in an async runtime.
    pub fn get_connection_sync(&self, peer_address: SocketAddr) -> Option<quinn::Connection> {
        if let hash_map::Entry::Occupied(e) = self.map.blocking_write().entry(peer_address) {
            if let IncomingPeerState::Connected(c) = e.get() {
                // Check if the connection is still alive.
                if let Some(r) = c.close_reason() {
                    if cfg!(debug_assertions) {
                        tracing::warn!("Peer connection {peer_address} is already closed: {r}");
                    } else {
                        tracing::warn!("Peer connection is already closed: {r}");
                    }
                    e.remove();
                } else {
                    if cfg!(debug_assertions) {
                        tracing::debug!(
                            "Synchronous get for peer connection {peer_address} is already established"
                        );
                    } else {
                        tracing::debug!(
                            "Synchronous get for peer connection is already established"
                        );
                    }
                    return Some(c.clone());
                }
            }
        }
        None
    }

    /// Get the connection state of a peer.
    pub async fn get_connection_async(
        &self,
        peer_address: SocketAddr,
    ) -> Option<quinn::Connection> {
        if let hash_map::Entry::Occupied(e) = self.map.write().await.entry(peer_address) {
            if let IncomingPeerState::Connected(c) = e.get() {
                // Check if the connection is still alive.
                if let Some(r) = c.close_reason() {
                    if cfg!(debug_assertions) {
                        tracing::warn!("Peer connection {peer_address} is already closed: {r}");
                    } else {
                        tracing::warn!("Peer connection is already closed: {r}");
                    }
                    e.remove();
                } else {
                    if cfg!(debug_assertions) {
                        tracing::debug!(
                            "Asynchronous get for peer connection {peer_address} is already established"
                        );
                    } else {
                        tracing::debug!(
                            "Asynchronous get for peer connection is already established"
                        );
                    }
                    return Some(c.clone());
                }
            }
        }
        None
    }
}

/// Allow peers to connect using self-signed certificates.
/// Necessary for using the QUIC protocol with peer-to-peer connections where
/// peers likely won't have a certificate signed by a certificate authority.
#[derive(Debug)]
struct SkipServerCertVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerCertVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

/// Skip server certificate verification. Still verify signatures.
impl rustls::client::danger::ServerCertVerifier for SkipServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a QUIC client config that will skip server verification.
/// # Panics
/// If the conversion from `Duration` to `IdleTimeout` fails.
fn configure_peer_verification() -> quinn::ClientConfig {
    // TODO: Use a secure client configuration when connecting to the server.
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerCertVerification::new())
            .with_no_client_auth(),
    )
    .expect("Failed to create a QUIC client configuration");

    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));

    // Set custom keep alive policies.
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        file_yeet_shared::QUIC_TIMEOUT_MILLIS,
    ))));

    // Send keep alive packets at a fraction of the idle timeout.
    transport_config.keep_alive_interval(Some(Duration::from_millis(
        file_yeet_shared::QUIC_TIMEOUT_MILLIS as u64 / 6,
    )));
    client_config.transport_config(Arc::new(transport_config));

    client_config
}
