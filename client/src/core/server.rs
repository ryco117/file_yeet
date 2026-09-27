use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{BiStream, HashBytes, ReadIpPortError, SocketAddrHelper, HASH_BYTE_COUNT};
use futures_util::TryFutureExt as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::core::{
    default_transport_config, instant_to_datetime_string, probe_local_address, read_error_from_io,
    try_port_mapping, PortMappingConfig, ProbeLocalAddressError,
};

/// A prepared server connection with relevant local and server connection info.
#[derive(Clone, Debug)]
pub struct PreparedConnection {
    pub server_connection: quinn::Connection,
    pub port_mapping: Option<crab_nat::PortMapping>,
    pub external_address: (SocketAddr, String),
}

/// Errors that may occur when preparing the client's network identity and the server connection.
#[derive(Debug, thiserror::Error)]
pub enum PrepareConnectionError {
    #[error("{0}")]
    ConnectToServer(#[from] ConnectToServerError),

    #[error("{0}")]
    LocalAddress(#[from] ProbeLocalAddressError),

    #[error("Invalid gateway address: {0}")]
    InvalidGatewayAddress(std::net::AddrParseError),

    #[error("Unknown gateway address: {0}")]
    UnknownGatewayAddress(String),

    #[error("Socket ping request failed: {0}")]
    SocketPing(#[from] SocketPingError),

    #[error("{0}")]
    PortOverride(#[from] PortOverrideError),
}

/// Create a QUIC endpoint connected to the server and perform basic setup.
/// Will attempt to infer optional arguments from the system if not specified.
#[tracing::instrument(skip_all)]
pub async fn prepare_server_connection(
    endpoint: &quinn::Endpoint,
    server_socket: SocketAddrHelper,
    suggested_gateway: Option<&str>,
    external_port_config: PortMappingConfig,
    skip_server_cert_validation: bool,
) -> Result<PreparedConnection, PrepareConnectionError> {
    tracing::debug!("Connecting to server {server_socket:?}");

    // Connect to the specified `file_yeet` server.
    let connection = connect(endpoint, server_socket, skip_server_cert_validation).await?;

    // Share debug information about the QUIC endpoints.
    let mut local_address = endpoint
        .local_addr()
        .expect("Failed to get the local address of our QUIC endpoint");
    if local_address.ip().is_unspecified() {
        local_address.set_ip(probe_local_address(
            connection.remote_address().ip().into(),
        )?);
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
            port_override_request(&connection, port).await?;
            sanity_check.0.set_port(port.get());
        }
    }

    Ok(PreparedConnection {
        server_connection: connection,
        port_mapping,
        external_address: sanity_check,
    })
}

/// Build a QUIC client config that will validate server addresses.
/// # Errors
/// If the QUIC client configuration cannot be created from the Rustls client configuration with platform verifier.
fn configure_server_verification() -> Result<quinn::ClientConfig, rustls::Error> {
    let mut client_config = quinn::ClientConfig::try_with_platform_verifier()?;
    client_config.transport_config(default_transport_config());
    Ok(client_config)
}

/// Use a sane default timeout for server connections.
pub const SERVER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Error that may occur when attempting to connect to the server.
#[derive(Debug, thiserror::Error)]
pub enum ConnectToServerError {
    /// Failed to create a default QUIC client configuration for server verification.
    #[error("Failed to configure default server certificate verification: {0}")]
    TlsConfiguration(#[from] rustls::Error),

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
/// Optionally, skip server certificate validation by using the default peer configuration.
#[tracing::instrument(skip(endpoint))]
async fn connect(
    endpoint: &quinn::Endpoint,
    server_socket: SocketAddrHelper,
    skip_server_cert_validation: bool,
) -> Result<quinn::Connection, ConnectToServerError> {
    // Attempt to connect to the server using QUIC.
    let connection: quinn::Connection = tokio::time::timeout(
        SERVER_CONNECTION_TIMEOUT,
        if skip_server_cert_validation {
            endpoint.connect(server_socket.address, server_socket.hostname.as_str())
        } else {
            endpoint.connect_with(
                configure_server_verification()?,
                server_socket.address,
                server_socket.hostname.as_str(),
            )
        }?,
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
#[tracing::instrument(skip(server_connection))]
pub async fn port_override_request(
    server_connection: &quinn::Connection,
    port: NonZeroU16,
) -> Result<(), PortOverrideError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Format a port override request.
    let mut byte_buffer = [0u8; 2 + 2];
    let mut bb = &mut byte_buffer[..];
    bb.put_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16);
    bb.put_u16(port.get());

    // Send the port override request to the server and clear the buffer.
    server_streams.send.write_all(&byte_buffer).await?;

    Ok(())
}

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
    let mut send_buffer = [0u8; 2 + HASH_BYTE_COUNT + 8];
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
}

/// Perform a subscribe request to the server.
/// Returns a list of peers that are sharing the file and the file size they promise to send.
#[tracing::instrument(skip(server_connection, our_external_address))]
pub async fn subscribe(
    server_connection: &quinn::Connection,
    hash: HashBytes,
    our_external_address: Option<SocketAddr>,
) -> Result<Vec<(SocketAddr, u64)>, SubscribeError> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Send the server a subscribe request.
    let mut byte_buffer = [0u8; 2 + HASH_BYTE_COUNT];
    let mut bb = &mut byte_buffer[..];
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash.bytes[..]);
    server_streams.send.write_all(&byte_buffer).await?;

    tracing::info!("Requesting file with hash from the server...");

    // Determine if the server is responding with a success or failure.
    let response_count = server_streams.recv.read_u16().await.map_err(|e| {
        read_error_from_io(
            e,
            SubscribeError::ReadSizeFailedWithError,
            SubscribeError::ReadSizeFailedWithKind,
        )
    })?;

    if response_count == 0 {
        // No peers are sharing the file.
        return Ok(Vec::new());
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
            read_error_from_io(
                e,
                SubscribeError::ReadSizeFailedWithError,
                SubscribeError::ReadSizeFailedWithKind,
            )
        })?;

        if our_external_address.is_some_and(|a| a == peer_address) {
            tracing::debug!("Skipping our own address from the server response");
            continue;
        }

        peers.push((peer_address, file_size));
    }

    Ok(peers)
}
