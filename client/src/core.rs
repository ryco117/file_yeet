use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU16,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{
    local_now_fmt, BiStream, HashBytes, SocketAddrHelper, MAX_SERVER_COMMUNICATION_SIZE,
};
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

/// Use a sane default timeout for server connections.
pub const SERVER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
/// Sane default timeout for listening for a peer.
pub const PEER_LISTEN_TIMEOUT: Duration = Duration::from_secs(3);
/// Sane default timeout for peer connection attempts. Should try to connect for a longer time than listening.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Define a sane number of maximum retries.
pub const MAX_PEER_CONNECTION_RETRIES: usize = 3;

/// Define the maximum size of a payload for peer communication.
/// QUIC may choose to fragment the payload when sending raw packets, but this isn't a concern.
/// The limit is mainly meant to set reasonable memory usage for a stream.
pub const MAX_PEER_COMMUNICATION_SIZE: usize = 16 * 1024;

/// Specify whether any existing port forwarding can be used or if a new mapping should be attempted.
pub enum PortMappingConfig {
    None,
    PortForwarding(NonZeroU16),
    PcpNatPmp(Option<crab_nat::PortMapping>),
}

/// The command relationship between the two peers. Useful for asserting synchronization roles based on the command type.
#[derive(Clone, Copy, Debug)]
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
    pub external_address: String,
}

/// Create a QUIC endpoint connected to the server and perform basic setup.
pub async fn prepare_server_connection(
    server_address: Option<&str>,
    server_port: NonZeroU16,
    suggested_gateway: Option<&str>,
    port_config: PortMappingConfig,
    bb: &mut bytes::BytesMut,
) -> anyhow::Result<PreparedConnection> {
    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()
        .expect("Failed to generate self-signed certificate");
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)
        .expect("Quinn failed to accept our generated certificates");

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Get the server address info.
    let server_socket = file_yeet_shared::get_server_or_default(server_address, server_port)?;
    println!(
        "{} Connecting to server {} at socket address: {}",
        local_now_fmt(),
        server_socket.hostname,
        server_socket.address,
    );

    let using_ipv4 = server_socket.address.is_ipv4();

    // Create our QUIC endpoint. Use an unspecified address and port since we don't have any preference.
    let mut endpoint = quinn::Endpoint::server(
        server_config,
        if using_ipv4 {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        },
    )?;

    // Use an insecure client configuration when connecting to peers.
    // TODO: Use a secure client configuration when connecting to the server.
    endpoint.set_default_client_config(configure_peer_verification());
    // Connect to the public file_yeet_server.
    let connection = connect_to_server(server_socket, &endpoint).await?;

    // Share debug information about the QUIC endpoints.
    let mut local_address = endpoint
        .local_addr()
        .expect("Failed to get the local address of our QUIC endpoint");
    if local_address.ip().is_unspecified() {
        local_address.set_ip(probe_local_address(using_ipv4)?);
    }
    println!(
        "{} QUIC endpoint created with local address: {local_address}",
        local_now_fmt()
    );

    // Attempt to get a port forwarding, starting with user's override and then attempting NAT-PMP and PCP.
    let gateway = if let Some(g) = suggested_gateway {
        g.parse()?
    } else {
        default_net::get_default_gateway()
            .map_err(|s| anyhow::anyhow!(s))?
            .ip_addr
    };
    let (port_mapping, port_override) = match port_config {
        // Use a port that is explicitly set by the user without PCP/NAT-PMP.
        PortMappingConfig::PortForwarding(p) => (None, Some(p)),

        // Attempt PCP and NAT-PMP port mappings to the gateway.
        PortMappingConfig::PcpNatPmp(None) => {
            match try_port_mapping(gateway, local_address).await {
                Ok(m) => {
                    let p = m.external_port();
                    println!(
                        "{} Success mapping external port {p} -> internal {}",
                        local_now_fmt(),
                        m.internal_port(),
                    );
                    (Some(m), Some(p))
                }
                Err(e) => {
                    eprintln!("{} Failed to create a port mapping: {e}", local_now_fmt());
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
    let (mut sanity_check_addr, sanity_check) = socket_ping_request(&connection).await?;
    println!("{} Server sees us as {sanity_check}", local_now_fmt());

    if let Some(port) = port_override {
        // Only send a port override request if the server sees us through a different port.
        if sanity_check_addr.port() != port.get() {
            port_override_request(&connection, port, bb).await?;
            sanity_check_addr.set_port(port.get());
        }
    }

    Ok(PreparedConnection {
        endpoint,
        server_connection: connection,
        port_mapping,
        external_address: sanity_check_addr.to_string(),
    })
}

/// Helper to determine the default interface's IP address.
fn probe_local_address(using_ipv4: bool) -> anyhow::Result<IpAddr> {
    let interface = default_net::get_default_interface()
        .map_err(|e| anyhow::anyhow!("Failed to get a default interface: {e}"))?;
    let ip = if using_ipv4 {
        IpAddr::V4(
            interface
                .ipv4
                .first()
                .ok_or_else(|| anyhow::anyhow!("Failed to get a default IPv4 address"))?
                .addr,
        )
    } else {
        IpAddr::V6(
            interface
                .ipv6
                .first()
                .ok_or_else(|| anyhow::anyhow!("Failed to get a default IPv6 address"))?
                .addr,
        )
    };

    Ok(ip)
}

/// Attempt to create a port mapping using NAT-PMP or PCP.
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

/// Connect to the server using QUIC.
async fn connect_to_server(
    server_socket: SocketAddrHelper,
    endpoint: &quinn::Endpoint,
) -> anyhow::Result<quinn::Connection> {
    // Reused error message string.
    const SERVER_CONNECTION_ERR: &str = "Failed to establish a QUIC connection to the server";

    // Attempt to connect to the server using QUIC.
    let connection = match tokio::time::timeout(
        SERVER_CONNECTION_TIMEOUT,
        endpoint.connect(server_socket.address, server_socket.hostname.as_str())?,
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            anyhow::bail!("{SERVER_CONNECTION_ERR}: {e}");
        }
        Err(e) => {
            anyhow::bail!("{SERVER_CONNECTION_ERR}: Timeout {e:#}");
        }
    };
    println!("{} QUIC connection made to the server", local_now_fmt());
    Ok(connection)
}

/// Perform a socket ping request to the server and sanity chech the response.
/// Returns the server's address and the string encoding it was sent as.
pub async fn socket_ping_request(
    server_connection: &quinn::Connection,
) -> anyhow::Result<(SocketAddr, String)> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection.open_bi().await?.into();

    // Perform a sanity check by sending the server a socket ping request.
    // This allows us to verify that the server can determine our public address.
    server_streams
        .send
        .write_u16(file_yeet_shared::ClientApiRequest::SocketPing as u16)
        .await?;

    // Read the server's response to the sanity check.
    let string_len = server_streams.recv.read_u16().await?;
    let sanity_check = expect_server_text(&mut server_streams.recv, string_len).await?;
    let sanity_check_addr: SocketAddr = sanity_check.parse()?;

    Ok((sanity_check_addr, sanity_check))
}

/// Perform a port override request to the server.
pub async fn port_override_request(
    server_connection: &quinn::Connection,
    port: NonZeroU16,
    bb: &mut bytes::BytesMut,
) -> anyhow::Result<()> {
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

/// Perform a publish request to the server.
pub async fn publish(
    server_connection: &quinn::Connection,
    mut bb: bytes::BytesMut,
    hash: HashBytes,
    file_size: u64,
) -> anyhow::Result<BiStream> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to open a bi-directional QUIC stream for a socket ping request {e}"
            )
        })?
        .into();

    // Format a publish request.
    bb.clear();
    bb.put_u16(file_yeet_shared::ClientApiRequest::Publish as u16);
    bb.put(&hash[..]);
    bb.put_u64(file_size);

    // Send the server a publish request.
    server_streams
        .send
        .write_all(&bb)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send a publish request to the server {e}"))?;

    Ok(server_streams)
}

/// Read a response to a publish request from the server.
pub async fn read_subscribing_peer(
    server_recv: &mut quinn::RecvStream,
) -> anyhow::Result<SocketAddr> {
    let data_len = server_recv
        .read_u16()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read response from the server: {e}"))?
        as usize;
    if data_len == 0 {
        anyhow::bail!("Server encountered and error");
    }
    if data_len > MAX_SERVER_COMMUNICATION_SIZE {
        anyhow::bail!("Server response length is invalid");
    }

    let mut scratch_space = [0; MAX_SERVER_COMMUNICATION_SIZE];
    let peer_string_bytes = &mut scratch_space[..data_len];
    if let Err(e) = server_recv.read_exact(peer_string_bytes).await {
        anyhow::bail!("Failed to read a response from the server: {e}");
    }

    // Parse the response as a peer socket address or skip this message.
    let peer_string = match std::str::from_utf8(peer_string_bytes) {
        Ok(s) => s,
        Err(e) => anyhow::bail!("Server did not send a valid UTF-8 response: {e}"),
    };
    let peer_address = match peer_string.parse() {
        Ok(addr) => addr,
        Err(e) => anyhow::bail!("Failed to parse peer address: {e}"),
    };

    Ok(peer_address)
}

/// Perform a subscribe request to the server.
/// Returns a list of peers that are sharing the file and the file size they promise to send.
pub async fn subscribe(
    server_connection: &quinn::Connection,
    bb: &mut bytes::BytesMut,
    hash: HashBytes,
) -> anyhow::Result<Vec<(SocketAddr, u64)>> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to open a bi-directional QUIC stream for a socket ping request: {e}"
            )
        })?
        .into();

    // Send the server a subscribe request.
    bb.clear();
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash[..]);
    server_streams
        .send
        .write_all(bb)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send a subscribe request to the server: {e}"))?;

    println!(
        "{} Requesting file with hash from the server...",
        local_now_fmt()
    );

    // Determine if the server is responding with a success or failure.
    let response_count = server_streams
        .recv
        .read_u16()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read a u16 response from the server: {e}"))?;

    if response_count == 0 {
        return Ok(Vec::with_capacity(0));
    }

    let mut peers = Vec::new();

    // Parse each peer socket address and file size.
    for _ in 0..response_count {
        // Read the incoming peer address length.
        let address_len = server_streams
            .recv
            .read_u8()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response from server: {e}"))?;

        // Read the incoming peer address to memory.
        let peer_address_str =
            expect_server_text(&mut server_streams.recv, u16::from(address_len)).await?;

        // Parse the peer address into a socket address.
        let peer_address = match peer_address_str.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} Failed to parse peer address {peer_address_str}: {e}",
                    local_now_fmt()
                );
                continue;
            }
        };

        // Read the incoming file size.
        let file_size = server_streams.recv.read_u64().await?;

        peers.push((peer_address, file_size));
    }

    Ok(peers)
}

/// Try to read a valid UTF-8 from the server until the expected length is reached.
async fn expect_server_text(stream: &mut quinn::RecvStream, len: u16) -> anyhow::Result<String> {
    let mut raw_bytes = [0; MAX_SERVER_COMMUNICATION_SIZE];
    let expected_slice = &mut raw_bytes[..len as usize];
    stream.read_exact(expected_slice).await?;
    Ok(std::str::from_utf8(expected_slice)?.to_owned())
}

/// Attempt to connect to peer using UDP hole punching.
pub async fn udp_holepunch(
    cmd: FileYeetCommandType,
    hash: HashBytes,
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<(quinn::Connection, BiStream)> {
    // Spawn a thread that listens for a peer and will set the boolean lock when connected.
    let endpoint_listen = endpoint.clone();
    let listen_future = tokio::time::timeout(
        PEER_LISTEN_TIMEOUT,
        listen_for_peer(endpoint_listen, peer_address),
    );

    // Attempt to connect to the peer's public address.
    let connect_future = tokio::time::timeout(
        PEER_CONNECT_TIMEOUT,
        connect_to_peer(endpoint, peer_address),
    );

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    let listen_stream = listen_stream.ok().flatten();
    let connect_stream = connect_stream.ok().flatten();
    let connections =
        // TODO: It could be interesting and possible to create a more general stream negotiation.
        //       For example, if each peer sent a random nonce over each stream, and the nonces were XOR'd per stream,
        //       the result could be used to determine which stream to use (highest/lowest resulting nonce after XOR).
        match cmd {
            FileYeetCommandType::Pub => listen_stream.into_iter().chain(connect_stream.into_iter()),
            FileYeetCommandType::Sub => connect_stream.into_iter().chain(listen_stream.into_iter()),
        };

    for connection in connections {
        if let Some(peer_streams) = peer_connection_into_stream(&connection, hash, cmd).await {
            // Let the user know that a connection is established. A bi-directional stream is ready to use.
            println!("{} Peer connection established", local_now_fmt());
            return Some((connection, peer_streams));
        }
    }
    None
}

/// Try to finalize a peer connection attempt by turning it into a bi-directional stream.
pub async fn peer_connection_into_stream(
    connection: &quinn::Connection,
    expected_hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Option<BiStream> {
    let streams = match cmd {
        FileYeetCommandType::Pub => {
            // Let the downloading peer initiate a bi-directional stream.
            let mut r = connection.accept_bi().await;
            if let Ok(s) = &mut r {
                let mut requested_hash = HashBytes::default();
                s.1.read_exact(&mut requested_hash).await.ok()?;

                // Ensure the requested hash matches the expected file hash.
                if requested_hash != expected_hash {
                    eprintln!(
                        "{} Peer requested a file with an unexpected hash",
                        local_now_fmt(),
                    );
                    return None;
                }

                println!("{} New peer stream accepted", local_now_fmt());
            }
            r
        }
        FileYeetCommandType::Sub => {
            // Open a bi-directional stream to the publishing peer.
            let mut r = connection.open_bi().await;
            if let Ok(s) = &mut r {
                s.0.write_all(&expected_hash).await.ok()?;

                println!("{} New peer stream opened", local_now_fmt());
            }
            r
        }
    };
    if let Ok(streams) = streams {
        Some(streams.into())
    } else {
        None
    }
}

/// Spawn a thread that listens for a peer and will assign the peer `Connection` lock when connected.
async fn listen_for_peer(
    endpoint: quinn::Endpoint,
    expected_peer: SocketAddr,
) -> Option<quinn::Connection> {
    // Print and create binding from the local address.
    println!(
        "{} Listening for peer on the QUIC endpoint",
        local_now_fmt()
    );

    // Accept a peer connection.
    let connecting = endpoint.accept().await?;

    // Ensure we are connecting to the expected peer.
    // TODO: Allow returning an unexpected peer connection to the caller to be routed appropriately.
    if connecting.remote_address() != expected_peer {
        eprintln!(
            "{} Peer connection from unexpected address: {}",
            local_now_fmt(),
            connecting.remote_address(),
        );
        return None;
    }

    let connection = match connecting.await {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!(
                "{} Failed to accept a peer connection: {e}",
                local_now_fmt()
            );
            return None;
        }
    };

    // Connected to a peer on the listening stream, print their address.
    let peer_addr = connection.remote_address();
    println!(
        "{} New connection accepted from peer at: {peer_addr:?}",
        local_now_fmt()
    );

    Some(connection)
}

/// Try to connect to a peer at the given address.
async fn connect_to_peer(
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<quinn::Connection> {
    // Set a sane number of connection retries.
    let mut retries = MAX_PEER_CONNECTION_RETRIES;

    // Ensure we have retries left and there isn't already a peer `Connection` to use.
    while retries > 0 {
        println!("{} Connecting to peer at {peer_address}", local_now_fmt());
        match endpoint.connect(peer_address, "peer") {
            Ok(connecting) => {
                let connection = match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} Failed to connect to peer: {e}", local_now_fmt());
                        retries -= 1;
                        continue;
                    }
                };

                println!("{} Connected to peer at {peer_address}", local_now_fmt());
                return Some(connection);
            }
            Err(e) => {
                eprintln!("{} Failed to connect to peer: {e}", local_now_fmt());
                retries -= 1;
            }
        }
    }

    None
}

/// Errors that may occur when downloading a file from a peer.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("An I/O error occurred: {0}")]
    IoError(std::io::Error),
    #[error("A write error occurred: {0}")]
    WriteError(quinn::WriteError),
    #[error("The downloaded file hash does not match the expected hash")]
    HashMismatch,
    #[error("Download lock was poisoned: {0}")]
    PoisonedLock(String),
}

/// Download a file from the peer. Initiates the download by consenting to the peer to receive the file.
#[allow(clippy::cast_precision_loss)]
pub async fn download_from_peer(
    hash: HashBytes,
    peer_streams: &mut BiStream,
    file_size: u64,
    output_path: &Path,
    bb: &mut bytes::BytesMut,
    byte_progress: Option<Arc<RwLock<f32>>>,
) -> Result<(), DownloadError> {
    // Open the file for writing.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output_path)
        .await
        .map_err(DownloadError::IoError)?;

    // Let the peer know which range we want to download using this QUIC stream.
    // Here we want the entire file.
    bb.clear();
    bb.put_u64(0); // Start at the beginning of the file.
    bb.put_u64(file_size); // Request the file's entire size.
    peer_streams
        .send
        .write(bb)
        .await
        .map_err(DownloadError::WriteError)?;
    peer_streams
        .send
        .finish()
        .await
        .map_err(|e| DownloadError::IoError(e.into()))?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];
    // Read from the peer and write to the file.
    let mut bytes_written = 0;
    let file_size_f = file_size as f32;
    let mut hasher = sha2::Sha256::new();
    while bytes_written < file_size {
        // Read a natural amount of bytes from the peer.
        let size = peer_streams
            .recv
            .read(&mut buf)
            .await
            .map_err(|e| DownloadError::IoError(e.into()))?
            .ok_or(DownloadError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Peer closed the upload early",
            )))?;

        if size > 0 {
            // Write the bytes to the file and update the hash.
            let bb = &buf[..size];
            let f = file.write_all(bb);
            // Update hash while future may be pending.
            hasher.update(bb);
            f.await.map_err(DownloadError::IoError)?;

            // Update the number of bytes written.
            bytes_written += size as u64;

            // Update the caller with the number of bytes written.
            if let Some(progress) = byte_progress.as_ref() {
                *progress
                    .write()
                    .map_err(|e| DownloadError::PoisonedLock(e.to_string()))? =
                    bytes_written as f32 / file_size_f;
            }
        }
    }

    // Ensure the file hash is correct.
    let downloaded_hash = hasher.finalize();
    if hash != Into::<HashBytes>::into(downloaded_hash) {
        return Err(DownloadError::HashMismatch);
    }

    // Let the user know that the download is complete.
    println!(
        "{} Download complete: {}",
        local_now_fmt(),
        output_path.display()
    );
    Ok(())
}

/// Get a file's size and its SHA-256 hash.
#[allow(clippy::cast_precision_loss)]
pub async fn file_size_and_hash(
    file_path: &Path,
    progress: Option<Arc<RwLock<f32>>>,
) -> anyhow::Result<(u64, HashBytes)> {
    let mut hasher = sha2::Sha256::new();
    let mut reader = tokio::io::BufReader::new(
        tokio::fs::File::open(file_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open the file: {e}"))?,
    );

    // Get the file size so we can report progress.
    let file_size = reader
        .seek(std::io::SeekFrom::End(0))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to seek in file: {e}"))?;

    // Reset the reader to the start of the file.
    reader
        .seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to seek in file: {e}"))?;

    let size_float = file_size as f32;
    let mut hash_byte_buffer = [0; 8192];
    let mut bytes_hashed = 0;
    loop {
        let n = reader
            .read(&mut hash_byte_buffer)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read from the file: {e}"))?;
        if n == 0 {
            break;
        }

        hasher.update(&hash_byte_buffer[..n]);
        bytes_hashed += n;

        // Update the caller with the number of bytes read.
        if let Some(progress) = progress.as_ref() {
            *progress
                .write()
                .map_err(|e| anyhow::anyhow!("Progress lock was poisoned: {e}"))? =
                bytes_hashed as f32 / size_float;
        }
    }
    let hash: HashBytes = hasher.finalize().into();

    Ok((file_size, hash))
}

/// Upload the file to the peer. Ensure they consent to the file size before sending the file.
#[allow(clippy::cast_precision_loss)]
pub async fn upload_to_peer(
    peer_streams: &mut BiStream,
    file_size: u64,
    mut reader: tokio::io::BufReader<tokio::fs::File>,
    byte_progress: Option<Arc<RwLock<f32>>>,
) -> anyhow::Result<()> {
    // Read the peer's desired upload range.
    let start_index = peer_streams.recv.read_u64().await?;
    let upload_length = peer_streams.recv.read_u64().await?;
    // Sanity check the upload range.
    match start_index.checked_add(upload_length) {
        Some(end) if end > file_size => anyhow::bail!("Invalid range requested, exceeds file size"),
        None => anyhow::bail!("Invalid range requested, 64-bit overflow 🫠"),
        Some(_) => {}
    }

    // Ensure that the file reader is at the starting index for the upload.
    reader.seek(std::io::SeekFrom::Start(start_index)).await?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];
    let mut bytes_read = 0;
    let upload_length_f = upload_length as f32;

    // Read from the file and write to the peer.
    while bytes_read < upload_length {
        // Read a natural amount of bytes from the file.
        let mut n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Ensure we don't send more bytes than were requested in the range.
        let remaining = upload_length - bytes_read;
        if (n as u64) > remaining {
            n = usize::try_from(remaining)?;
        }

        // Write the bytes to the peer.
        peer_streams.send.write_all(&buf[..n]).await?;

        // Update the number of bytes read.
        bytes_read += n as u64;

        // Update the caller with the number of bytes sent to the peer.
        if let Some(progress) = byte_progress.as_ref() {
            *progress
                .write()
                .map_err(|e| anyhow::anyhow!("Upload progress lock was poisoned: {e}"))? =
                bytes_read as f32 / upload_length_f;
        }
    }

    // Gracefully close our connection after all data has been sent.
    if let Err(e) = peer_streams.send.finish().await {
        eprintln!(
            "{} Failed to close the peer stream gracefully: {e}",
            local_now_fmt()
        );
    }

    // Let the user know that the upload is complete.
    println!("{} Upload complete!", local_now_fmt());
    Ok(())
}

/// Turn a byte count into a human readable string.
#[allow(clippy::cast_precision_loss)]
pub fn humanize_bytes(bytes: u64) -> String {
    human_bytes::human_bytes(bytes as f64)
}

/// Allow peers to connect using self-signed certificates.
/// Necessary for using the QUIC protocol.
#[derive(Debug)]
struct SkipAllServerVerification;

/// Skip all server verification.
impl rustls::client::ServerCertVerifier for SkipAllServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// Build a QUIC client config that will skip server verification.
/// # Panics
/// If the conversion from `Duration` to `IdleTimeout` fails.
fn configure_peer_verification() -> quinn::ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(SkipAllServerVerification {}))
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));

    // Set custom keep alive policies.
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(
        Duration::from_secs(file_yeet_shared::QUIC_TIMEOUT_SECONDS)
            .try_into()
            .expect("Failed to convert `Duration` to `IdleTimeout`"),
    ));

    // Send keep alive packets at a fraction of the idle timeout.
    transport_config.keep_alive_interval(Some(Duration::from_secs(
        file_yeet_shared::QUIC_TIMEOUT_SECONDS / 6,
    )));
    client_config.transport_config(Arc::new(transport_config));

    client_config
}
