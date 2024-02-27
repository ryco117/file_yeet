use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU16,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{local_now_fmt, HashBytes, SocketAddrHelper, MAX_SERVER_COMMUNICATION_SIZE};
use sha2::Digest as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _},
    sync::RwLock,
};

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
#[derive(Clone, Copy)]
pub enum FileYeetCommandType {
    Pub,
    Sub,
}

/// A prepared server connection, local QUIC endpoint, and optional port mapping.
#[derive(Clone, Debug)]
pub struct PreparedConnection {
    pub endpoint: quinn::Endpoint,
    pub server_connection: quinn::Connection,
    pub port_mapping: Option<crab_nat::PortMapping>,
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
        .expect("Quinn failed to accept the server certificates");

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
        local_address.set_ip({
            let interface = default_net::get_default_interface()
                .map_err(|e| anyhow::anyhow!("Failed to get a default interface: {e}"))?;
            if using_ipv4 {
                IpAddr::V4(
                    interface
                        .ipv4
                        .first()
                        .ok_or_else(|| anyhow::anyhow!("Failed to get a default IPv4 address:"))?
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
            }
        });
    }
    println!(
        "{} QUIC endpoint created with address: {local_address}",
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
        PortMappingConfig::PortForwarding(p) => (None, Some(p)),

        // Allow the user to skip port mapping.
        PortMappingConfig::PcpNatPmp(_) => match try_port_mapping(gateway, local_address).await {
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
        },
        PortMappingConfig::None => (None, None),
    };

    // Read the server's response to the sanity check.
    let (sanity_check_addr, sanity_check) = socket_ping_request(&connection).await?;
    println!("{} Server sees us as {sanity_check}", local_now_fmt());

    if let Some(port) = port_override {
        // Only send a port override request if the server sees us through a different port.
        if sanity_check_addr.port() != port.get() {
            port_override_request(&connection, port, bb).await?;
        }
    }

    Ok(PreparedConnection {
        endpoint,
        server_connection: connection,
        port_mapping,
    })
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
        crab_nat::PortMappingOptions::default(),
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
    bb.put_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16);
    bb.put_u16(port.get());

    // Send the port override request to the server and clear the buffer.
    server_streams.send.write_all(bb).await?;
    bb.clear();

    Ok(())
}

/// Perform a subscribe request to the server. Returns a list of peers that are sharing the file.
pub async fn subscribe(
    server_connection: &quinn::Connection,
    bb: &mut bytes::BytesMut,
    hash: HashBytes,
) -> anyhow::Result<Vec<SocketAddr>> {
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

    let mut scratch_space = [0; MAX_SERVER_COMMUNICATION_SIZE];
    let mut peers = Vec::new();

    // Parse each peer socket address.
    for _ in 0..response_count {
        let address_len = server_streams
            .recv
            .read_u16()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response from server: {e}"))?
            as usize;
        let peer_string_bytes = &mut scratch_space[..address_len];
        server_streams
            .recv
            .read_exact(peer_string_bytes)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to read a valid UTF-8 response from the server: {e}")
            })?;
        let peer_address_str = std::str::from_utf8(peer_string_bytes)
            .map_err(|e| anyhow::anyhow!("Server did not send a valid UTF-8 response: {e}"))?;
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

        peers.push(peer_address);
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
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<(quinn::Connection, BiStream)> {
    // Create a lock for where we will place the QUIC connection used to communicate with our peer.
    let peer_reached_lock: Arc<Mutex<bool>> = Arc::default();

    // Spawn a thread that listens for a peer and will set the boolean lock when connected.
    let peer_reached_listen = peer_reached_lock.clone();
    let endpoint_listen = endpoint.clone();
    let listen_future = tokio::time::timeout(
        PEER_LISTEN_TIMEOUT,
        listen_for_peer(endpoint_listen, &peer_reached_listen),
    );

    // Attempt to connect to the peer's public address.
    let connect_future = tokio::time::timeout(
        PEER_CONNECT_TIMEOUT,
        connect_to_peer(endpoint, peer_address, &peer_reached_lock),
    );

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    let listen_stream = listen_stream.ok().flatten();
    let connect_stream = connect_stream.ok().flatten();
    let connection = match u32::from(listen_stream.is_some()) + u32::from(connect_stream.is_some())
    {
        0 => None,
        1 => listen_stream.or(connect_stream),
        2 => {
            // TODO: It could be interesting and possible to create a more general stream negotiation.
            //       For example, if each peer sent a random nonce over each stream, and the nonces were XOR'd per stream,
            //       the result could be used to determine which stream to use (highest/lowest resulting nonce after XOR).
            match cmd {
                FileYeetCommandType::Pub => listen_stream,
                FileYeetCommandType::Sub => connect_stream,
            }
        }
        _ => unreachable!("Not possible to have more than two streams"),
    }?;

    let peer_streams: BiStream = tokio::time::timeout(Duration::from_millis(400), async {
        let streams = match cmd {
            FileYeetCommandType::Pub => {
                // Open a bi-directional stream.
                connection.open_bi().await
            }
            FileYeetCommandType::Sub => {
                // Let the uploading peer open a bi-directional stream.
                connection.accept_bi().await
            }
        };
        if let Ok(streams) = streams {
            Some(streams.into())
        } else {
            None
        }
    })
    .await
    .ok()
    .flatten()?;

    // Let the user know that a connection is established. A bi-directional stream is ready to use.
    println!("{} Peer connection established", local_now_fmt());

    Some((connection, peer_streams))
}

/// Spawn a thread that listens for a peer and will assign the peer `Connection` lock when connected.
async fn listen_for_peer(
    endpoint: quinn::Endpoint,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<quinn::Connection> {
    // Print and create binding from the local address.
    println!(
        "{} Listening for peer on the QUIC endpoint",
        local_now_fmt()
    );

    // Accept a peer connection.
    let connecting = endpoint.accept().await?;
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

    // Set the peer stream lock to the listening stream if there isn't already one present.
    *peer_reached_lock
        .lock()
        .expect("Could not obtain the mutex lock") = true;

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
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<quinn::Connection> {
    // Set a sane number of connection retries.
    let mut retries = MAX_PEER_CONNECTION_RETRIES;

    // Ensure we have retries left and there isn't already a peer `Connection` to use.
    while retries > 0
        && !*peer_reached_lock
            .lock()
            .expect("Could not obtain the mutex lock")
    {
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
                // Set the peer mutex to the connected stream if there isn't already one present.
                *peer_reached_lock
                    .lock()
                    .expect("Could not obtain the mutex lock") = true;

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
    #[error("The downloaded file hash does not match the expected hash")]
    HashMismatch,
}

/// Download a file from the peer. Initiates the download by consenting to the peer to receive the file.
pub async fn download_from_peer(
    hash: HashBytes,
    mut peer_streams: BiStream,
    file_size: u64,
    output: &Path,
    byte_progress: Option<Arc<RwLock<u64>>>,
) -> Result<(), DownloadError> {
    // Open the file for writing.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output)
        .await
        .map_err(DownloadError::IoError)?;

    // Let the peer know that we accepted the download.
    peer_streams
        .send
        .write_u8(1)
        .await
        .map_err(DownloadError::IoError)?;
    peer_streams
        .send
        .finish()
        .await
        .map_err(|e| DownloadError::IoError(e.into()))?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];
    // Read from the peer and write to the file.
    let mut bytes_written = 0;
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
                *progress.write().await = bytes_written;
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
        output.display()
    );
    Ok(())
}

/// Get a file's size and its SHA-256 hash.
pub async fn file_size_and_hash(file_path: &Path) -> anyhow::Result<(u64, HashBytes)> {
    let mut hasher = sha2::Sha256::new();
    let mut reader = tokio::io::BufReader::new(
        tokio::fs::File::open(file_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open the file: {e}"))?,
    );
    let mut hash_byte_buffer = [0; 8192];
    loop {
        let n = reader
            .read(&mut hash_byte_buffer)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read from the file: {e}"))?;
        if n == 0 {
            break;
        }

        hasher.update(&hash_byte_buffer[..n]);
    }
    let file_size = reader
        .seek(tokio::io::SeekFrom::End(0))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to seek to the end of the file: {e}"))?;
    let hash: HashBytes = hasher.finalize().into();

    Ok((file_size, hash))
}

/// Upload the file to the peer. Ensure they consent to the file size before sending the file.
pub async fn upload_to_peer(
    mut peer_streams: BiStream,
    file_size: u64,
    mut reader: tokio::io::BufReader<tokio::fs::File>,
) -> anyhow::Result<()> {
    // Ensure that the file reader is at the start before the upload.
    reader.rewind().await?;

    // Send the file size to the peer.
    peer_streams.send.write_u64(file_size).await?;

    // Read the peer's response to the file size.
    let response = peer_streams.recv.read_u8().await?;
    if response == 0 {
        println!("{} Peer cancelled the upload", local_now_fmt());
        return Ok(());
    }

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PEER_COMMUNICATION_SIZE];
    // Read from the file and write to the peer.
    loop {
        // Read a natural amount of bytes from the file.
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Write the bytes to the peer.
        peer_streams.send.write_all(&buf[..n]).await?;
    }

    // Greacefully close our connection after all data has been sent.
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
    transport_config.keep_alive_interval(Some(Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport_config));

    client_config
}

/// Helper type for grouping a bi-directional stream, instead of the default tuple type.
pub struct BiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}
impl From<(quinn::SendStream, quinn::RecvStream)> for BiStream {
    fn from((send, recv): (quinn::SendStream, quinn::RecvStream)) -> Self {
        Self { send, recv }
    }
}
