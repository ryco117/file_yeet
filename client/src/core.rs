use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{local_now_fmt, SocketAddrHelper, MAX_SERVER_COMMUNICATION_SIZE};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Use a sane default timeout for server connections.
pub const SERVER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
pub const PEER_LISTEN_TIMEOUT: Duration = Duration::from_secs(5);
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Define a sane number of maximum retries.
pub const MAX_PEER_CONNECTION_RETRIES: usize = 3;

/// Define the maximum size of a payload for peer communication.
/// QUIC may choose to fragment the payload, but this isn't a concern.
pub const MAX_PEER_COMMUNICATION_SIZE: usize = 8192;

/// Specify whether any existing port forwarding can be used or if a new mapping should be attempted.
pub enum PortMappingConfig {
    None,
    PortForwarding(NonZeroU16),
    TryNatPmp,
}

/// The command relationship between the two peers. Useful for asserting synchronization roles based on the command type.
#[derive(Clone, Copy)]
pub enum FileYeetCommandType {
    Pub,
    Sub,
}

/// Create a QUIC endpoint connected to the server and perform basic setup.
pub async fn prepare_server_connection(
    server_address: Option<&str>,
    server_port: NonZeroU16,
    suggested_gateway: Option<&str>,
    port_config: PortMappingConfig,
    bb: &mut bytes::BytesMut,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    Option<crab_nat::PortMapping>,
) {
    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()
        .expect("Failed to generate self-signed certificate");
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)
        .expect("Quinn failed to accept the server certificates");

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Create our QUIC endpoint. Use an unspecified address and port since we don't have any preference.
    let mut endpoint = quinn::Endpoint::server(
        server_config,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    )
    .expect("Failed to open QUIC endpoint");

    // Share debug information about the QUIC endpoints.
    let mut local_address = endpoint
        .local_addr()
        .expect("Failed to get the local address of our QUIC endpoint");
    if local_address.ip().is_unspecified() {
        local_address.set_ip(
            default_net::interface::get_local_ipaddr().expect("Failed to get our local address"),
        );
    }
    println!(
        "{} QUIC endpoint created with address: {local_address}",
        local_now_fmt()
    );

    // Attempt to get a port forwarding, starting with user's override and then attempting NAT-PMP and PCP.
    let gateway = if let Some(g) = suggested_gateway {
        g.parse().expect("Failed to parse gateway address")
    } else {
        default_net::get_default_gateway()
            .expect("Failed to get the default gateway")
            .ip_addr
    };
    let (port_mapping, port_override) = match port_config {
        PortMappingConfig::PortForwarding(p) => (None, Some(p)),

        // Allow the user to skip port mapping.
        PortMappingConfig::TryNatPmp => match try_port_mapping(gateway, local_address).await {
            Ok(m) => {
                let p = NonZeroU16::new(m.external_port()).expect("Failed to get a non-zero port");
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

    // Use an insecure client configuration when connecting to peers.
    // TODO: Use a secure client configuration when connecting to the server.
    endpoint.set_default_client_config(configure_peer_verification());
    // Connect to the public file_yeet_server.
    let connection = connect_to_server(server_address, server_port, &endpoint).await;

    // Read the server's response to the sanity check.
    let (sanity_check_addr, sanity_check) = socket_ping_request(&connection).await;
    println!("{} Server sees us as {sanity_check}", local_now_fmt());

    if let Some(port) = port_override {
        // Only send a port override request if the server sees us through a different port.
        if sanity_check_addr.port() != port.get() {
            port_override_request(&connection, port, bb).await;
        }
    }

    (endpoint, connection, port_mapping)
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
    server_address: Option<&str>,
    server_port: NonZeroU16,
    endpoint: &quinn::Endpoint,
) -> quinn::Connection {
    // Reused error message string.
    const SERVER_CONNECTION_ERR: &str = "Failed to establish a QUIC connection to the server";

    // Get the server address info.
    let SocketAddrHelper {
        addr: server_address,
        hostname,
    } = file_yeet_shared::get_server_or_default(server_address, server_port)
        .expect("Failed to parse server address");
    println!(
        "{} Connecting to server {hostname} at socket address: {server_address}",
        local_now_fmt()
    );

    // Attempt to connect to the server using QUIC.
    let connection = match tokio::time::timeout(
        SERVER_CONNECTION_TIMEOUT,
        endpoint
            .connect(server_address, hostname.as_str())
            .expect("Failed to open a QUIC connection to the server"),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            panic!("{} {SERVER_CONNECTION_ERR}: {e}", local_now_fmt());
        }
        Err(e) => {
            panic!("{} {SERVER_CONNECTION_ERR}: Timeout {e:#}", local_now_fmt());
        }
    };
    println!("{} QUIC connection made to the server", local_now_fmt());
    connection
}

/// Perform a socket ping request to the server and sanity chech the response.
/// Returns the server's address and the string encoding it was sent as.
pub async fn socket_ping_request(server_connection: &quinn::Connection) -> (SocketAddr, String) {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .expect("Failed to open a bi-directional QUIC stream for a socket ping request")
        .into();

    // Perform a sanity check by sending the server a socket ping request.
    // This allows us to verify that the server can determine our public address.
    server_streams
        .send
        .write_u16(file_yeet_shared::ClientApiRequest::SocketPing as u16)
        .await
        .expect("Failed to send a socket ping request to the server");

    // Read the server's response to the sanity check.
    let string_len = server_streams
        .recv
        .read_u16()
        .await
        .expect("Failed to read a u16 response from the server");
    let sanity_check = expect_server_text(&mut server_streams.recv, string_len)
        .await
        .expect("Failed to read a valid socket address from the server");
    let sanity_check_addr: SocketAddr = sanity_check
        .parse()
        .expect("Server did not send a valid socket address for the sanity check");

    (sanity_check_addr, sanity_check)
}

pub async fn port_override_request(
    server_connection: &quinn::Connection,
    port: NonZeroU16,
    bb: &mut bytes::BytesMut,
) {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .expect("Failed to open a bi-directional QUIC stream for a socket ping request")
        .into();

    // Format a port override request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16);
    bb.put_u16(port.get());
    // Send the port override request to the server and clear the buffer.
    server_streams
        .send
        .write_all(bb)
        .await
        .expect("Failed to send the port override request to the server");
    bb.clear();
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
    local_address: SocketAddr,
    peer_address: SocketAddr,
) -> Option<(quinn::Connection, BiStream)> {
    // Create a lock for where we will place the QUIC connection used to communicate with our peer.
    let peer_reached_lock: Arc<Mutex<bool>> = Arc::default();

    // Spawn a thread that listens for a peer and will set the boolean lock when connected.
    let peer_reached_listen = peer_reached_lock.clone();
    let endpoint_listen = endpoint.clone();
    let listen_future = tokio::time::timeout(
        PEER_LISTEN_TIMEOUT,
        listen_for_peer(endpoint_listen, local_address, &peer_reached_listen),
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
    local_address: SocketAddr,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<quinn::Connection> {
    // Print and create binding from the local address.
    println!(
        "{} Listening for peer on the QUIC endpoint: {local_address}",
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
    transport_config.keep_alive_interval(Some(Duration::from_secs(60)));
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
