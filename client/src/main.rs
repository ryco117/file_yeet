use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{local_now_fmt, HashBytes, SocketAddrHelper, MAX_PAYLOAD_SIZE};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Use a sane default timeout for server connections.
const SERVER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Define a sane number of maximum retries.
const MAX_PEER_CONNECTION_RETRIES: usize = 3;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The address of the rendezvous server. Either an IP address or a hostname.
    #[arg(short, long)]
    server_address: Option<String>,

    /// The server port to connect to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    server_port: u16,

    /// Override the port seen by the server to communicate a custom port to peers.
    /// Useful when port-forwarding.
    #[arg(short = 'o', long)]
    port_override: Option<u16>,

    /// The IP address of local gateway to use when attempting the Port Control Protocol.
    /// If not specified, a default gateway will be searched for.
    #[arg(short, long)]
    gateway: Option<String>,

    /// When enabled the client will attempt NAT-PMP and PCP port mapping protocols.
    #[arg(short, long)]
    nat_map: bool,

    #[command(subcommand)]
    cmd: FileYeetCommand,
}

#[derive(clap::Subcommand)]
enum FileYeetCommand {
    /// Publish a file to the server.
    Pub { file_path: String },
    /// Subscribe to a file from the server.
    Sub {
        file: Option<String>,
        sha256_hex: String,
    },
}

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    use clap::Parser as _;
    let args = Cli::parse();

    // Create a buffer for sending and receiving data within the payload size for `file_yeet`.
    let mut bb = bytes::BytesMut::with_capacity(MAX_PAYLOAD_SIZE);

    // Connect to the public file_yeet_server.
    let (endpoint, connection, server_send, server_recv, port_mapping) =
        prepare_server_connection(&args, &mut bb).await;

    // Determine if we are going to make a publish or subscribe request.
    match &args.cmd {
        // Try to hash and publish the file to the rendezvous server.
        FileYeetCommand::Pub { file_path } => {
            let file_path = std::path::Path::new(file_path);
            let mut hasher = Sha256::new();
            let mut reader = tokio::io::BufReader::new(
                tokio::fs::File::open(file_path)
                    .await
                    .expect("Failed to open the file"),
            );
            let mut hash_byte_buffer = [0; 8192];
            loop {
                let n = reader
                    .read(&mut hash_byte_buffer)
                    .await
                    .expect("Failed to read from the file");
                if n == 0 {
                    break;
                }

                hasher.update(&hash_byte_buffer[..n]);
            }
            let hash: HashBytes = hasher.finalize().into();
            let mut hex_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            println!(
                "{} File {} has SHA-256 hash: {}",
                local_now_fmt(),
                file_path.display(),
                faster_hex::hex_encode(&hash, &mut hex_bytes)
                    .expect("Failed to use a valid hex buffer"),
            );
            reader.rewind().await.expect("Failed to rewind the file");

            publish_loop(&args, endpoint, server_send, server_recv, bb, hash, reader).await;
        }
        // Try to get the file hash from the rendezvous server and peers.
        FileYeetCommand::Sub { sha256_hex, .. } => {
            let mut hash = HashBytes::default();
            if let Err(e) = faster_hex::hex_decode(sha256_hex.as_bytes(), &mut hash) {
                eprintln!("{} Failed to parse hex hash: {e}", local_now_fmt());
                return;
            };
            subscribe(&args, endpoint, server_send, server_recv, bb, hash).await;
        }
    }

    // Clean up the port mapping and close the server connection.
    if let Some(mapping) = port_mapping {
        // Try to safely delete the port mapping.
        if let Err((e, _)) = mapping.try_drop().await {
            eprintln!("{} Failed to delete the port mapping: {e}", local_now_fmt());
        } else {
            println!(
                "{} Successfully deleted the created port mapping",
                local_now_fmt()
            );
        }
    }
    connection.close(quinn::VarInt::from_u32(0), &[]);
}

/// Enter a loop to listen for the server to send peer socket addresses requesting our publish.
async fn publish_loop(
    args: &Cli,
    endpoint: quinn::Endpoint,
    mut server_send: quinn::SendStream,
    mut server_recv: quinn::RecvStream,
    mut bb: bytes::BytesMut,
    hash: HashBytes,
    mut _reader: tokio::io::BufReader<tokio::fs::File>,
) {
    // Format a publish request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::Publish as u16);
    bb.put(&hash[..]);
    // Send the server a publish request.
    server_send
        .write_all(&bb)
        .await
        .expect("Failed to send a publish request to the server");
    drop(bb);

    // Close the stream after completing the publish request.
    let _ = server_send.finish().await;

    // Enter a loop to listen for the server to send peer connections.
    loop {
        let data_len = server_recv
            .read_u16()
            .await
            .expect("Failed to read a u16 response from the server")
            as usize;
        if data_len == 0 {
            eprintln!("{} Server encountered and error", local_now_fmt());
            break;
        }
        if data_len > file_yeet_shared::MAX_PAYLOAD_SIZE {
            eprintln!("{} Server response length is invalid", local_now_fmt());
            break;
        }

        let mut scratch_space = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
        let peer_string_bytes = &mut scratch_space[..data_len];
        if let Err(e) = server_recv.read_exact(peer_string_bytes).await {
            eprintln!(
                "{} Failed to read a response from the server: {e}",
                local_now_fmt()
            );
            break;
        }

        // Parse the response as a peer socket address or skip this message.
        let peer_string = match std::str::from_utf8(peer_string_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} Server did not send a valid UTF-8 response: {e}",
                    local_now_fmt()
                );
                continue;
            }
        };
        let peer_address = match peer_string.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("{} Failed to parse peer address: {e}", local_now_fmt());
                continue;
            }
        };

        // Listen for a peer and assign the peer `Connection` lock when connected.
        let Some(peer_connection) = udp_holepunch(
            args,
            endpoint.clone(),
            endpoint
                .local_addr()
                .expect("Could not determine our local IP"),
            peer_address,
        )
        .await
        else {
            eprintln!("{} Failed to connect to peer", local_now_fmt());
            continue;
        };

        // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
        test_rwpl(peer_connection, false).await;
    }

    println!("Server connection closed");
}

async fn subscribe(
    args: &Cli,
    endpoint: quinn::Endpoint,
    mut server_send: quinn::SendStream,
    mut server_recv: quinn::RecvStream,
    mut bb: bytes::BytesMut,
    hash: HashBytes,
) {
    // Send the server a subscribe request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash[..]);
    server_send
        .write_all(&bb)
        .await
        .expect("Failed to send a subscribe request to the server");
    drop(bb);

    // Close the stream after completing the publish request.
    let _ = server_send.finish().await;

    // Determine if the server is responding with a success or failure.
    let response_size = server_recv
        .read_u16()
        .await
        .expect("Failed to read a u16 response from the server") as usize;
    if response_size == 0 {
        eprintln!("{} No publishers available for file hash", local_now_fmt());
        return;
    }
    if response_size > file_yeet_shared::MAX_PAYLOAD_SIZE {
        eprintln!("{} Server response length is invalid", local_now_fmt());
        return;
    }

    // Parse the response as a peer socket address.
    let mut scratch_space = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
    let peer_string_bytes = &mut scratch_space[..response_size];
    server_recv
        .read_exact(peer_string_bytes)
        .await
        .expect("Failed to read a valid UTF-8 response from the server");
    let peer_address: SocketAddr = std::str::from_utf8(peer_string_bytes)
        .expect("Server did not send a valid UTF-8 response")
        .parse::<SocketAddr>()
        .expect("Server did not send a valid socket address for the peer");

    // Connect to the peer and assign the peer `Connection` lock when connected.
    let local_address = endpoint
        .local_addr()
        .expect("Could not determine our local IP");
    let peer_connection = udp_holepunch(args, endpoint, local_address, peer_address)
        .await
        .expect("UDP hole punching failed");

    // TODO: Perform some handshake with the peer to discover the size of the file we're retrieving.
    test_rwpl(peer_connection, true).await;
}

/// Create a QUIC endpoint connected to the server and perform basic setup.
async fn prepare_server_connection(
    args: &Cli,
    bb: &mut bytes::BytesMut,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
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
    let gateway = if let Some(g) = args.gateway.as_ref() {
        g.parse().expect("Failed to parse gateway address")
    } else {
        default_net::get_default_gateway()
            .expect("Failed to get the default gateway")
            .ip_addr
    };
    let (port_mapping, port_override) = if let Some(p) = args.port_override {
        (None, Some(p))
    } else {
        // Allow the user to skip port mapping.
        let map_option = if args.nat_map {
            match crab_nat::PortMapping::new(
                gateway,
                local_address.ip(),
                crab_nat::InternetProtocol::Udp,
                std::num::NonZeroU16::new(local_address.port())
                    .expect("Socket address has no port"),
                crab_nat::PortMappingOptions::default(),
            )
            .await
            {
                Ok(m) => Some(m),
                Err(e) => {
                    eprintln!("{} Failed to create a port mapping: {e}", local_now_fmt());
                    None
                }
            }
        } else {
            None
        };
        if let Some(m) = map_option {
            let p = m.external_port();
            println!(
                "{} Success mapping external port {p} -> internal {}",
                local_now_fmt(),
                m.internal_port(),
            );
            (Some(m), Some(p))
        } else {
            (None, None)
        }
    };

    // Use an insecure client configuration when connecting to peers.
    // TODO: Use a secure client configuration when connecting to the server.
    endpoint.set_default_client_config(configure_peer_verification());
    // Connect to the public file_yeet_server.
    let connection = connect_to_server(args, &endpoint).await;

    // Create a bi-directional stream to the server.
    let (mut server_send, mut server_recv) = connection
        .open_bi()
        .await
        .expect("Failed to open a bi-directional QUIC stream to the server");

    // Perform a sanity check by sending the server a socket ping request.
    // This allows us to verify that the server can determine our public address.
    server_send
        .write_u16(file_yeet_shared::ClientApiRequest::SocketPing as u16)
        .await
        .expect("Failed to send a socket ping request to the server");

    // Read the server's response to the sanity check.
    let string_len = server_recv
        .read_u16()
        .await
        .expect("Failed to read a u16 response from the server");
    let sanity_check = expect_server_text(&mut server_recv, string_len)
        .await
        .expect("Failed to read a valid socket address from the server");
    let sanity_check_addr: SocketAddr = sanity_check
        .parse()
        .expect("Server did not send a valid socket address for the sanity check");
    println!("{} Server sees us as {sanity_check}", local_now_fmt());

    if let Some(port) = port_override {
        // Only send a port override request if the server sees us through a different port.
        if sanity_check_addr.port() != port {
            // Format a port override request.
            bb.put_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16);
            bb.put_u16(port);
            // Send the port override request to the server and clear the buffer.
            server_send
                .write_all(bb)
                .await
                .expect("Failed to send the port override request to the server");
            bb.clear();
        }
    }

    (endpoint, connection, server_send, server_recv, port_mapping)
}

/// Connect to the server using QUIC.
async fn connect_to_server(args: &Cli, endpoint: &quinn::Endpoint) -> quinn::Connection {
    // Reused error message string.
    const SERVER_CONNECTION_ERR: &str = "Failed to establish a QUIC connection to the server";

    // Get the server address info.
    let SocketAddrHelper {
        addr: server_address,
        hostname,
    } = file_yeet_shared::get_server_or_default(&args.server_address, args.server_port)
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

/// Attempt to connect to peer using UDP hole punching.
async fn udp_holepunch(
    args: &Cli,
    endpoint: quinn::Endpoint,
    local_address: SocketAddr,
    peer_address: SocketAddr,
) -> Option<quinn::Connection> {
    // Create a lock for where we will place the QUIC connection used to communicate with our peer.
    let peer_reached_lock: Arc<Mutex<bool>> = Arc::default();

    // Spawn a thread that listens for a peer and will set the boolean lock when connected.
    let peer_reached_listen = peer_reached_lock.clone();
    let endpoint_listen = endpoint.clone();
    let listen_future = listen_for_peer(endpoint_listen, local_address, &peer_reached_listen);

    // Attempt to connect to the peer's public address.
    let connect_future = connect_to_peer(endpoint, peer_address, &peer_reached_lock);

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    match u32::from(listen_stream.is_some()) + u32::from(connect_stream.is_some()) {
        0 => None,
        1 => listen_stream.or(connect_stream),
        2 => {
            // TODO: It could be interesting and possible to create a more general stream negotiation.
            //       For example, if each peer sent a random nonce over each stream, and the nonces were XOR'd per stream,
            //       the result could be used to determine which stream to use (highest/lowest resulting nonce after XOR).
            if let FileYeetCommand::Pub { .. } = args.cmd {
                listen_stream
            } else {
                connect_stream
            }
        }
        _ => unreachable!("Not possible to have more than two streams"),
    }
}

/// Spawn a thread that listens for a peer and will assign the peer `Connection` lock when connected.
async fn listen_for_peer(
    endpoint: quinn::Endpoint,
    local_address: SocketAddr,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<quinn::Connection> {
    // Print and create binding from the local address.
    println!(
        "{} Listening for peer on the same endpoint connected to the server: {local_address}",
        local_now_fmt()
    );

    // Accept a peer connection.
    let connecting = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.accept())
        .await
        .ok()? // Timeout.
        .expect("Failed to accept on endpoint");
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
        "{} New connection from peer at: {peer_addr:?}",
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
    loop {
        println!("{} Connecting to peer at: {peer_address}", local_now_fmt());
        match endpoint.connect(peer_address, "peer") {
            Ok(connecting) => {
                let connection =
                    match tokio::time::timeout(Duration::from_secs(5), connecting).await {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            eprintln!("{} Failed to connect to peer: {e}", local_now_fmt());
                            retries -= 1;
                            continue;
                        }
                        Err(_) => {
                            eprintln!("{} Failed to connect to peer: Timeout", local_now_fmt());

                            // Do not retry on timeout.
                            return None;
                        }
                    };
                // Set the peer mutex to the connected stream if there isn't already one present.
                *peer_reached_lock
                    .lock()
                    .expect("Could not obtain the mutex lock") = true;

                println!("{} Connected to peer at: {peer_address}", local_now_fmt());
                return Some(connection);
            }
            Err(e) => {
                eprintln!("{} Failed to connect to peer: {e}", local_now_fmt());
                retries -= 1;
            }
        }

        if retries == 0
            || *peer_reached_lock
                .lock()
                .expect("Could not obtain the mutex lock")
        {
            return None;
        }
    }
}

/// Try to read a valid UTF-8 from the server until the expected length is reached.
async fn expect_server_text(stream: &mut quinn::RecvStream, len: u16) -> anyhow::Result<String> {
    let mut raw_bytes = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
    let expected_slice = &mut raw_bytes[..len as usize];
    stream.read_exact(expected_slice).await?;
    Ok(std::str::from_utf8(expected_slice)?.to_owned())
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

/// Test loop that reads from stdin to write to the peer, and reads from the peer to print to stdout.
async fn test_rwpl(peer_connection: quinn::Connection, open: bool) {
    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PAYLOAD_SIZE];

    let (mut peer_send, mut peer_recv) = if open {
        let mut streams = peer_connection
            .open_bi()
            .await
            .expect("Failed to open a bi-directional QUIC stream to the peer");

        // The receiver will not know about the new stream request until data is sent.
        // Thus, we send a hello packet to initialize the stream.
        streams
            .0
            .write_all("Hello peer!\n".as_bytes())
            .await
            .expect("Failed to write to peer stream");

        streams
    } else {
        peer_connection
            .accept_bi()
            .await
            .expect("Failed to accept a bi-directional QUIC stream to the peer")
    };

    // Let the user know that the handshake is complete. Bi-directional streams are ready to use.
    println!("{} Peer connection established", local_now_fmt());

    // Testing.
    loop {
        // Read from stdin and write to the peer.
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .expect("Failed to read valid UTF-8 from stdin");
        peer_send
            .write_all(line.as_bytes())
            .await
            .expect("Failed to write to peer stream");

        // Read from the peer and print to stdout.
        let size = peer_recv
            .read(&mut buf)
            .await
            .expect("Could not read from peer stream")
            .expect("Peer stream closed");
        match std::str::from_utf8(&buf[..size]) {
            Ok(peer_line) => print!("{peer_line}"),
            Err(e) => eprintln!("Received invalid UTF-8 from peer: {e}"),
        }
    }
}
