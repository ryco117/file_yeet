use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex},
};

use chrono::Local;
use file_yeet_shared::{HashBytes, SocketAddrHelper, MAX_PAYLOAD_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The server to connect to. Either an IP address or a hostname.
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

    /// When enabled the client will listen for incoming peer connections.
    #[arg(short, long)]
    listen: bool,
}

/// Define a sane number of maximum retries.
const MAX_CONNECTION_RETRIES: usize = 5;

/// Zero bytes used for testing.
const TEST_HASH: HashBytes = [0; 32];

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    use clap::Parser as _;
    let args = Cli::parse();

    // Connect to the public file_yeet_server.
    let (endpoint, mut server_send, mut server_recv, _port_mapping) =
        prepare_server_connection(&args).await;

    if args.listen {
        // Send the server a publish request.
        server_send
            .write_u16(file_yeet_shared::ClientApiRequest::Publish as u16)
            .await
            .expect("Failed to send a publish request to the server");
        server_send
            .write_all(&TEST_HASH)
            .await
            .expect("Failed to send the file hash of a publish request to the server");

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
                eprintln!("{} Server encountered and error", Local::now());
                break;
            }
            if data_len > file_yeet_shared::MAX_PAYLOAD_SIZE {
                eprintln!("{} Server response length is invalid", Local::now());
                break;
            }

            let mut scratch_space = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
            let peer_string_bytes = &mut scratch_space[..data_len];
            if let Err(e) = server_recv.read_exact(peer_string_bytes).await {
                eprintln!(
                    "{} Failed to read a response from the server: {e}",
                    Local::now()
                );
                break;
            }

            // Parse the response as a peer socket address or skip this message.
            let peer_string = match std::str::from_utf8(peer_string_bytes) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "{} Server did not send a valid UTF-8 response: {e}",
                        Local::now()
                    );
                    continue;
                }
            };
            let peer_address = match peer_string.parse() {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("{} Failed to parse peer address: {e}", Local::now());
                    continue;
                }
            };

            // Listen for a peer and assign the peer `TcpStream` lock when connected.
            let Some(peer_tcp) = tcp_holepunch(
                &args,
                endpoint.clone(),
                endpoint
                    .local_addr()
                    .expect("Could not determine our local IP"),
                peer_address,
            )
            .await
            else {
                eprintln!("{} Failed to connect to peer", Local::now());
                continue;
            };

            // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
            test_rwpl(peer_tcp, false).await;
        }

        println!("Server connection closed");
    } else {
        // Send the server a subscribe request.
        server_send
            .write_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16)
            .await
            .expect("Failed to send a subscribe request to the server");
        server_send
            .write_all(&TEST_HASH)
            .await
            .expect("Failed to send the file hash of a subscribe request to the server");

        // Close the stream after completing the publish request.
        let _ = server_send.finish().await;

        // Determine if the server is responding with a success or failure.
        let response_size = server_recv
            .read_u16()
            .await
            .expect("Failed to read a u16 response from the server")
            as usize;
        if response_size == 0 {
            eprintln!("{} No publishers available for file hash", Local::now());
            return;
        }
        if response_size > file_yeet_shared::MAX_PAYLOAD_SIZE {
            eprintln!("{} Server response length is invalid", Local::now());
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

        // Connect to the peer and assign the peer `TcpStream` lock when connected.
        let local_address = endpoint
            .local_addr()
            .expect("Could not determine our local IP");
        let peer_tcp = tcp_holepunch(&args, endpoint, local_address, peer_address)
            .await
            .expect("TCP hole punching failed");

        // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
        test_rwpl(peer_tcp, true).await;
    }
}

async fn prepare_server_connection(
    args: &Cli,
) -> (
    quinn::Endpoint,
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
        Local::now()
    );

    // Attempt to get a port forwarding, starting with user's override and then attempting the Port Control Protocol.
    let gateway = if let Some(g) = args.gateway.as_ref() {
        g.parse().expect("Failed to parse gateway address")
    } else {
        default_net::get_default_gateway()
            .expect("Failed to get the default gateway")
            .ip_addr
    };
    let (port_mapping, port_override) = if let Some(p) = args.port_override {
        (None, Some(p))
    } else if let Ok(m) = crab_nat::try_port_mapping(
        gateway,
        local_address.ip(),
        crab_nat::InternetProtocol::Udp,
        local_address.port(),
        None,
        None,
    )
    .await
    {
        let p = m.external_port;
        println!(
            "{} Success mapping external port {p} -> internal {}",
            Local::now(),
            m.internal_port
        );
        (Some(m), Some(p))
    } else {
        (None, None)
    };

    // Use an insecure client configuration when connecting to peers.
    // TODO: Use a secure client configuration when connecting to the server.
    endpoint.set_default_client_config(file_yeet_shared::configure_peer_verification());
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
    let _: SocketAddr = sanity_check
        .parse()
        .expect("Server did not send a valid socket address for the sanity check");
    println!("{} Server sees us as {sanity_check}", Local::now());

    if let Some(port) = port_override {
        // Send the server a port override request.
        server_send
            .write_u16(file_yeet_shared::ClientApiRequest::PortOverride as u16)
            .await
            .expect("Failed to send a port override request to the server");
        server_send
            .write_u16(port)
            .await
            .expect("Failed to send the port override to the server");
    }

    (endpoint, server_send, server_recv, port_mapping)
}

/// Connect to the server using QUIC.
async fn connect_to_server(args: &Cli, endpoint: &quinn::Endpoint) -> quinn::Connection {
    // Get the server address info.
    let SocketAddrHelper {
        addr: server_address,
        hostname,
    } = file_yeet_shared::get_server_or_default(&args.server_address, args.server_port)
        .expect("Failed to parse server address");
    println!(
        "{} Connecting to server {hostname} at socket address: {server_address}",
        Local::now()
    );

    // Attempt to connect to the server using QUIC.
    let connection = endpoint
        .connect(server_address, hostname.as_str())
        .expect("Failed to start a QUIC connection to the server")
        .await
        .expect("Failed to establish a QUIC connection to the server");
    println!("{} QUIC connection made to the server", Local::now());
    connection
}

/// Read a valid UTF-8 from the server until
async fn expect_server_text(stream: &mut quinn::RecvStream, len: u16) -> anyhow::Result<String> {
    let mut raw_bytes = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
    let expected_slice = &mut raw_bytes[..len as usize];
    stream.read_exact(expected_slice).await?;
    Ok(std::str::from_utf8(expected_slice)?.to_owned())
}

/// Attempt to connect to peer using TCP hole punching.
async fn tcp_holepunch(
    args: &Cli,
    endpoint: quinn::Endpoint,
    local_address: SocketAddr,
    peer_address: SocketAddr,
) -> Option<quinn::Connection> {
    // Create a lock for where we will place the TCP stream used to communicate with our peer.
    let peer_reached_lock: Arc<Mutex<bool>> = Arc::default();

    // Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
    let peer_reached_listen = peer_reached_lock.clone();
    let endpoint_listen = endpoint.clone();
    let listen_future = listen_for_peer_async(endpoint_listen, local_address, &peer_reached_listen);

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
            if args.listen {
                listen_stream
            } else {
                connect_stream
            }
        }
        _ => unreachable!("Not possible to have more than two streams"),
    }
}

/// Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
async fn listen_for_peer_async(
    endpoint: quinn::Endpoint,
    local_address: SocketAddr,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<quinn::Connection> {
    // Print and create binding from the local address.
    println!(
        "{} Listening for peer on the same endpoint connected to the server: {local_address}",
        Local::now()
    );

    // Accept a peer connection.
    let connecting =
        tokio::time::timeout(std::time::Duration::from_millis(5_000), endpoint.accept())
            .await
            .ok()? // Timeout.
            .expect("Failed to accept on endpoint");
    let connection = match connecting.await {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("{} Failed to accept a peer connection: {e}", Local::now());
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
        Local::now()
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
    let mut retries = MAX_CONNECTION_RETRIES;

    // Ensure we have retries left and there isn't already a peer `TcpStream` to use.
    loop {
        println!("{} Connecting to peer at: {peer_address}", Local::now());
        match endpoint.connect(peer_address, "peer") {
            Ok(connecting) => {
                let connection =
                    match tokio::time::timeout(std::time::Duration::from_millis(5_000), connecting)
                        .await
                    {
                        Ok(Ok(c)) => c,
                        Ok(Err(e)) => {
                            eprintln!("{} Failed to connect to peer: {e}", Local::now());
                            retries -= 1;
                            continue;
                        }
                        Err(_) => return None, // Timeout.
                    };
                // Set the peer mutex to the connected stream if there isn't already one present.
                *peer_reached_lock
                    .lock()
                    .expect("Could not obtain the mutex lock") = true;

                println!("{} Connected to peer at: {peer_address}", Local::now());
                return Some(connection);
            }
            Err(e) => {
                eprintln!("{} Failed to connect to peer: {e}", Local::now());
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
    println!("{} Peer connection established", Local::now());

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
