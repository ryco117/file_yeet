use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use chrono::Local;
use file_yeet_shared::MAX_PAYLOAD_SIZE;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The server to connect to. Mediates peer-to-peer connections.
    #[arg(short, long)]
    server_ip: Option<String>,

    /// The server port to connect to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    server_port: u16,

    /// When enabled the client will listen for incoming peer connections.
    #[arg(short, long)]
    listen: bool,
}

/// Define a sane number of maximum retries.
const MAX_CONNECTION_RETRIES: usize = 5;

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    use clap::Parser as _;
    let args = Cli::parse();

    // TODO: Allow the using IPv6 and hostname server addresses.
    let server_address: (Ipv4Addr, u16) = (
        args.server_ip
            .as_ref()
            .filter(|s| !s.is_empty())
            .map_or(Ipv4Addr::LOCALHOST, |s| {
                s.parse().expect("Invalid IP address")
            }),
        args.server_port,
    );
    let (ip, port) = &server_address;

    // File publishing.
    if args.listen {
        // Open a reusable socket address.
        let server_socket = TcpSocket::new_v4().expect("Failed to create TCP socket");
        server_socket
            .set_reuseaddr(true)
            .expect("Failed to set SO_REUSEADDR on the socket, necessary for TCP hole punching");

        // Create a TCP stream to the server.
        let server_stream = server_socket
            .connect(server_address.into())
            .await
            .expect("Failed to connect to server");

        // Get our local network address as a string.
        // Needed for rebinding to the same address that NATs will forward for the server stream.
        let local_address = server_stream
            .local_addr()
            .expect("Could not determine our local address");

        // Connect to the server's websocket and specify .
        let (mut socket, connect_response) =
            tokio_tungstenite::client_async(format!("ws://{ip}:{port}/pub/6c1d798ec1c7cca4c62883807a9faf1623c02c26d8f03da5f4e6ae2322a72978"), server_stream)
                .await
                .expect("Failed to connect to server");
        println!(
            "Websocket connection made to server with status: {:?}",
            connect_response.status()
        );

        // Perform a sanity check to ensure the server is responsive and allows us to verify that the server can determine our public address.
        let sanity_check = socket
            .next()
            .await
            .expect("Could not read from server websocket");
        match sanity_check {
            Ok(message) => {
                let sock: SocketAddr = message
                    .to_text()
                    .expect("Server did not send a TEXT response for the sanity check")
                    .parse()
                    .expect("Server did not send a valid socket address for the sanity check");
                println!("Server sanity check passed, server connected to us at: {sock:?}");
            }
            Err(e) => {
                eprintln!("Server sanity check failed: {e}");
                return;
            }
        }

        // TODO: Read peer socket addresses from the server.
        // while let Some(_message) = socket.next().await {
        loop {
            // Listen for a peer and assign the peer `TcpStream` lock when connected.
            let Some(peer_tcp) = tcp_holepunch(&args, Some(local_address), None).await else {
                eprintln!("Failed to connect to peer");
                continue;
            };

            // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
            test_rwpl(peer_tcp).await;
        }

        #[allow(unreachable_code)]
        {println!("Server websocket closed");}
    } else {
        // Query the server for the address of a peer that has the file.
        let server_connection = reqwest::Client::new();
        let response = match server_connection
            .get(format!("http://{ip}:{port}/sub/6c1d798ec1c7cca4c62883807a9faf1623c02c26d8f03da5f4e6ae2322a72978"))
            .send().await {
                Ok(response) => response,
                Err(e) => {
                    eprintln!("Failed to query server for peer address: {e}");
                    return;
                }
            };

        // Parse the response body as a peer socket address.
        let peer_address_string = match response.text().await {
            Ok(peer_address) => peer_address,
            Err(e) => {
                eprintln!("Failed to parse server response as socket address: {e}");
                return;
            }
        };
        let peer_address = peer_address_string
            .parse::<SocketAddr>()
            .expect("Server did not send a valid socket address for the peer");

        // Connect to the peer and assign the peer `TcpStream` lock when connected.
        let peer_tcp = tcp_holepunch(&args, None, Some(peer_address))
            .await
            .expect("Failed to connect to peer");

        // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
        test_rwpl(peer_tcp).await;
    }
}

/// Attempt to connect to peer using TCP hole punching.
async fn tcp_holepunch(
    _args: &Cli,
    local_address: Option<SocketAddr>,
    peer_address: Option<SocketAddr>,
) -> Option<TcpStream> {
    // Create a lock for where we will place the TCP stream used to communicate with our peer.
    let peer_stream_lock: Arc<Mutex<Option<TcpStream>>> = Arc::default();

    // TODO: Allow concurrent listening and connecting since it may be necessary for some TCP hole punching scenarios.

    // Allow the caller to optionally listen during the TCP hole punching process.
    if let Some(local_addr) = local_address {
        // Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
        listen_for_peer_async(local_addr, peer_stream_lock.clone()).await;
    }

    // Allow the caller to optionally attempt connections to the peer's public address.
    if let Some(peer_address_string) = peer_address {
        // Attempt to connect to the peer's public address.
        connect_to_peer(peer_address_string, &peer_stream_lock).await;
    }

    // Return the peer stream if we have one.
    let peer_stream = peer_stream_lock
        .lock()
        .expect("Could not obtain the mutex lock")
        .take()
        .unwrap();
    Some(peer_stream)
}

/// Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
async fn listen_for_peer_async(
    local_addr: SocketAddr,
    peer_stream_lock: Arc<Mutex<Option<TcpStream>>>,
) {
    // Print and create binding from the local address.
    println!(
        "{} Binding to the same local address connected to the server: {local_addr}",
        Local::now()
    );
    let binding = TcpListener::bind(local_addr)
        .await
        .expect("Failed to bind to our local address");

    // Accept a peer connection.
    let (peer_listening_stream, peer_addr) = binding
        .accept()
        .await
        .expect("Failed to accept incoming connection");

    // Connected to a peer on the listening stream, print their address.
    println!(
        "{} New connection from peer at: {peer_addr:?}",
        Local::now()
    );

    // Set the peer stream lock to the listening stream if there isn't already one present.
    peer_stream_lock
        .lock()
        .expect("Could not obtain the mutex lock")
        .get_or_insert(peer_listening_stream);
}

/// Try to connect to a peer at the given address.
async fn connect_to_peer(
    peer_address: SocketAddr,
    peer_stream_lock: &Arc<Mutex<Option<TcpStream>>>,
) {
    // Set a sane number of connection retries.
    let mut retries = MAX_CONNECTION_RETRIES;

    // Ensure we have retries left and there isn't already a peer `TcpStream` to use.
    loop {
        // TODO: Support IPv6.
        match TcpStream::connect(peer_address).await {
            Ok(stream) => {
                println!("{} Connected to peer at: {peer_address}", Local::now());

                // Set the peer mutex to the connected stream if there isn't already one present.
                let _ = peer_stream_lock
                    .lock()
                    .expect("Could not obtain the mutex lock")
                    .get_or_insert(stream);
                return;
            }
            Err(e) => {
                eprintln!("Failed to connect to peer: {e}");
                retries -= 1;
            }
        }

        if retries == 0
            || peer_stream_lock
                .lock()
                .expect("Could not obtain the mutex lock")
                .is_some()
        {
            return;
        }
    }
}

/// Test loop that reads from stdin to write to the peer, and reads from the peer to print to stdout.
async fn test_rwpl(mut peer_stream: TcpStream) {
    // Create a scratch space for reading data from the stream.
    let mut buf = [0; MAX_PAYLOAD_SIZE];

    // Testing.
    loop {
        // Read from stdin and write to the peer.
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .expect("Failed to read valid UTF-8 from stdin");
        peer_stream
            .write_all(line.as_bytes())
            .await
            .expect("Failed to write to peer stream");

        // Read from the peer and print to stdout.
        let size = peer_stream
            .read(&mut buf)
            .await
            .expect("Could not read from peer stream");
        match std::str::from_utf8(&buf[..size]) {
            Ok(peer_line) => print!("{peer_line}"),
            Err(e) => eprintln!("Received invalid UTF-8 from peer: {e}"),
        }
    }
}
