use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use chrono::Local;
use file_yeet_shared::{SocketAddrHelper, MAX_PAYLOAD_SIZE};
use futures_util::StreamExt;
use net2::TcpBuilder;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};
use tokio_tungstenite::{
    tungstenite::{self, Message},
    WebSocketStream,
};

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The server to connect to. Either an IP address or a hostname.
    #[arg(short, long)]
    server_address: Option<String>,

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

    // Get the server address info.
    let SocketAddrHelper {
        addr: server_address,
        hostname,
    } = file_yeet_shared::get_server_or_default(&args.server_address, args.server_port)
        .expect("Failed to parse server address");

    // Open a reusable socket address.
    let server_socket = if server_address.is_ipv4() {
        TcpSocket::new_v4().expect("Failed to create IPv4 TCP socket")
    } else {
        TcpSocket::new_v6().expect("Failed to create IPv6 TCP socket")
    };
    server_socket
        .set_reuseaddr(true)
        .expect("Failed to set SO_REUSEADDR on the socket, necessary for TCP hole punching");

    // Create a TCP stream to the server.
    let server_stream = server_socket
        .connect(server_address)
        .await
        .expect("Failed to connect to server");
    println!(
        "{} TCP connection made to server at socket {server_address:?}",
        Local::now()
    );

    // Get our local network address as a string.
    // Needed for rebinding to the same address that NATs will forward for the server stream.
    let local_address = server_stream
        .local_addr()
        .expect("Could not determine our local address");

    // Get the URL for our API call.
    let request_address = format!(
        "ws://{hostname}:{}/{}/6c1d798ec1c7cca4c62883807a9faf1623c02c26d8f03da5f4e6ae2322a72978",
        server_address.port(),
        if args.listen { "pub" } else { "sub" }
    );
    println!(
        "{} Requesting websocket connection to server at: {request_address}",
        Local::now()
    );

    // Attempt to connect to the server using websockets and pass the API request address.
    let response = tokio_tungstenite::client_async(request_address, server_stream).await;
    let (mut socket, connect_response) = match response {
        Ok(response) => response,
        Err(e) => {
            // Attempt to parse the response body as UTF-8.
            let body = if let tungstenite::error::Error::Http(response) = &e {
                if let Some(bytes) = response.body() {
                    std::str::from_utf8(bytes)
                        .map(|body| (response.status(), body))
                        .ok()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some((status, body)) = body {
                return eprintln!(
                    "{} The server responded with an error: {status} {body}",
                    Local::now(),
                );
            }
            return eprintln!(
                "{} The server could not find a peer sharing this file: {:?}",
                Local::now(),
                e,
            );
        }
    };

    //let (mut socket, connect_response) = response.expect("Failed to connect to server");
    println!(
        "{} Websocket connection made to server with status: {:#}",
        Local::now(),
        connect_response.status(),
    );

    // Perform a sanity check to ensure the server is responsive.
    // Also, this allows us to verify that the server can determine our public address.
    let sanity_check = expect_server_text(&mut socket).await;
    let _: SocketAddr = sanity_check
        .parse()
        .expect("Server did not send a valid socket address for the sanity check");

    if args.listen {
        // Enter a loop to listen for incoming peer connections.
        while let Some(message) = socket.next().await {
            // Parse the response as a peer socket address or skip this message.
            let peer_address = match try_recv_peer_address(message) {
                Ok(addr) => addr,
                Err(e) => {
                    eprintln!("Failed to parse peer address: {e}");
                    continue;
                }
            };

            // Listen for a peer and assign the peer `TcpStream` lock when connected.
            let Some(peer_tcp) = tcp_holepunch(&args, local_address, peer_address).await else {
                eprintln!("Failed to connect to peer");
                continue;
            };

            // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
            test_rwpl(peer_tcp).await;
        }

        println!("Server websocket closed");
    } else {
        // Parse the response as a peer socket address.
        let peer_address = expect_server_text(&mut socket)
            .await
            .parse::<SocketAddr>()
            .expect("Server did not send a valid socket address for the peer");

        // Connect to the peer and assign the peer `TcpStream` lock when connected.
        let peer_tcp = tcp_holepunch(&args, local_address, peer_address)
            .await
            .expect("TCP hole punching failed");

        // TODO: Perform some handshake with the peer to inform them of the size of the file we're sending.
        test_rwpl(peer_tcp).await;
    }
}

async fn expect_server_text(socket: &mut WebSocketStream<TcpStream>) -> String {
    const SERVER_CLOSED_EARLY: &str = "Server closed our websocket before sending expected text";

    socket
        .next()
        .await
        .expect(SERVER_CLOSED_EARLY)
        .expect(SERVER_CLOSED_EARLY)
        .into_text()
        .expect("Server did not send a TEXT response")
}

/// Helper to attempt to parse a websocket message as a peer socket address in text.
fn try_recv_peer_address(
    response: Result<Message, tokio_tungstenite::tungstenite::error::Error>,
) -> anyhow::Result<SocketAddr> {
    // Attempt to receive a peer's socket address as text from the server.
    Ok(response?.to_text()?.parse()?)
}

/// Attempt to connect to peer using TCP hole punching.
async fn tcp_holepunch(
    args: &Cli,
    local_address: SocketAddr,
    peer_address: SocketAddr,
) -> Option<TcpStream> {
    // Create a lock for where we will place the TCP stream used to communicate with our peer.
    let peer_reached_lock: Arc<Mutex<bool>> = Arc::default();

    // TODO: Allow concurrent listening and connecting since it may be necessary for some TCP hole punching scenarios.

    // Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
    let peer_reached_listen = peer_reached_lock.clone();
    let listen_future = tokio::time::timeout(
        std::time::Duration::from_millis(5_000),
        tokio::task::spawn_blocking(move || {
            listen_for_peer_async(local_address, &peer_reached_listen)
        }),
    );

    // Attempt to connect to the peer's public address.
    let connect_future = connect_to_peer(peer_address, &peer_reached_lock);

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    let listen_stream = listen_stream.ok().and_then(Result::ok);
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
fn listen_for_peer_async(
    local_address: SocketAddr,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> TcpStream {
    // Print and create binding from the local address.
    println!(
        "{} Listening on the same local address connected to the server: {local_address}",
        Local::now()
    );
    let builder = tcp_builder(local_address.ip());
    builder
        .reuse_address(true)
        .expect("Failed to set SO_REUSEADDR on the socket")
        .bind(local_address)
        .expect("Failed to bind to our local address");

    // Accept a peer connection.
    // TODO: Refactor to allow publisher to have a long-lived listening stream.
    let (peer_listening_stream, peer_addr) = builder
        .listen(1)
        .expect("Failed to listen on socket")
        .accept()
        .expect("Failed to accept incoming connection");

    // Connected to a peer on the listening stream, print their address.
    println!(
        "{} New connection from peer at: {peer_addr:?}",
        Local::now()
    );

    // Set the peer stream lock to the listening stream if there isn't already one present.
    *peer_reached_lock
        .lock()
        .expect("Could not obtain the mutex lock") = true;

    TcpStream::from_std(peer_listening_stream)
        .expect("Failed to convert std::net::TcpStream to tokio::net::TcpStream")
}

/// Try to connect to a peer at the given address.
async fn connect_to_peer(
    peer_address: SocketAddr,
    peer_reached_lock: &Arc<Mutex<bool>>,
) -> Option<TcpStream> {
    // Set a sane number of connection retries.
    let mut retries = MAX_CONNECTION_RETRIES;

    // Ensure we have retries left and there isn't already a peer `TcpStream` to use.
    loop {
        match TcpStream::connect(peer_address).await {
            Ok(stream) => {
                println!("{} Connected to peer at: {peer_address}", Local::now());

                // Set the peer mutex to the connected stream if there isn't already one present.
                *peer_reached_lock
                    .lock()
                    .expect("Could not obtain the mutex lock") = true;
                return Some(stream);
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

fn tcp_builder(bind_address: std::net::IpAddr) -> TcpBuilder {
    match bind_address {
        std::net::IpAddr::V4(_) => TcpBuilder::new_v4().expect("Failed to create IPv4 TCP socket"),
        std::net::IpAddr::V6(_) => TcpBuilder::new_v6().expect("Failed to create IPv6 TCP socket"),
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
