use std::{
    io::Write,
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use chrono::Local;
use net2::TcpBuilder;

use file_yeet_shared::{ReadStreamError, MAX_PAYLOAD_SIZE};

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

fn main() {
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

    // Create a TCP stream to the server.
    let mut server_stream = TcpBuilder::new_v4()
        .unwrap()
        .reuse_address(true)
        .expect("Failed to set SO_REUSEADDR on the socket, necessary for TCP hole punching")
        .connect(server_address)
        .expect("Failed to connect to server");

    // TODO: Send our local endpoint to the server for private-network file shares.

    // Accept peer-connection info from the server in a loop.
    /*loop*/
    {
        // Create a scratch space for reading data from the stream.
        let mut buf = [0; MAX_PAYLOAD_SIZE];

        // Read peer connection info from the server as a byte-buffer.
        let size = match file_yeet_shared::read_stream(&mut server_stream, &mut buf) {
            // Valid buffer size read.
            Ok(size) => size,

            // The TCP stream has been closed, exit loop.
            Err(ReadStreamError::ConnectionClosed) => {
                eprintln!("Server closed the connection");
                return;
            }

            // An error occurred while reading from the stream, exit loop.
            Err(ReadStreamError::IoError(e)) => {
                eprintln!("Failed to read from server stream: {e}");
                return;
            }
        };

        // Attempt to parse the buffer as a UTF-8 string. Ensure the string is owned to copy out of the temporary buffer.
        let peer_address_string = match std::str::from_utf8(&buf[..size.get()]) {
            Ok(buf) => buf.to_owned(),
            Err(e) => {
                eprintln!("Received invalid UTF-8 from server: {e}");
                return;
            }
        };

        // Both attempt connections and listen for the peer and use the first successful connection stream.
        let mut peer_stream = tcp_holepunch(&args, &mut server_stream, &peer_address_string)
            .expect("Could not successfully connect to peer through TCP hole punching");

        // Testing.
        loop {
            // Read from stdin and write to the peer.
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .expect("Failed to read valid UTF-8 from stdin");
            peer_stream
                .write_all(line.as_bytes())
                .expect("Failed to write to peer stream");

            // Read from the peer and print to stdout.
            let size = file_yeet_shared::read_stream(&mut peer_stream, &mut buf)
                .expect("Could not read from peer stream");
            match std::str::from_utf8(&buf[..size.get()]) {
                Ok(peer_line) => print!("{peer_line}"),
                Err(e) => eprintln!("Received invalid UTF-8 from peer: {e}"),
            }
        }
    }
}

/// Attempt to connect to peer using TCP hole punching.
fn tcp_holepunch(
    args: &Cli,
    server_stream: &mut TcpStream,
    peer_address_string: &str,
) -> Option<TcpStream> {
    // Create a lock for where we will place the TCP stream used to communicate with our peer.
    let peer_stream_lock: Arc<Mutex<Option<TcpStream>>> = Arc::default();

    // Get our local network address as a string.
    let local_addr = server_stream
        .local_addr()
        .expect("Could not determine our local address")
        .to_string();

    if args.listen {
        // Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
        spawn_listen_for_peer(&local_addr, peer_stream_lock.clone())
            .join()
            .expect("Listening thread failed");
    } else {
        // Attempt to connect to the peer's public address.
        match connect_to_peer(peer_address_string, &peer_stream_lock) {
            // Successfully connected to the peer.
            Some(peer_stream) => {
                peer_stream_lock.lock().unwrap().get_or_insert(peer_stream);

                // TODO: Cancel the listening thread since we have a peer connection.
                // https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
            }

            // Could not reach the peer through outward connections, ensure that the listening thread has succeeded or close.
            None => {
                if peer_stream_lock.lock().unwrap().is_none() {
                    return None;
                }
            }
        }
    }

    let peer_stream = peer_stream_lock.lock().unwrap().take().unwrap();
    Some(peer_stream)
}

/// Spawn a thread that listens for a peer and will assign the peer `TcpStream` lock when connected.
fn spawn_listen_for_peer(
    local_addr: &str,
    peer_stream_lock: Arc<Mutex<Option<TcpStream>>>,
) -> JoinHandle<()> {
    // Print and create binding from the local address outside of the thread because of lifetime restrictions.
    println!(
        "{} Binding to the same local address connected to the server: {local_addr}",
        Local::now()
    );
    let binding = TcpListener::bind(local_addr).expect("Failed to bind to our local address");

    std::thread::spawn(move || {
        // TODO: Allow the `accept()` call to timeout or be cancelled somehow if the connection attempts succeed first.
        // Establish a binding where the peer can reach us, then wait for a connection.
        let (peer_listening_stream, peer_addr) = binding
            .accept()
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
    })
}

/// Try to connect to a peer at the given address.
fn connect_to_peer(
    peer_address: &str,
    peer_stream_lock: &Arc<Mutex<Option<TcpStream>>>,
) -> Option<TcpStream> {
    // Helper function to recursively attempt to connect to a peer.
    fn dial(
        peer_address: &str,
        peer_stream_lock: &Arc<Mutex<Option<TcpStream>>>,
        retries: usize,
    ) -> Option<TcpStream> {
        // Ensure we have retries left and there isn't already a peer `TcpStream` to use.
        if retries == 0 || peer_stream_lock.lock().unwrap().is_some() {
            return None;
        }

        // TODO: Support IPv6.
        match TcpBuilder::new_v4().unwrap().connect(peer_address) {
            Ok(stream) => {
                println!("{} Connected to peer at: {peer_address}", Local::now());
                Some(stream)
            }
            Err(e) => {
                eprintln!("Failed to connect to peer: {e}");
                dial(peer_address, peer_stream_lock, retries - 1)
            }
        }
    }

    // Define a sane number of maximum retries.
    const MAX_CONNECTION_RETRIES: usize = 5;

    // User three retries to connect to the peer.
    dial(peer_address, peer_stream_lock, MAX_CONNECTION_RETRIES)
}
