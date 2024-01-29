use std::{collections::HashMap, sync::Arc};

use chrono::Local;
use clap::Parser;
use file_yeet_shared::{ClientApiRequest, HashBytes, SocketAddrHelper, MAX_PAYLOAD_SIZE};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, RwLock},
};

/// A client that has connected to the server.
struct Client {
    pub address: String,
    pub stream: mpsc::Sender<String>,
}

/// The command line arguments for the server.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The IP address the server will bind to. The default is local for testing.
    #[arg(short = 'b', long)]
    bind_ip: Option<String>,

    /// The port the server will bind to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    bind_port: u16,
}

/// The type for mapping between file hashes and the addresses of connected peers that are publishing the file.
#[derive(Default, Clone)]
struct PublishersRef {
    pub lock: Arc<RwLock<HashMap<HashBytes, Client>>>,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    let args = Cli::parse();

    // Determine which address to bind to.
    let SocketAddrHelper {
        addr: bind_address,
        hostname: _,
    } = file_yeet_shared::get_server_or_default(&args.bind_ip, args.bind_port)
        .expect("Failed to parse server address");

    // Print out the address we're going to bind to.
    println!("{} Using bind address: {bind_address:?}", Local::now());

    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()
        .expect("Failed to generate self-signed certificate");
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)
        .expect("Quinn failed to accept the server certificates");

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Tell the clients that they cannot change their socket address mid connection since it will disrupt peer-to-peer connecting.
    server_config.migration(false);

    // Create a new QUIC endpoint.
    let local_end = quinn::Endpoint::server(server_config, bind_address)
        .expect("Failed to bind to local QUIC endpoint");

    // Create a map between file hashes and the addresses of peers that have the file.
    let publishers: PublishersRef = PublishersRef::default();

    // Create a loop to handle QUIC connections.
    while let Some(connecting) = local_end.accept().await {
        let publishers = publishers.clone();
        tokio::spawn(async {
            if let Err(e) = handle_quic_connection(connecting, publishers).await {
                eprintln!("{} Failed to handle client connection: {e}", Local::now());
            }
        });
    }
}

/// Errors encountered while handling a client request.
#[derive(Debug, thiserror::Error)]
enum ClientRequestError {
    #[error("Failed to read a port override from the stream")]
    PortOverride,

    #[error("Failed to read SHA-256 hash for publishing")]
    PubHashBytes,

    #[error("Failed to read SHA-256 hash for subscribing")]
    SubHashBytes,
}

/// Handle the initial QUIC connection and attempt to determine whether the client wants to publish or subscribe.
async fn handle_quic_connection(
    connecting: quinn::Connecting,
    publishers: PublishersRef,
) -> anyhow::Result<()> {
    let connection = connecting.await?;
    let socket_addr = connection.remote_address();
    let mut sock_string = socket_addr.to_string();
    let (mut quic_send, mut quic_recv) = connection.accept_bi().await?;

    loop {
        let api = ClientApiRequest::try_from(quic_recv.read_u16().await?)?;
        println!("{} {api} from {sock_string}", Local::now());

        match api {
            ClientApiRequest::EmptyPing => {}
            ClientApiRequest::SocketPing => {
                quic_send
                    .write_u16(
                        u16::try_from(sock_string.len())
                            .expect("Message content length is invalid"),
                    )
                    .await?;
                quic_send.write_all(sock_string.as_bytes()).await?;
            }
            ClientApiRequest::PortOverride => {
                let port = quic_recv
                    .read_u16()
                    .await
                    .map_err(|_| ClientRequestError::PortOverride)?;

                sock_string = {
                    let mut a = socket_addr;
                    a.set_port(port);
                    a.to_string()
                };
                println!("{} Overriding port to {port}", Local::now());
            }
            ClientApiRequest::Publish => {
                let mut hash = HashBytes::default();
                quic_recv
                    .read_exact(&mut hash)
                    .await
                    .map(|()| ClientRequestError::PubHashBytes)?;

                // Now that we have the peer's socket address and the file hash, we can handle the publish request.
                if let Err(e) =
                    handle_publish(connection, quic_send, sock_string, hash, publishers).await
                {
                    eprintln!("{} Failed to handle publish request: {e}", Local::now());
                }

                // Terminate our connection with the client.
                return Ok(());
            }
            ClientApiRequest::Subscribe => {
                let mut hash = HashBytes::default();
                quic_recv
                    .read_exact(&mut hash)
                    .await
                    .map(|()| ClientRequestError::SubHashBytes)?;

                // Now that we have the peer's socket address and the file hash, we can handle the subscribe request.
                if let Err(e) = handle_subscribe(quic_send, sock_string, hash, publishers).await {
                    eprintln!("{} Failed to handle subscribe request: {e}", Local::now());
                }

                // Terminate our connection with the client.
                return Ok(());
            }
        }
    }
}

/// Handle QUIC connections for clients that want to publish a new file hash.
async fn handle_publish(
    connection: quinn::Connection,
    mut quic_send: quinn::SendStream,
    sock_string: String,
    hash: HashBytes,
    clients: PublishersRef,
) -> anyhow::Result<()> {
    // Use a channel to handle buffering and flushing of messages.
    // Ensures that the stream doesn't need to be cloned or passed between threads.
    let (tx, mut rx) = mpsc::channel::<String>(4 * MAX_PAYLOAD_SIZE);
    let sock_string_clone = sock_string.clone();
    tokio::task::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Err(e) = quic_send
                .write_u16(u16::try_from(message.len()).expect("Message content length is invalid"))
                .await
            {
                eprintln!("{} Failed to send message to client: {e}", Local::now());
                break;
            }
            if let Err(e) = quic_send.write_all(message.as_bytes()).await {
                eprintln!("{} Failed to send message to client: {e}", Local::now());
                break;
            }
        }
        println!(
            "{} Closed forwarding thread for client {sock_string_clone}",
            Local::now()
        );
    });

    let address = sock_string.clone();
    let client = Client {
        address,
        stream: tx,
    };

    // Add the client to the map of clients.
    // TODO: If there is already a client for this hash, perhaps multple clients can be stored for a file hash.
    if let Some(old_client) = clients.lock.write().await.insert(hash, client) {
        println!("{} Replaced client: {}", Local::now(), old_client.address);
    }

    // Wait for the client to close the connection.
    let closed_reason = connection.closed().await;
    println!(
        "{} Client disconnected: {sock_string} {closed_reason:?}",
        Local::now()
    );

    // TODO: Handle different client addresses for one file hash.
    clients.lock.write().await.remove(&hash);

    Ok(())
}

/// Handle QUIC connections for clients that want to subscribe to a file hash.
async fn handle_subscribe(
    mut quic_send: quinn::SendStream,
    sock_string: String,
    hash: HashBytes,
    clients: PublishersRef,
) -> anyhow::Result<()> {
    // Attempt to get the client from the map.
    let read_lock = clients.lock.read().await;
    let Some(pub_client) = read_lock.get(&hash) else {
        eprintln!("{} Failed to find client for hash", Local::now());

        // TODO: Allow a client to wait for a publishing peer to become available.
        quic_send.write_u16(0).await?;
        quic_send.finish().await?;
        return Ok(());
    };

    // Feed the publishing client socket address to the task that handles communicating with this client.
    pub_client
        .stream
        .send(sock_string)
        .await
        .expect("Could not feed the publish task thread");

    // Send the publisher's socket address to the subscribing client.
    let n = u16::try_from(pub_client.address.len()).expect("Message content length is invalid");
    quic_send.write_u16(n).await?;
    quic_send.write_all(pub_client.address.as_bytes()).await?;
    quic_send.finish().await?;

    Ok(())
}
