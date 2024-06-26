use std::{collections::HashMap, mem::size_of, net::SocketAddr, num::NonZeroU16, sync::Arc};

use bytes::BufMut as _;
use clap::Parser;
use file_yeet_shared::{
    BiStream, ClientApiRequest, HashBytes, SocketAddrHelper, GOODBYE_CODE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, RwLock},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A client stream that is handling a publish request.
#[derive(Debug)]
struct Publisher {
    // A reference to the client's socket address as a string.
    pub address: Arc<RwLock<String>>,

    // A channel to send messages to the task handling this client's publish request.
    pub stream: mpsc::Sender<String>,
}
type PublisherRef = Arc<RwLock<Publisher>>;

/// A client and the file size they are publishing.
#[derive(Debug)]
struct PublishedFile {
    pub publisher: PublisherRef,
    pub file_size: u64,
}
impl PublishedFile {
    pub fn new(publisher: PublisherRef, file_size: u64) -> Self {
        Self {
            publisher,
            file_size,
        }
    }
}

/// A nonce for the server to use in its communications with clients.
type Nonce = [u64; 2];

/// The command line interface for `file_yeet_server`.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The IP address the server will bind to. The default is local for testing.
    #[arg(short = 'b', long)]
    bind_ip: Option<String>,

    /// The port the server will bind to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    bind_port: NonZeroU16,
}

/// A mapping between file hashes and the addresses of connected peers that are publishing the file.
type PublishersRef = Arc<RwLock<HashMap<HashBytes, HashMap<Nonce, PublishedFile>>>>;

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    let args = Cli::parse();

    // Initialize logging.
    tracing_subscriber::fmt::init();

    // Determine which address to bind to.
    let SocketAddrHelper {
        address: bind_address,
        hostname: _,
    } = file_yeet_shared::get_server_or_default(args.bind_ip.as_deref(), args.bind_port)
        .expect("Failed to parse server address");

    // Print out the address we're going to bind to.
    tracing::info!("Using bind address: {bind_address:?}");

    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()
        .expect("Failed to generate self-signed certificate");
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)
        .expect("Quinn failed to accept the server certificates");

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Tell the clients that they cannot change their socket address mid connection since it will disrupt peer-to-peer connecting.
    // TODO: Investigate whether migrations can be captured to update their addresses in the server's map.
    server_config.migration(false);

    // Create a new QUIC endpoint.
    let local_end = quinn::Endpoint::server(server_config, bind_address)
        .expect("Failed to bind to local QUIC endpoint");

    // Create a map between file hashes and the addresses of peers that have the file.
    let publishers: PublishersRef = PublishersRef::default();

    // Create a cancellation token and set of tasks to allow the server to shut down gracefully.
    let cancellation_token = CancellationToken::new();
    let task_master = TaskTracker::new();

    // Create a loop to handle QUIC connections, but allow cancelling the loop.
    tokio::select! {
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                tracing::error!("Failed to handle SIGINT, aborting: {e}");
            } else {
                tracing::info!("Shutting down server");
            }
        }
        () = handle_incoming_loop(local_end.clone(), publishers, cancellation_token.clone(), task_master.clone()) => {}
    }

    // Cancel the server's tasks.
    cancellation_token.cancel();

    // Close the QUIC endpoint with the DEADBEEF status.
    local_end.close(quinn::VarInt::from_u32(0xDEAD_BEEF), &[]);

    // Wait for the server's tasks to finish.
    task_master.close();

    tracing::info!("Server has shut down");
}

/// Process incoming QUIC connections into their own tasks, allowing for client-task cancellation.
async fn handle_incoming_loop(
    local_end: quinn::Endpoint,
    publishers: PublishersRef,
    cancellation_token: CancellationToken,
    task_master: TaskTracker,
) {
    while let Some(connecting) = local_end.accept().await {
        let cancellation_token = cancellation_token.clone();
        let publishers = publishers.clone();
        let client_disconnect_token = CancellationToken::new();

        task_master.spawn(async move {
            tokio::select! {
                // Allow the server to cancel client tasks.
                () = cancellation_token.cancelled() => client_disconnect_token.cancel(),

                // Handle this client's connection.
                r = handle_quic_connection(connecting, publishers, client_disconnect_token.clone()) => {
                    // Let all tasks created for this client know that they should shut down.
                    client_disconnect_token.cancel();

                    if let Err(e) = r {
                        match e {
                            // Check for a graceful disconnect.
                            ClientRequestError::Connection(quinn::ConnectionError::ApplicationClosed(r)) | ClientRequestError::RequestStream(quinn::ConnectionError::ApplicationClosed(r))
                            if r.error_code == GOODBYE_CODE => {
                                #[cfg(debug_assertions)]
                                tracing::debug!("Client gracefully disconnected: {r}");
                            }

                            // Check for a timeout when waiting for the next request.
                            ClientRequestError::RequestStream(quinn::ConnectionError::TimedOut) => {
                                #[cfg(debug_assertions)]
                                tracing::debug!("Client left without notice");
                            }

                            // If the client didn't gracefully disconnected, print the error.
                            e => tracing::warn!("Failed to handle client connection: {e}"),
                        }
                    }
                }
            }
        });
    }
}

/// Errors encountered while handling a client request.
#[derive(Debug, thiserror::Error)]
enum ClientRequestError {
    /// Failed to establish a QUIC connection.
    #[error("QUIC connection error: {0}")]
    Connection(quinn::ConnectionError),

    /// Failed to establish a new request QUIC stream.
    #[error("QUIC stream error: {0}")]
    RequestStream(quinn::ConnectionError),

    /// An invalid API request code was received from a client.
    #[error("Invalid API request code: {0}")]
    InvalidApiRequestCode(u16),

    /// An I/O error on occurred when reading or writing to a QUIC stream.
    #[error("I/O error on peer stream: {0}")]
    IoError(std::io::Error),

    /// Invalid content was sent by the client in the request.
    #[error("Invalid request content was sent by the client")]
    InvalidRequestContent,
}

#[derive(Debug)]
struct ClientSession {
    pub nonce: Nonce,
    pub sock_string: Arc<RwLock<String>>,
    pub client_pubs: Vec<PublisherRef>,
    pub bb: bytes::BytesMut,
    pub cancellation_token: CancellationToken,
}
impl ClientSession {
    pub fn new(socket_addr: SocketAddr, cancellation_token: CancellationToken) -> Self {
        let mut sock_string = socket_addr.to_string();
        sock_string.make_ascii_lowercase();
        let sock_string = Arc::new(RwLock::new(sock_string));
        let nonce = random_nonce();
        let bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

        Self {
            nonce,
            sock_string,
            client_pubs: Vec::new(),
            bb,
            cancellation_token,
        }
    }
}

/// Handle the initial QUIC connection and attempt to determine whether the client wants to publish or subscribe.
#[tracing::instrument(skip_all)]
async fn handle_quic_connection(
    connecting: quinn::Connecting,
    publishers: PublishersRef,
    cancellation_token: CancellationToken,
) -> Result<(), ClientRequestError> {
    let connection = connecting.await.map_err(ClientRequestError::Connection)?;
    let socket_addr = connection.remote_address();
    let mut port_used = socket_addr.port();

    let mut session = ClientSession::new(socket_addr, cancellation_token);
    loop {
        // Accept a new stream for each client request.
        // QUIC streams are very cheap and multiple streams lends itself to concurrent requests.
        let mut client_streams: BiStream = connection
            .accept_bi()
            .await
            .map_err(ClientRequestError::RequestStream)?
            .into();

        let api = ClientApiRequest::try_from(
            client_streams
                .recv
                .read_u16()
                .await
                .map_err(ClientRequestError::IoError)?,
        )
        .map_err(|e| ClientRequestError::InvalidApiRequestCode(e.number))?;
        tracing::info!("{api} from {}", session.sock_string.read().await);

        match api {
            // Send a ping response to the client.
            // Close the connection if we can't send the response.
            ClientApiRequest::SocketPing => {
                socket_ping(client_streams.send, &session.sock_string).await?;
            }

            // Update the client's address string with the new port.
            // Close the connection if we can't read the new port.
            ClientApiRequest::PortOverride => {
                port_override(
                    &mut session,
                    client_streams.recv,
                    socket_addr,
                    &mut port_used,
                )
                .await?;
            }

            // Create a new task to handle the client's file-publishing request.
            // Close the connection if we can't read the file hash.
            ClientApiRequest::Publish => {
                let mut hash = HashBytes::default();
                client_streams
                    .recv
                    .read_exact(&mut hash)
                    .await
                    .map_err(|_| {
                        ClientRequestError::IoError(std::io::Error::from(
                            std::io::ErrorKind::UnexpectedEof,
                        ))
                    })?;
                let file_size = client_streams.recv.read_u64().await.map_err(|_| {
                    ClientRequestError::IoError(std::io::Error::from(
                        std::io::ErrorKind::UnexpectedEof,
                    ))
                })?;

                // Now that we have the peer's socket address and the file hash, we can handle the publish request.
                handle_publish(
                    &mut session,
                    client_streams,
                    hash,
                    file_size,
                    publishers.clone(),
                )
                .await;
            }

            // Handle the client's file-subscription request.
            // Close the connection if we can't complete the request.
            ClientApiRequest::Subscribe => {
                handle_subscribe(&mut session, client_streams, &publishers).await?;
            }

            // Handle the client's request to be introduced to a specific peer over a certain file hash.
            ClientApiRequest::Introduction => {
                handle_introduction(&mut session, client_streams, &publishers).await?;
            }
        }
        // Clear the scratch space before the next iteration.
        // This is a low cost operation because it only changes an internal size value.
        session.bb.clear();
    }
}

/// Generate a random nonce to uniquely identify client connections.
fn random_nonce() -> Nonce {
    [rand::random(), rand::random()]
}

/// Send a ping response to the client by sending the address we introduce them to peers as.
#[tracing::instrument(skip(quic_send))]
async fn socket_ping(
    mut quic_send: quinn::SendStream,
    sock_string: &Arc<RwLock<String>>,
) -> Result<(), ClientRequestError> {
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    // Format the ping response as a length and UTF-8 string.
    {
        let sock_string = sock_string.read().await;
        bb.put_u16(u16::try_from(sock_string.len()).expect("Message content length is invalid"));
        bb.put(sock_string.as_bytes());
    }

    // Send the ping response to the client.
    quic_send
        .write_all(&bb)
        .await
        .map_err(|e| ClientRequestError::IoError(e.into()))
}

/// Update the client's address string with the new port.
#[tracing::instrument(skip(session, quic_recv))]
async fn port_override(
    session: &mut ClientSession,
    mut quic_recv: quinn::RecvStream,
    socket_addr: SocketAddr,
    port_used: &mut u16,
) -> Result<(), ClientRequestError> {
    let port = quic_recv
        .read_u16()
        .await
        .map_err(ClientRequestError::IoError)?;

    // Avoid unnecessary string allocations.
    if port == *port_used {
        return Ok(());
    }

    // Update the shared string with the new port.
    *session.sock_string.write().await = {
        let mut a = socket_addr;
        a.set_port(port);
        a.to_string()
    };
    tracing::info!("Overriding port to {port}");
    *port_used = port;

    // Update the client address string for each
    for pub_lock in &session.client_pubs {
        let mut client = pub_lock.write().await;
        client.address = session.sock_string.clone();
    }

    Ok(())
}

/// Handle QUIC connections for clients that want to publish a new file hash.
#[tracing::instrument(skip(session, client_streams, publishers))]
async fn handle_publish(
    session: &mut ClientSession,
    mut client_streams: BiStream,
    hash: HashBytes,
    file_size: u64,
    publishers: PublishersRef,
) {
    /// Helper to remove a publisher from the list of peers sharing a file hash.
    async fn try_remove_publisher(
        session_nonce: Nonce,
        hash: HashBytes,
        publishers: PublishersRef,
    ) {
        // Remove the client from the list of peers publishing this hash.
        let mut publishers = publishers.write().await;
        if let Some(file_publishers) = publishers.get_mut(&hash) {
            // Remove this client from the file's list of publishers.
            file_publishers.remove(&session_nonce);

            // Remove the file hash from the map if no clients are publishing it.
            if file_publishers.is_empty() {
                publishers.remove(&hash);
            }
        }
    }
    /// A loop to handle messages to be sent to a client publishing a file hash.
    async fn handle_publish_inner(
        mut quic_send: quinn::SendStream,
        mut rx: mpsc::Receiver<String>,
        sock_string: &Arc<RwLock<String>>,
        hash_hex: &str,
    ) {
        #[cfg(debug_assertions)]
        tracing::debug!(
            "Starting publish task for client {} {hash_hex}",
            sock_string.read().await
        );
        let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

        while let Some(message) = rx.recv().await {
            // Format the message as a length and UTF-8 string.
            bb.put_u16(u16::try_from(message.len()).expect("Message content length is invalid"));
            bb.put(message.as_bytes());

            // Try to send the message to the client.
            if let Err(e) = quic_send.write_all(&bb).await {
                tracing::error!("Failed to send message to client: {e}");
                return;
            }
            // Clear the scratch space before the next iteration.
            bb.clear();

            #[cfg(debug_assertions)]
            tracing::debug!("Introduced {message} to {}", sock_string.read().await);
        }
    }

    // Use a channel to handle buffering and flushing of messages.
    // Ensures that the stream doesn't need to be cloned or passed between threads.
    let (tx, rx) = mpsc::channel::<String>(4 * MAX_SERVER_COMMUNICATION_SIZE);

    let client = Arc::new(RwLock::new(Publisher {
        address: session.sock_string.clone(),
        stream: tx,
    }));
    session.client_pubs.push(client.clone());

    // Add the client to a list of peers publishing this hash.
    // Wrap the lock in a block to ensure it is released quickly.
    {
        let mut publishers_lock = publishers.write().await;
        let new_pub = PublishedFile::new(client, file_size);
        if let Some(client_list) = publishers_lock.get_mut(&hash) {
            client_list.insert(session.nonce, new_pub);
        } else {
            publishers_lock.insert(hash, HashMap::from([(session.nonce, new_pub)]));
        }
    }

    // Create a cancellable task to handle the client's publish request.
    let mut scratch = [0u8; 1];

    // Copy relevant session data to the task context.
    let cancellation_token = session.cancellation_token.clone();
    let sock_string = session.sock_string.clone();
    let session_nonce = session.nonce;

    tokio::task::spawn(async move {
        let hash_hex = faster_hex::hex_string(&hash);

        tokio::select! {
            // Allow the server to cancel the task.
            () = cancellation_token.cancelled() => {}

            // Allow the client to cancel their publish request.
            _ = client_streams.recv.read_exact(&mut scratch) => {}

            // Handle the client's file-publishing task.
            () = handle_publish_inner(client_streams.send, rx, &sock_string, &hash_hex) => {}
        }

        // Remove any reference there may be to this publish task.
        try_remove_publisher(session_nonce, hash, publishers).await;

        tracing::info!(
            "Finishing publish task for client {} {hash_hex}",
            sock_string.read().await
        );
    });
}

/// Handle a client request to subscribe to a file hash, receiving a list of peers that are publishing this hash.
#[tracing::instrument(skip(session, client_streams, clients))]
async fn handle_subscribe(
    session: &mut ClientSession,
    mut client_streams: BiStream,
    clients: &PublishersRef,
) -> Result<(), ClientRequestError> {
    // Start by getting the file hash from the client.
    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash)
        .await
        .map_err(|_| {
            ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        })?;

    // Attempt to get the client from the map.
    let read_lock = clients.read().await;
    let Some(client_list) = read_lock.get(&hash).filter(|v| !v.is_empty()) else {
        #[cfg(debug_assertions)]
        {
            let mut hex_hash_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            tracing::debug!(
                "Failed to find client for hash {}",
                faster_hex::hex_encode(&hash, &mut hex_hash_bytes)
                    .expect("Failed to encode hash in hexadecimal"),
            );
        }

        // Send the subscriber a message that no publishers are available.
        client_streams
            .send
            .write_u16(0)
            .await
            .map_err(ClientRequestError::IoError)?;
        return Ok(());
    };

    // Write a temporary zero to the buffer for space efficiency.
    // This will be overwritten later with the actual number of peers introduced.
    session.bb.put_u16(0);

    let clients = client_list.iter();
    let mut n: u16 = 0;
    for (_, pub_client) in clients {
        let file_size = pub_client.file_size;

        // Get read access on client lock.
        let pub_client = pub_client.publisher.read().await;
        let client_address = pub_client.address.read().await;

        // Ensure that the message doesn't exceed the maximum size.
        if session.bb.len() + (size_of::<u64>() + size_of::<u8>()) + client_address.len()
            > MAX_SERVER_COMMUNICATION_SIZE
        {
            break;
        }

        // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
        // Only include the peer if the message was successfully passed.
        if let Ok(()) = pub_client
            .stream
            .send(session.sock_string.read().await.clone())
            .await
        {
            // Send the publisher's socket address to the subscribing client.
            session
                .bb
                .put_u8(u8::try_from(client_address.len()).unwrap());
            session.bb.put(client_address.as_bytes());

            // Send the file size to the subscribing client.
            session.bb.put_u64(file_size);

            n += 1;
        }
    }

    // Overwrite the number of peers shared with the actual count, in big-endian.
    session.bb[..2].copy_from_slice(&n.to_be_bytes());

    // Send the message to the client.
    client_streams
        .send
        .write_all(&session.bb)
        .await
        .map_err(|e| ClientRequestError::IoError(e.into()))?;

    #[cfg(debug_assertions)]
    if n != 0 {
        tracing::debug!(
            "Introduced {} peers to {}",
            n,
            session.sock_string.read().await,
        );
    }

    Ok(())
}

/// Handle a client request to be introduced to a specific client regarding a file they are publishing.
#[tracing::instrument(skip(session, client_streams, clients))]
async fn handle_introduction(
    session: &mut ClientSession,
    mut client_streams: BiStream,
    clients: &PublishersRef,
) -> Result<(), ClientRequestError> {
    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash)
        .await
        .map_err(|_| {
            ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        })?;

    let address_len = client_streams.recv.read_u8().await.map_err(|_| {
        ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;

    let mut scratch_space = [0; 256];
    let slice = &mut scratch_space[..address_len as usize];
    client_streams.recv.read_exact(slice).await.map_err(|_| {
        ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;
    let peer_address = std::str::from_utf8(slice)
        .map(str::to_lowercase)
        .map_err(|_| ClientRequestError::InvalidRequestContent)?;

    // Attempt to get the clients from the file-hash map.
    let read_lock = clients.read().await;
    let Some(client_list) = read_lock.get(&hash).filter(|v| !v.is_empty()) else {
        #[cfg(debug_assertions)]
        {
            let mut hex_hash_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            tracing::debug!(
                "Failed to find client for hash {}",
                faster_hex::hex_encode(&hash, &mut hex_hash_bytes)
                    .expect("Failed to encode hash in hexadecimal"),
            );
        }

        // Send the subscriber a message that no publishers are available.
        client_streams
            .send
            .write_u8(0)
            .await
            .map_err(ClientRequestError::IoError)?;
        return Ok(());
    };

    let clients = client_list.iter();
    for (_, pub_client) in clients {
        // Get read access on client lock.
        let pub_client = pub_client.publisher.read().await;
        let client_address = pub_client.address.read().await;

        if client_address.eq(&peer_address) {
            // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
            if let Ok(()) = pub_client
                .stream
                .send(session.sock_string.read().await.clone())
                .await
            {
                // Send the file size to the subscribing client.
                client_streams
                    .send
                    .write_u8(1)
                    .await
                    .map_err(ClientRequestError::IoError)?;

                #[cfg(debug_assertions)]
                tracing::debug!(
                    "Introduced publisher {} to {}",
                    peer_address,
                    session.sock_string.read().await,
                );
            }

            // We found the correct socket address, stop searching the client list.
            break;
        }
    }

    Ok(())
}
