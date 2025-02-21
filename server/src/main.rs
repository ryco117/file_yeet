use std::{
    collections::HashMap,
    mem::size_of,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
};

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
    /// A reference to the client's socket address as a string.
    pub address: Arc<RwLock<String>>,

    /// A channel to send messages to the task handling this client's publish request.
    pub stream: mpsc::Sender<String>,
}
type PublisherRef = Arc<RwLock<Publisher>>;

/// A client and the file size they are publishing.
#[derive(Debug)]
struct PublishedFile {
    /// A reference to the publishing client's public address and the channel to peers to them.
    pub publisher: PublisherRef,

    /// The size of the file the client is publishing.
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

    /// Optional limit to the number of connections the server will accept.
    /// Must be a positive integer less than 2^32.
    #[arg(short, long)]
    max_connections: Option<NonZeroU32>,
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
    server_config.migration(false);

    // Create a new QUIC endpoint.
    let local_end = quinn::Endpoint::server(server_config, bind_address)
        .expect("Failed to bind to local QUIC endpoint");

    // Create a map between file hashes and the addresses of peers that have the file.
    let publishers: PublishersRef = PublishersRef::default();

    // Create a cancellation token and set of tasks to allow the server to shut down gracefully.
    let global_cancellation_token = CancellationToken::new();
    let task_master = TaskTracker::new();

    // Create a loop to handle QUIC connections, but allow Ctrl+C to cancel the loop.
    tokio::select! {
        // Gracefully handle Ctrl+C to shut down the server.
        r = tokio::signal::ctrl_c() => {
            if let Err(e) = r {
                tracing::error!("Failed to handle SIGINT, aborting: {e}");
            } else {
                tracing::info!("Shutting down server");
            }
        }

        // Perform the main server loop.
        () = handle_incoming_clients_loop(
            local_end.clone(),
            publishers,
            global_cancellation_token.clone(),
            task_master.clone(),
            args.max_connections
        ) => {}
    }

    // Cancel the server's tasks.
    global_cancellation_token.cancel();

    // Close the QUIC endpoint with the DEADBEEF status.
    local_end.close(quinn::VarInt::from_u32(0xDEAD_BEEF), &[]);

    // Close the tracker after no more tasks should be spawned.
    task_master.close();

    // Wait for the server's tasks to finish.
    task_master.wait().await;

    tracing::info!("Server has shut down");
}

/// Process incoming QUIC connections into their own tasks, allowing for client-task cancellation.
#[tracing::instrument(skip_all)]
async fn handle_incoming_clients_loop(
    local_end: quinn::Endpoint,
    publishers: PublishersRef,
    global_cancellation_token: CancellationToken,
    task_master: TaskTracker,
    max_connections: Option<NonZeroU32>,
) {
    while let Some(connecting) = local_end.accept().await {
        // Check if the server has reached the maximum number of connections.
        if max_connections.is_some_and(|m| {
            m.get() <= u32::try_from(local_end.open_connections()).unwrap_or(u32::MAX)
        }) {
            tracing::warn!("Server has reached the maximum number of connections");
            connecting.refuse();
            continue;
        }

        // Attempt to complete the handshake with the client, else continue.
        let Ok(connecting) = connecting.accept() else {
            continue;
        };

        let global_cancellation_token = global_cancellation_token.clone();
        let publishers = publishers.clone();
        let client_disconnect_token = CancellationToken::new();
        let task_master_clone = task_master.clone();
        task_master.spawn(async move {
            tokio::select! {
                // Allow the server to cancel all client tasks.
                () = global_cancellation_token.cancelled() => client_disconnect_token.cancel(),

                // Handle this client's connection.
                r = handle_quic_connection(connecting, publishers, client_disconnect_token.clone(), task_master_clone) => {
                    // Let all tasks created for this client know that they should shut down as we are done with this connection.
                    client_disconnect_token.cancel();

                    if let Err(e) = r {
                        match e {
                            // Check for a graceful disconnect.
                            ClientRequestError::IncomingClientFailed(quinn::ConnectionError::ApplicationClosed(r)) | ClientRequestError::RequestStream(quinn::ConnectionError::ApplicationClosed(r))
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

    // The server should never exit this loop.
    tracing::error!("Server has stopped accepting new connections unexpectedly");
}

/// Errors encountered while handling a client request.
#[derive(Debug, thiserror::Error)]
enum ClientRequestError {
    /// Failed to establish a QUIC connection.
    #[error("QUIC connection error: {0}")]
    IncomingClientFailed(quinn::ConnectionError),

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

/// Track a connection with a client and the state made through requests.
#[derive(Debug)]
struct ClientSession {
    /// Unique identifier for the client session.
    pub nonce: Nonce,
    pub sock_string: Arc<RwLock<String>>,
    pub port_used: u16,
    pub client_pubs: Vec<PublisherRef>,
    pub cancellation_token: CancellationToken,
}
impl ClientSession {
    pub fn new(socket_addr: SocketAddr, cancellation_token: CancellationToken) -> Self {
        let mut sock_string = socket_addr.to_string();
        sock_string.make_ascii_lowercase();
        let sock_string = Arc::new(RwLock::new(sock_string));
        let port_used = socket_addr.port();
        let nonce = random_nonce();

        Self {
            nonce,
            sock_string,
            port_used,
            client_pubs: Vec::new(),
            cancellation_token,
        }
    }
}

/// Handle the initial QUIC connection and process requests from the client.
#[tracing::instrument(skip_all)]
async fn handle_quic_connection(
    connecting: quinn::Connecting,
    publishers: PublishersRef,
    cancellation_token: CancellationToken,
    task_master: TaskTracker,
) -> Result<(), ClientRequestError> {
    let connection = connecting
        .await
        .map_err(ClientRequestError::IncomingClientFailed)?;
    let socket_addr = connection.remote_address();

    let session = Arc::new(RwLock::new(ClientSession::new(
        socket_addr,
        cancellation_token,
    )));
    let session_sock_string = session.read().await.sock_string.clone();
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
        tracing::info!("{api} from {}", session_sock_string.read().await);

        match api {
            // Send a ping response to the client.
            ClientApiRequest::SocketPing => {
                let cancel = session.read().await.cancellation_token.clone();
                let sock_string = session_sock_string.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request for a ping response.
                        r = socket_ping(client_streams.send, &sock_string) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to send ping response: {e}");
                            }
                        }
                    }
                });
            }

            // Update the client's address string with the new port.
            ClientApiRequest::PortOverride => {
                let session = session.clone();
                task_master.spawn(async move {
                    let cancel = session.read().await.cancellation_token.clone();
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to override the port.
                        r = port_override(&session, client_streams.recv, socket_addr) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to send ping response: {e}");
                            }
                        }
                    }
                });
            }

            // Create a new task to handle the client's file-publishing request.
            ClientApiRequest::Publish => {
                let session = session.clone();
                let task_master_copy = task_master.clone();
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    let cancel = session.read().await.cancellation_token.clone();
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the publish request.
                        r = handle_publish(&session, client_streams, publishers, task_master_copy) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to handle publish request: {e}");
                            }
                        }
                    }
                });
            }

            // Handle the client's file-subscription request.
            ClientApiRequest::Subscribe => {
                let session = session.clone();
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    let cancel = session.read().await.cancellation_token.clone();
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to subscribe to a file hash.
                        r = handle_subscribe(&session, client_streams, &publishers) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to handle subscribe request: {e}");
                            }
                        }
                    }
                });
            }

            // Handle the client's request to be introduced to a specific peer over a certain file hash.
            ClientApiRequest::Introduction => {
                let session = session.clone();
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    let cancel = session.read().await.cancellation_token.clone();
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to be introduced to a specific peer.
                        r = handle_introduction(&session, client_streams, &publishers) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to handle introduction request: {e}");
                            }
                        }
                    }
                });
            }
        }
    }
}

/// Generate a random nonce to uniquely identify client connections.
fn random_nonce() -> Nonce {
    [rand::random(), rand::random()]
}

/// Send a ping response to the client by sending the address we introduce them to peers as.
#[tracing::instrument(skip_all)]
async fn socket_ping(
    mut quic_send: quinn::SendStream,
    sock_string: &RwLock<String>,
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
    session: &RwLock<ClientSession>,
    mut quic_recv: quinn::RecvStream,
    socket_addr: SocketAddr,
) -> Result<(), ClientRequestError> {
    let port = quic_recv
        .read_u16()
        .await
        .map_err(ClientRequestError::IoError)?;

    {
        let session = session.read().await;

        // Avoid unnecessary string allocations.
        if port == session.port_used {
            return Ok(());
        }

        // Update the shared string with the new port.
        *session.sock_string.write().await = {
            let mut a = socket_addr;
            a.set_port(port);
            a.to_string()
        };
    }

    tracing::info!("Overriding port to {port}");
    session.write().await.port_used = port;

    {
        let session = session.read().await;

        // Update the client address string for each
        for pub_lock in &session.client_pubs {
            pub_lock.write().await.address = session.sock_string.clone();
        }
    }

    Ok(())
}

/// Handle QUIC connections for clients that want to publish a new file hash.
#[tracing::instrument(skip_all)]
async fn handle_publish(
    session: &RwLock<ClientSession>,
    mut client_streams: BiStream,
    publishers: PublishersRef,
    task_master: TaskTracker,
) -> Result<(), ClientRequestError> {
    /// Helper to remove a publisher from the list of peers sharing a file hash.
    #[tracing::instrument(skip(publishers))]
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
    #[tracing::instrument(skip(quic_send, rx, sock_string))]
    async fn handle_publish_inner(
        mut quic_send: quinn::SendStream,
        mut rx: mpsc::Receiver<String>,
        sock_string: &RwLock<String>,
        hash_hex: &str,
    ) {
        tracing::info!(
            "Starting publish task for client {}",
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

            tracing::info!("Introduced {message} to {}", sock_string.read().await);
        }
    }

    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash.bytes)
        .await
        .map_err(|_| {
            ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        })?;
    let file_size = client_streams.recv.read_u64().await.map_err(|_| {
        ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;

    // Use a channel to handle buffering and flushing of messages.
    // Ensures that the stream doesn't need to be cloned or passed between threads.
    let (tx, rx) = mpsc::channel::<String>(8);

    let (sock_string, session_nonce) = {
        let session = session.read().await;
        (session.sock_string.clone(), session.nonce)
    };

    let client: Arc<RwLock<Publisher>> = Arc::new(RwLock::new(Publisher {
        address: sock_string.clone(),
        stream: tx,
    }));
    session.write().await.client_pubs.push(client.clone());

    // Add the client to a list of peers publishing this hash.
    // Wrap the lock in a block to ensure it is released quickly.
    {
        let mut publishers_lock = publishers.write().await;
        let new_pub = PublishedFile::new(client, file_size);
        if let Some(client_list) = publishers_lock.get_mut(&hash) {
            client_list.insert(session_nonce, new_pub);
        } else {
            publishers_lock.insert(hash, HashMap::from([(session_nonce, new_pub)]));
        }
    }

    // Create a cancellable task to handle the client's publish request.
    let mut client_cancel_scratch = [0u8; 1];

    // Copy relevant session data to the task context.
    let cancellation_token = session.read().await.cancellation_token.clone();

    task_master.spawn(async move {
        let hash_hex = hash.to_string();

        tokio::select! {
            // Allow the server to cancel the task.
            () = cancellation_token.cancelled() => {}

            // Allow the client to cancel their publish request with a single byte.
            _ = client_streams.recv.read_exact(&mut client_cancel_scratch) => {}

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

    Ok(())
}

/// Handle a client request to subscribe to a file hash, receiving a list of peers that are publishing this hash.
#[tracing::instrument(skip_all)]
async fn handle_subscribe(
    session: &RwLock<ClientSession>,
    mut client_streams: BiStream,
    clients: &PublishersRef,
) -> Result<(), ClientRequestError> {
    // Start by getting the file hash from the client.
    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash.bytes)
        .await
        .map_err(|_| {
            ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        })?;

    // Attempt to get the client from the map.
    let read_lock = clients.read().await;
    let Some(client_list) = read_lock.get(&hash).filter(|v| !v.is_empty()) else {
        tracing::debug!("Failed to find client for hash {hash}");

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
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);
    bb.put_u16(0);

    let clients = client_list.iter();
    let publisher_sock_string = session.read().await.sock_string.read().await.clone();
    let mut n: u16 = 0;
    for (_, pub_client) in clients {
        let file_size = pub_client.file_size;

        // Get read access on client lock.
        let pub_client = pub_client.publisher.read().await;
        let client_address = pub_client.address.read().await;

        // Ensure that the message doesn't exceed the maximum size.
        if bb.len() + (size_of::<u64>() + size_of::<u8>()) + client_address.len()
            > MAX_SERVER_COMMUNICATION_SIZE
        {
            break;
        }

        // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
        // Only include the peer if the message was successfully passed.
        if let Ok(()) = pub_client.stream.send(publisher_sock_string.clone()).await {
            // Send the publisher's socket address to the subscribing client.
            let client_address_bytes = client_address.as_bytes();
            bb.put_u8(u8::try_from(client_address_bytes.len()).unwrap());
            bb.put(client_address_bytes);

            // Send the file size to the subscribing client.
            bb.put_u64(file_size);

            n += 1;
        }
    }

    // Overwrite the number of peers shared with the actual count, in big-endian.
    // TODO: Consider permuting this list before it is sent to the client.
    bb[..2].copy_from_slice(&n.to_be_bytes());

    // Send the message to the client.
    client_streams
        .send
        .write_all(&bb)
        .await
        .map_err(|e| ClientRequestError::IoError(e.into()))?;

    if n != 0 {
        tracing::debug!("Introduced {n} peers to {publisher_sock_string}");
    }

    Ok(())
}

/// Handle a client request to be introduced to a specific client regarding a file they are publishing.
#[tracing::instrument(skip_all)]
async fn handle_introduction(
    session: &RwLock<ClientSession>,
    mut client_streams: BiStream,
    clients: &PublishersRef,
) -> Result<(), ClientRequestError> {
    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash.bytes)
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
        tracing::debug!("Failed to find client for hash {hash}");

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
            let sock_string = session.read().await.sock_string.read().await.clone();

            // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
            if let Ok(()) = pub_client.stream.send(sock_string.clone()).await {
                // Send the file size to the subscribing client.
                client_streams
                    .send
                    .write_u8(1)
                    .await
                    .map_err(ClientRequestError::IoError)?;

                tracing::debug!("Introduced publisher {peer_address} to {sock_string}");
            }

            // We found the correct socket address, stop searching the client list.
            break;
        }
    }

    Ok(())
}
