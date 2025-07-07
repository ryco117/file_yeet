use std::{
    collections::HashMap,
    mem::size_of,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
};

use bytes::BufMut as _;
use clap::Parser;
use file_yeet_shared::{
    BiStream, ClientApiRequest, HashBytes, SocketAddrHelper, GOODBYE_CODE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use rand::seq::SliceRandom;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, RwLock},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A client stream that is handling a publish request.
#[derive(Debug)]
struct Publisher {
    /// The IPv6-mapped address of the client publishing the file.
    pub peer_ip: Ipv6Addr,

    /// A reference to the mutable preferred port of the publishing client.
    pub preferred_port: Arc<RwLock<u16>>,

    /// A channel to send messages to the task handling this client's publish request.
    pub stream: mpsc::Sender<(Ipv6Addr, u16)>,
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
}

/// Track a connection with a client and the state made through requests.
#[derive(Debug)]
struct ClientSession {
    /// Unique identifier for the client session.
    pub nonce: Nonce,
    pub preferred_port: Arc<RwLock<u16>>,
    pub client_pubs: Vec<PublisherRef>,
    pub cancellation_token: CancellationToken,
}
impl ClientSession {
    pub fn new(socket_addr: SocketAddr, cancellation_token: CancellationToken) -> Self {
        let preferred_port = Arc::new(RwLock::new(socket_addr.port()));
        let nonce = random_nonce();

        Self {
            nonce,
            preferred_port,
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
        cancellation_token.clone(),
    )));
    let client_preferred_port = session.read().await.preferred_port.clone();
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
        tracing::info!("{api} from {socket_addr}");

        match api {
            // Send a ping response to the client.
            ClientApiRequest::SocketPing => {
                let cancel = cancellation_token.clone();
                let port = client_preferred_port.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request for a ping response.
                        r = socket_ping(client_streams.send, socket_addr.ip(), &port) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to send ping response: {e}");
                            }
                        }
                    }
                });
            }

            // Update the client's address string with the new port.
            ClientApiRequest::PortOverride => {
                let port = client_preferred_port.clone();
                let cancel = cancellation_token.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to override the port.
                        r = port_override(client_streams.recv, socket_addr, &port) => {
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
                let cancel = cancellation_token.clone();
                let task_master_copy = task_master.clone();
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the publish request.
                        r = handle_publish(
                            &session,
                            client_streams,
                            socket_addr.ip(),
                            publishers,
                            task_master_copy,
                        ) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to handle publish request: {e}");
                            }
                        }
                    }
                });
            }

            // Handle the client's file-subscription request.
            ClientApiRequest::Subscribe => {
                let cancel = cancellation_token.clone();
                let port = *client_preferred_port.read().await;
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to subscribe to a file hash.
                        r = handle_subscribe(client_streams, socket_addr.ip(), port, &publishers) => {
                            if let Err(e) = r {
                                tracing::error!("Failed to handle subscribe request: {e}");
                            }
                        }
                    }
                });
            }

            // Handle the client's request to be introduced to a specific peer over a certain file hash.
            ClientApiRequest::Introduction => {
                let cancel = cancellation_token.clone();
                let port = *client_preferred_port.read().await;
                let publishers = publishers.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        // Allow the server to cancel the task.
                        () = cancel.cancelled() => {}

                        // Handle the client's request to be introduced to a specific peer.
                        r = handle_introduction(client_streams, socket_addr.ip(), port, &publishers) => {
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
    peer_ip: IpAddr,
    preferred_port: &RwLock<u16>,
) -> Result<(), ClientRequestError> {
    const RESPONSE_SIZE: usize = 16 + 2;
    let mut bb = bytes::BytesMut::with_capacity(RESPONSE_SIZE);

    // Format the ping response as a mapped IPv6 address and port.
    file_yeet_shared::write_ip_and_port(&mut bb, peer_ip, *preferred_port.read().await);

    // Send the ping response to the client.
    quic_send
        .write_all(&bb)
        .await
        .map_err(|e| ClientRequestError::IoError(e.into()))
}

/// Update the client's address string with the new port.
#[tracing::instrument(skip(quic_recv, preferred_port))]
async fn port_override(
    mut quic_recv: quinn::RecvStream,
    peer_socket: SocketAddr,
    preferred_port: &RwLock<u16>,
) -> Result<(), ClientRequestError> {
    let mut port = quic_recv
        .read_u16()
        .await
        .map_err(ClientRequestError::IoError)?;

    tracing::info!("Overriding port with {port}");
    if port == 0 {
        port = peer_socket.port();
    }

    // Update the mutable lock with the new port.
    *preferred_port.write().await = port;

    Ok(())
}

/// Handle QUIC connections for clients that want to publish a new file hash.
#[tracing::instrument(skip_all)]
async fn handle_publish(
    session: &RwLock<ClientSession>,
    mut client_streams: BiStream,
    peer_address: IpAddr,
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
    #[tracing::instrument(skip(quic_send, rx))]
    async fn handle_publish_inner(
        mut quic_send: quinn::SendStream,
        mut rx: mpsc::Receiver<(Ipv6Addr, u16)>,
    ) {
        tracing::info!("Starting publish task for client");
        let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

        while let Some((peer_ip, port)) = rx.recv().await {
            // Format the message as an IP address and port.
            file_yeet_shared::write_ipv6_and_port(&mut bb, peer_ip, port);

            // Try to send the message to the client.
            if let Err(e) = quic_send.write_all(&bb).await {
                tracing::error!("Failed to send message to client: {e}");
                return;
            }
            // Clear the scratch space before the next iteration.
            bb.clear();

            tracing::info!("Introduced {peer_ip} to peer");
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
    let (tx, rx) = mpsc::channel::<(Ipv6Addr, u16)>(8);

    let (preferred_port, session_nonce) = {
        let session = session.read().await;
        (session.preferred_port.clone(), session.nonce)
    };

    let peer_ip = file_yeet_shared::ipv6_mapped(peer_address);
    let client: Arc<RwLock<Publisher>> = Arc::new(RwLock::new(Publisher {
        peer_ip,
        preferred_port: preferred_port.clone(),
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

    let cancellation_token = session.read().await.cancellation_token.clone();
    task_master.spawn(async move {
        tokio::select! {
            // Allow the server to cancel the task.
            () = cancellation_token.cancelled() => {}

            // Allow the client to gracefully cancel their publish request with a single byte.
            _ = client_streams.recv.read_exact(&mut client_cancel_scratch) => {}

            // Handle the client's file-publishing task.
            () = handle_publish_inner(client_streams.send, rx) => {}
        }

        // Remove any reference there may be to this publish task.
        try_remove_publisher(session_nonce, hash, publishers).await;

        tracing::info!("Finishing publish task for client {hash}",);
    });

    Ok(())
}

/// Handle a client request to subscribe to a file hash, receiving a list of peers that are publishing this hash.
#[tracing::instrument(skip(client_streams, client_preferred_port, clients))]
async fn handle_subscribe(
    mut client_streams: BiStream,
    client_ip: IpAddr,
    client_preferred_port: u16,
    clients: &PublishersRef,
) -> Result<(), ClientRequestError> {
    // Constants for the maximum number of peer-published items to send to the client.
    const PEER_PUBLISH_BYTE_SIZE: usize =
        size_of::<[u8; 16]>() + size_of::<u16>() + size_of::<u64>();
    const MAX_PUBLISHES_SENT: usize = MAX_SERVER_COMMUNICATION_SIZE / PEER_PUBLISH_BYTE_SIZE;

    // Start by getting the file hash from the client.
    let mut hash = HashBytes::default();
    client_streams
        .recv
        .read_exact(&mut hash.bytes)
        .await
        .map_err(|_| {
            ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        })?;
    let client_ip = file_yeet_shared::ipv6_mapped(client_ip);

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

    // Take a random sample of the publishers to send to the client.
    // TODO: If client_list has more than `MAX_PUBLISHES_SENT` items, random sampling should be used before the `take` call.
    let mut peer_publish_list: Vec<_> = client_list.values().take(MAX_PUBLISHES_SENT).collect();
    slice_shuffle(&mut peer_publish_list);

    let mut n: u16 = 0;
    for pub_client in peer_publish_list {
        let file_size = pub_client.file_size;

        // Get read access on client lock.
        let pub_client = pub_client.publisher.read().await;
        let publishing_ip = pub_client.peer_ip;
        let publishing_port = *pub_client.preferred_port.read().await;

        // Ensure that the message doesn't exceed the maximum size.
        if bb.len() + PEER_PUBLISH_BYTE_SIZE > MAX_SERVER_COMMUNICATION_SIZE {
            break;
        }

        // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
        // Only include the peer if the message was successfully passed.
        if let Ok(()) = pub_client
            .stream
            .send((client_ip, client_preferred_port))
            .await
        {
            // Send the publisher's socket address to the subscribing client.
            file_yeet_shared::write_ipv6_and_port(&mut bb, publishing_ip, publishing_port);

            // Send the file size to the subscribing client.
            bb.put_u64(file_size);

            n += 1;
        }
    }

    // Overwrite the number of peers shared with the actual count, in big-endian.
    bb[..2].copy_from_slice(&n.to_be_bytes());

    // Send the message to the client.
    client_streams
        .send
        .write_all(&bb)
        .await
        .map_err(|e| ClientRequestError::IoError(e.into()))?;

    if n != 0 {
        tracing::debug!("Introduced {n} peers");
    }

    Ok(())
}

/// Handle a client request to be introduced to a specific client regarding a file they are publishing.
#[tracing::instrument(skip_all)]
async fn handle_introduction(
    mut client_streams: BiStream,
    client_ip: IpAddr,
    client_preferred_port: u16,
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

    // Read the requested IP address and port from the stream.
    let (requested_peer_ip, requested_peer_port) =
        file_yeet_shared::read_ip_and_port(&mut client_streams.recv)
            .await
            .map_err(|_| {
                ClientRequestError::IoError(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            })?;

    // Attempt to get the clients from the file-hash map.
    let read_lock = clients.read().await;
    let Some(client_list) = read_lock.get(&hash).filter(|v| !v.is_empty()) else {
        tracing::debug!("Failed to find client for hash {hash}");
        return Ok(());
    };

    let client_ip = file_yeet_shared::ipv6_mapped(client_ip);
    for pub_client in client_list.values() {
        // Get read access on client lock.
        let pub_client = pub_client.publisher.read().await;
        let publishing_ip = pub_client.peer_ip;
        let publishing_port = &pub_client.preferred_port;

        if publishing_ip.eq(&requested_peer_ip)
            && *publishing_port.read().await == requested_peer_port
        {
            // Feed the subscribing client's socket address to the task that handles communicating with the publisher.
            if let Ok(()) = pub_client
                .stream
                .send((client_ip, client_preferred_port))
                .await
            {
                tracing::debug!("Introduced publisher {publishing_ip}");
            }
        }
    }

    Ok(())
}

/// A helper to randomly permute a mutable slice.
fn slice_shuffle<T>(v: &mut [T]) {
    let mut rng = rand::rng();
    v.shuffle(&mut rng);
}
