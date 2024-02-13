use std::{collections::HashMap, sync::Arc};

use bytes::BufMut as _;
use clap::Parser;
use file_yeet_shared::{
    local_now_fmt, ClientApiRequest, HashBytes, SocketAddrHelper, MAX_SERVER_COMMUNICATION_SIZE,
};
use smallvec::SmallVec;
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

/// A mapping between file hashes and the addresses of connected peers that are publishing the file.
type PublishersRef = Arc<RwLock<HashMap<HashBytes, SmallVec<[Client; 3]>>>>;

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
    println!("{} Using bind address: {bind_address:?}", local_now_fmt());

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
                eprintln!(
                    "{} Failed to handle client connection: {e}",
                    local_now_fmt()
                );
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
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    loop {
        let api = ClientApiRequest::try_from(quic_recv.read_u16().await?)?;
        println!("{} {api} from {sock_string}", local_now_fmt());

        match api {
            ClientApiRequest::EmptyPing => {}
            ClientApiRequest::SocketPing => {
                // Format the ping response as a length and UTF-8 string.
                bb.put_u16(
                    u16::try_from(sock_string.len()).expect("Message content length is invalid"),
                );
                bb.put(sock_string.as_bytes());

                // Send the ping response to the client.
                quic_send.write_all(&bb).await?;
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
                println!("{} Overriding port to {port}", local_now_fmt());

                // TODO: If this client is publishing, these addresses will be stale.
                // Store `sock_string` in a `RwLock` pass a thread-safe reference to callers.
            }
            ClientApiRequest::Publish => {
                let mut hash = HashBytes::default();
                quic_recv
                    .read_exact(&mut hash)
                    .await
                    .map(|()| ClientRequestError::PubHashBytes)?;

                // Now that we have the peer's socket address and the file hash, we can handle the publish request.
                if let Err(e) =
                    handle_publish(connection, quic_send, sock_string, hash, publishers, bb).await
                {
                    eprintln!("{} Failed to handle publish request: {e}", local_now_fmt());
                }

                // Terminate our connection with the client.
                // TODO: Consider allowing the client to publish more than one file hash, or subscribe simultaneously to a file.
                return Ok(());
            }
            ClientApiRequest::Subscribe => {
                let mut hash = HashBytes::default();
                quic_recv
                    .read_exact(&mut hash)
                    .await
                    .map(|()| ClientRequestError::SubHashBytes)?;

                // Now that we have the peer's socket address and the file hash, we can handle the subscribe request.
                if let Err(e) =
                    handle_subscribe(&mut quic_send, &sock_string, hash, &publishers, &mut bb).await
                {
                    eprintln!(
                        "{} Failed to handle subscribe request: {e}",
                        local_now_fmt()
                    );
                }
            }
        }
        // Clear the scratch space before the next iteration.
        // This is a low cost operation because it only changes an internal index value.
        bb.clear();
    }
}

/// Handle QUIC connections for clients that want to publish a new file hash.
async fn handle_publish(
    connection: quinn::Connection,
    mut quic_send: quinn::SendStream,
    sock_string: String,
    hash: HashBytes,
    clients: PublishersRef,
    mut bb: bytes::BytesMut,
) -> anyhow::Result<()> {
    // Use a channel to handle buffering and flushing of messages.
    // Ensures that the stream doesn't need to be cloned or passed between threads.
    let (tx, mut rx) = mpsc::channel::<String>(4 * MAX_SERVER_COMMUNICATION_SIZE);
    let sock_string_clone = sock_string.clone();
    tokio::task::spawn(async move {
        #[cfg(debug_assertions)]
        println!(
            "{} Starting subscribe task for client {sock_string_clone}",
            local_now_fmt()
        );

        while let Some(message) = rx.recv().await {
            // Format the message as a length and UTF-8 string.
            bb.put_u16(u16::try_from(message.len()).expect("Message content length is invalid"));
            bb.put(message.as_bytes());

            // Try to send the message to the client.
            if let Err(e) = quic_send.write_all(&bb).await {
                eprintln!("{} Failed to send message to client: {e}", local_now_fmt());
                break;
            }
            // Clear the scratch space before the next iteration.
            bb.clear();

            #[cfg(debug_assertions)]
            println!(
                "{} Introduced {message} to {sock_string_clone}",
                local_now_fmt()
            );
        }

        #[cfg(debug_assertions)]
        println!(
            "{} Closed forwarding thread for client {sock_string_clone}",
            local_now_fmt()
        );
    });

    let address = sock_string.clone();
    let client = Client {
        address,
        stream: tx,
    };

    // Add the client to a list of peers publishing this hash.
    // Ensure the clients lock is dropped before waiting for the client to close the connection.
    {
        let mut clients_lock = clients.write().await;
        if let Some(client_list) = clients_lock.get_mut(&hash) {
            client_list.push(client);
        } else {
            clients_lock.insert(hash, smallvec::smallvec![client]);
        }
    }

    // Wait for the client to close the connection.
    let closed_reason = connection.closed().await;
    println!(
        "{} Client disconnected: {sock_string} {closed_reason:?}",
        local_now_fmt()
    );

    // Remove the client from the list of peers publishing this hash.
    // TODO: Consider identifying clients by a unique ID in case of address collisions.
    if let Some(clients_list) = clients.write().await.get_mut(&hash) {
        clients_list.retain(|c| c.address != sock_string);
    }

    Ok(())
}

/// Handle QUIC connections for clients that want to subscribe to a file hash.
async fn handle_subscribe(
    quic_send: &mut quinn::SendStream,
    sock_string: &String,
    hash: HashBytes,
    clients: &PublishersRef,
    bb: &mut bytes::BytesMut,
) -> Result<(), std::io::Error> {
    // Attempt to get the client from the map.
    let read_lock = clients.read().await;
    let Some(client_list) = read_lock.get(&hash).filter(|v| !v.is_empty()) else {
        #[cfg(debug_assertions)]
        {
            let mut hex_hash_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            println!(
                "{} Failed to find client for hash {}",
                local_now_fmt(),
                faster_hex::hex_encode(&hash, &mut hex_hash_bytes)
                    .expect("Failed to hash as hexadecimal"),
            );
        }

        // Send the subscriber a message that no publishers are available.
        quic_send.write_u16(0).await?;
        return Ok(());
    };

    // Write a temporary zero to the buffer for space efficiency.
    // This will be overwritten later.
    bb.put_u16(0);

    let clients = client_list.iter();
    let mut n: u16 = 0;
    for pub_client in clients {
        // Ensure that the message doesn't exceed the maximum size.
        if bb.len() + 2 + pub_client.address.len() > MAX_SERVER_COMMUNICATION_SIZE {
            break;
        }

        // Feed the publishing client socket address to the task that handles communicating with this client.
        // Only include the peer if the message was successfully passed.
        if let Ok(()) = pub_client.stream.send(sock_string.clone()).await {
            // Send the publisher's socket address to the subscribing client.
            bb.put_u16(u16::try_from(pub_client.address.len()).unwrap());
            bb.put(pub_client.address.as_bytes());
            n += 1;
        }
    }

    // Overwrite the number of peers shared with the actual count, in big-endian.
    bb[..2].copy_from_slice(&n.to_be_bytes());

    // Send the message to the client.
    quic_send.write_all(bb).await?;

    #[cfg(debug_assertions)]
    if n != 0 {
        println!(
            "{} Introduced {} peers to {sock_string}",
            local_now_fmt(),
            n
        );
    }

    Ok(())
}
