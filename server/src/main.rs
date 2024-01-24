// `warp` websocket API learned from https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use chrono::Local;
use clap::Parser;
use file_yeet_shared::{SocketAddrHelper, MAX_PAYLOAD_SIZE};
use futures_util::SinkExt;
use tokio::sync::{mpsc, RwLock};
use warp::{
    http::StatusCode,
    reply::Reply,
    ws::{Message, WebSocket},
    Filter,
};

/// A client that has connected to the server.
struct Client {
    pub address: String,
    pub stream: mpsc::Sender<Message>,
}

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

/// Type for a block of raw SHA-256 bytes.
type HashBytes = [u8; 32];

/// The type for mapping between file hashes and the addresses of connected peers that are publishing the file.
#[derive(Default, Clone)]
struct ClientMapRef {
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

    // Create a map between file hashes and the addresses of peers that have the file.
    let clients: ClientMapRef = ClientMapRef::default();
    let get_clients = warp::any().map(move || clients.clone());

    // Define the HTTP based API.
    let api = {
        // Use `warp` to create an API for publishing new files.
        let publish_api = warp::path!("pub" / String)
            // The `ws()` filter will prepare the Websocket handshake.
            .and(warp::ws())
            .and(warp::addr::remote())
            .and(warp::header::optional("X-Forwarded-For"))
            .and(get_clients.clone())
            .map(
                |hash_hex: String, ws: warp::ws::Ws, client_socket, forwarded_for, clients| {
                    // Ensure a client socket address can be determined, otherwise return an error.
                    let (sock_string, hash) =
                        match validate_file_request(client_socket, &forwarded_for, &hash_hex) {
                            Ok(v) => v,
                            Err(e) => return e,
                        };

                    // Handle the websocket connection, established through an HTTP upgrade.
                    // NOTE: This "double move" is necessary to move `hash` into the outer closure, and to move `ws` into the async block.
                    ws.on_upgrade(move |ws| async move {
                        if let Err(e) =
                            handle_publish_websocket(ws, sock_string, hash, clients).await
                        {
                            eprintln!("{} Failed to handle publish websocket: {e}", Local::now());
                        }
                    })
                    .into_response()
                },
            );

        // API for fetching the address of a peer that has a file.
        let subscribe_api = warp::path!("sub" / String)
            .and(warp::ws())
            .and(warp::addr::remote())
            .and(warp::header::optional("X-Forwarded-For"))
            .and(get_clients)
            .and_then(
                |hash_hex: String,
                 ws: warp::ws::Ws,
                 client_socket,
                 forwarded_for,
                 clients: ClientMapRef| async move {
                    // Ensure a client socket address can be determined, otherwise return an error.
                    let (sock_string, hash) =
                        match validate_file_request(client_socket, &forwarded_for, &hash_hex) {
                            Ok(v) => v,
                            Err(e) => return Ok::<_, warp::reject::Rejection>(e),
                        };

                    {
                        // Attempt to get the client from the map. If none exist, return an error.
                        // TODO: Allow the client to specify if they are willing to wait?
                        let read_lock = clients.lock.read().await;
                        let Some(_) = read_lock.get(&hash) else {
                            eprintln!("{} Failed to find client for hash", Local::now());
                            return Ok(warp::reply::with_status(
                                "Failed to find client for hash\n".to_owned(),
                                StatusCode::NOT_FOUND,
                            )
                            .into_response());
                        };
                    }

                    // Handle the websocket connection, established through an HTTP upgrade.
                    // See above NOTE on "double move" necessity.
                    Ok(ws
                        .on_upgrade(move |ws| async move {
                            if let Err(e) =
                                handle_subscribe_websocket(ws, sock_string, hash, clients).await
                            {
                                eprintln!(
                                    "{} Failed to handle publish websocket: {e}",
                                    Local::now()
                                );
                            }
                        })
                        .into_response())
                },
            );

        // Merge available endpoints.
        publish_api.or(subscribe_api)
    };

    // Start the `warp` server.
    warp::serve(api).run(bind_address).await;
}

/// Handle websocket connections for clients that want to publish a new file hash.
async fn handle_publish_websocket(
    websocket: WebSocket,
    sock_string: String,
    hash: HashBytes,
    clients: ClientMapRef,
) -> anyhow::Result<()> {
    // Necessary to `split()` the websocket into a sender and receiver.
    use futures_util::StreamExt as _;

    // Split the socket into a sender and receiver of messages.
    let (mut client_tx, mut client_rx) = websocket.split();

    // Send the client back the socket address we believe to be theirs.
    // This is so users can perform their own sanity checks on the result.
    client_tx.send(Message::text(&sock_string)).await?;

    // Use a channel to handle buffering and flushing of messages.
    // Ensures that the websocket stream doesn't need to be cloned or passed between threads.
    let (tx, mut rx) = mpsc::channel(4 * MAX_PAYLOAD_SIZE);
    let sock_string_clone = sock_string.clone();
    tokio::task::spawn(async move {
        while let Some(message) = rx.recv().await {
            client_tx.send(message).await.unwrap_or_else(|e| {
                eprintln!("{} Websocket send error: {e}", Local::now());
            });
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

    // Ensure that we handle connection closes from the client.
    if client_rx.next().await.is_some() {
        println!(
            "{} Received unexpected message from client, closing connection",
            Local::now()
        );
    }

    println!("{} Client disconnected: {sock_string}", Local::now());

    // TODO: Handle different client addresses for one file hash.
    clients.lock.write().await.remove(&hash);

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum SubscribeError {
    #[error("No publishing peer available")]
    PubNotFound,
}

/// Handle websocket connections for clients that want to subscribe to a file hash.
async fn handle_subscribe_websocket(
    mut websocket: WebSocket,
    sock_string: String,
    hash: HashBytes,
    clients: ClientMapRef,
) -> anyhow::Result<()> {
    // Send the client back the socket address we believe to be theirs.
    // This is so users can perform their own sanity checks on the result.
    websocket.send(Message::text(&sock_string)).await?;

    // Attempt to get the client from the map.
    let read_lock = clients.lock.read().await;
    let Some(pub_client) = read_lock.get(&hash) else {
        eprintln!("{} Failed to find client for hash", Local::now());

        // TODO: Allow a client to wait for a publishing peer to become available.
        let _ = websocket
            .send(Message::text("No publishing peer available"))
            .await;
        return Err(SubscribeError::PubNotFound.into());
    };

    // Feed the publishing client socket address to the task that handles communicating with this client.
    pub_client
        .stream
        .send(Message::text(sock_string))
        .await
        .expect("Could not feed the publish task thread");

    // Send the publisher's socket address to the subscribing client.
    websocket.send(Message::text(&pub_client.address)).await?;

    Ok(())
}

/// Validate that the client's socket address can be determined.
fn validate_file_request(
    subscriber_socket: Option<SocketAddr>,
    forwarded_for: &Option<String>,
    hash_hex: &str,
) -> Result<(String, HashBytes), warp::reply::Response> {
    let subscriber_socket = determine_client_address(subscriber_socket, forwarded_for)?;
    let sock_string = subscriber_socket.to_string();
    println!("{} New connection from: {sock_string}", Local::now());

    // Validate the file hash or return an error.
    if let Some(hash) = validate_hash_hex(hash_hex) {
        // Return the validated hash and the client's socket address.
        println!("{} Validated SHA-256 hash {hash_hex}", Local::now());
        Ok((sock_string, hash))
    } else {
        // Invalid file hash, return an error to the client.
        eprintln!("{} Failed to validate SHA-256 hash", Local::now());
        Err(warp::reply::with_status(
            "Failed to decode hash\n".to_owned(),
            StatusCode::BAD_REQUEST,
        )
        .into_response())
    }
}

/// Validate the hash string is the correct length and can be decoded.
fn validate_hash_hex(hash_hex: &str) -> Option<HashBytes> {
    let mut hash = [0; 32];
    if hash_hex.len() != 2 * hash.len()
        || faster_hex::hex_decode(hash_hex.as_bytes(), &mut hash).is_err()
    {
        eprintln!("{} Failed to validate SHA-256 hash", Local::now());
        return None;
    }
    Some(hash)
}

/// Helper to use the available HTTP information to determine which address to use for the client.
fn determine_client_address(
    client_socket: Option<SocketAddr>,
    forwarded_for: &Option<String>,
) -> Result<SocketAddr, warp::reply::Response> {
    println!(
        "{} Known client information: Socket: {client_socket:?} X-Forwarded-For: {forwarded_for:?}",
        Local::now()
    );

    // Use the `X-Forwarded-For` header to determine if the client is behind a proxy, and return an error if so.
    // This header takes the form of a comma separated list, with the first entry being the client's address.
    let forwarded_client = forwarded_for
        .as_ref()
        .map(String::as_str)
        .unwrap_or_default()
        .split(',')
        .next();
    if let Some(client_address) = forwarded_client {
        if !client_address.is_empty() {
            // The headers indicate that a proxy is between the client and the server.
            // This means that TCP hole punching will not work, abort.
            eprintln!(
                "{} Client is behind a proxy, aborting TCP hole punching: {client_address}",
                Local::now()
            );
            return Err(warp::reply::with_status(
                "Client is behind a proxy\n",
                StatusCode::BAD_GATEWAY,
            )
            .into_response());
        }
    }

    // Ensure that the client socket address can be determined or return an error.
    client_socket.ok_or_else(|| {
        eprintln!("{} Failed to get client socket", Local::now());

        // Let the client know that we couldn't get their socket address.
        warp::reply::with_status(
            "Failed to get client socket\n",
            StatusCode::SERVICE_UNAVAILABLE,
        )
        .into_response()
    })
}
