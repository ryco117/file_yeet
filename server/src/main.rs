// `warp` websocket API learned from https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use chrono::Local;
use clap::Parser;
use file_yeet_shared::MAX_PAYLOAD_SIZE;
use futures_util::SinkExt;
use tokio::sync::{mpsc, RwLock};
use warp::{
    http::StatusCode,
    reply::{Reply, WithStatus},
    ws::{Message, WebSocket},
    Filter,
};

/// A client that has connected to the server.
struct Client {
    pub address: SocketAddr,
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

/// The type for mapping between file hashes and the addresses of connected peers.
#[derive(Default, Clone)]
struct ClientMap {
    pub lock: Arc<RwLock<HashMap<[u8; 32], Client>>>,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    let args = Cli::parse();

    // Determine which address to bind to.
    // TODO: Allow using an IPv6 address to bind to.
    let bind_address = (
        IpAddr::V4(args.bind_ip.as_ref().map_or(Ipv4Addr::LOCALHOST, |s| {
            s.parse().expect("Invalid IP address")
        })),
        args.bind_port,
    );

    // Print out the address we're going to bind to.
    println!("{} Using bind address: {bind_address:?}", Local::now());

    // Create a map between file hashes and the addresses of peers that have the file.
    let clients: ClientMap = ClientMap::default();
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
                move |hash_hex: String, ws: warp::ws::Ws, client_socket, forwarded_for, clients| {
                    // Ensure a client socket address can be determined, otherwise return an error.
                    let client_socket =
                        match determine_client_address(client_socket, &forwarded_for) {
                            Ok(addr) => addr,
                            Err(e) => return e,
                        };

                    // Validate the file hash is hexadecimal of the correct length or return an error.
                    let Some(hash) = validate_hash_hex(&hash_hex) else {
                        eprintln!("{} Failed to validate SHA-256 hash", Local::now());
                        return warp::reply::with_status(
                            "Failed to decode hash\n".to_owned(),
                            StatusCode::BAD_REQUEST,
                        )
                        .into_response();
                    };

                    // Handle the websocket connection, established through an HTTP upgrade.
                    ws.on_upgrade(move |ws| {
                        handle_publish_websocket(ws, client_socket, hash, clients)
                    })
                    .into_response()
                },
            );

        // API for fetching the address of a peer that has a file.
        let subscribe_api = warp::path!("sub" / String)
            .and(warp::addr::remote())
            .and(warp::header::optional("X-Forwarded-For"))
            .and(get_clients)
            .and_then(
                move |hash_hex, client_socket, forwarded_for, clients| async move {
                    // Ensure a client socket address can be determined, otherwise return an error.
                    let client_socket =
                        match determine_client_address(client_socket, &forwarded_for) {
                            Ok(addr) => addr,
                            Err(e) => return Ok::<_, warp::Rejection>(e),
                        };

                    // Handle the fetch request asynchronously and promise an HTTP response.
                    Ok::<_, warp::Rejection>(
                        handle_subscribe_fetch(client_socket, hash_hex, clients)
                            .await
                            .into_response(),
                    )
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
    client_socket: SocketAddr,
    hash: [u8; 32],
    clients: ClientMap,
) {
    // Internal function to make error handling more convenient.
    let handle_publish = || async move {
        // Necessary to `split()` the websocket into a sender and receiver.
        use futures_util::StreamExt as _;

        let sock_string = client_socket.to_string();
        println!(
            "{} New publish connection from: {}",
            Local::now(),
            &sock_string
        );

        // Split the socket into a sender and receiver of messages.
        let (mut client_tx, _) = websocket.split();

        // Send the client back the socket address we believe to be theirs.
        // This is so users can perform their own sanity checks on the result.
        client_tx
            .send(Message::text(&sock_string))
            .await
            .map_err(|e| {
                eprintln!(
                    "{} Failed to send socket address to client: {e}",
                    Local::now()
                );
            })?;

        // Use a channel to handle buffering and flushing of messages.
        // Ensures that the websocket stream doesn't need to be cloned or passed between threads.
        let (tx, mut rx) = mpsc::channel(2 * MAX_PAYLOAD_SIZE);
        tokio::task::spawn(async move {
            while let Some(message) = rx.recv().await {
                client_tx.send(message).await.unwrap_or_else(|e| {
                    eprintln!("Websocket send error: {e}");
                });
            }
        });

        let client = Client {
            address: client_socket,
            stream: tx,
        };

        // Add the client to the map of clients.
        // TODO: If there is already a client for this hash, perhaps multple clients can be stored for a file hash.
        if let Some(old_client) = clients.lock.write().await.insert(hash, client) {
            println!("{} Replaced client: {}", Local::now(), old_client.address);
        }
        Ok::<(), ()>(())
    };

    // Springboard to the internal function and handle the result asynchronously.
    handle_publish().await.unwrap_or_default();
}

/// Handle the fetch request for a specific file hash.
async fn handle_subscribe_fetch(
    subscriber_socket: SocketAddr,
    hash_hex: String,
    clients: ClientMap,
) -> WithStatus<String> {
    let sock_string = subscriber_socket.to_string();
    println!(
        "{} New subscribe connection from: {}",
        Local::now(),
        &sock_string
    );

    // Validate the file hash or return an error.
    let Some(hash) = validate_hash_hex(&hash_hex) else {
        eprintln!("{} Failed to validate SHA-256 hash", Local::now());
        return warp::reply::with_status(
            "Failed to decode hash\n".to_owned(),
            StatusCode::BAD_REQUEST,
        );
    };

    // Attempt to get the client from the map.
    let read_lock = clients.lock.read().await;
    let Some(pub_client) = read_lock.get(&hash) else {
        eprintln!("{} Failed to find client for hash", Local::now());
        return warp::reply::with_status(
            "Failed to find client for hash\n".to_owned(),
            StatusCode::NOT_FOUND,
        );
    };

    // Feed the client socket address to the task that handles communicating with this client.
    pub_client
        .stream
        .send(Message::text(sock_string))
        .await
        .expect("Could not feed the publish task thread");

    // Send the client the address of the peer that has the file.
    warp::reply::with_status(pub_client.address.to_string(), StatusCode::OK)
}

/// Validate the hash string is the correct length and can be decoded.
fn validate_hash_hex(hash_hex: &str) -> Option<[u8; 32]> {
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
        "{} Known client information: Socket: {:?} X-Forwarded-For: {:?}",
        Local::now(),
        &client_socket,
        &forwarded_for
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
