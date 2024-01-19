// `warp` websocket API learned from https://github.com/seanmonstar/warp/blob/master/examples/websockets_chat.rs.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use chrono::Local;
use clap::Parser;
use futures_util::{stream::SplitSink, SinkExt};
use tokio::sync::RwLock;
use warp::{
    http::StatusCode,
    reply::{Reply, WithStatus},
    ws::{Message, WebSocket},
    Filter,
};

/// A client that has connected to the server.
struct Client {
    pub address: SocketAddr,
    pub stream: SplitSink<WebSocket, Message>,
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
        /// Rewrap the address in an `Ok` or print and wrap `Response` as an `Err`.
        fn unwrap_address_or_respond(
            addr: Option<SocketAddr>,
        ) -> Result<SocketAddr, warp::reply::Response> {
            addr.ok_or_else(|| {
                eprintln!("{} Failed to get client socket", Local::now());

                // Let the client know that we couldn't get their socket address.
                warp::reply::with_status(
                    "Failed to get client socket",
                    StatusCode::SERVICE_UNAVAILABLE,
                )
                .into_response()
            })
        }

        // Use `warp` to create an API for publishing new files.
        let publish_api = warp::path("pub")
            // The `ws()` filter will prepare the Websocket handshake.
            .and(warp::ws())
            .and(warp::addr::remote())
            .and(get_clients.clone())
            .map(move |ws: warp::ws::Ws, client_socket, clients| {
                // Ensure a client socket address can be established, otherwise return an error.
                let client_socket = match unwrap_address_or_respond(client_socket) {
                    Ok(addr) => addr,
                    Err(err) => return err,
                };

                // Handle the websocket connection, established through an HTTP upgrade.
                ws.on_upgrade(move |ws| handle_publish_websocket(ws, client_socket, clients))
                    .into_response()
            });

        // API for fetching the address of a peer that has a file.
        let subscribe_api =
            warp::path!("sub" / String)
                .and(get_clients)
                .and_then(move |hash_hex, clients| async {
                    // Handle the fetch request asynchronously and promise an HTTP response.
                    Ok::<WithStatus<std::string::String>, warp::Rejection>(
                        handle_subscribe_fetch(hash_hex, clients).await,
                    )
                });

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
    clients: ClientMap,
) {
    /// Internal function to make error handling more convenient.
    async fn handle_internal(
        websocket: WebSocket,
        client_socket: SocketAddr,
        clients: ClientMap,
    ) -> Result<(), ()> {
        // Necessary to `split()` the websocket into a sender and receiver.
        use futures_util::StreamExt as _;

        let sock_string = client_socket.to_string();
        println!("{} New connection from: {}", Local::now(), &sock_string);

        // Split the socket into a sender and receiver of messages.
        let (user_tx, mut user_rx) = websocket.split();

        let mut client = Client {
            address: client_socket,
            stream: user_tx,
        };

        // Send the client back the socket address we believe to be theirs.
        // This is so users can perform their own sanity checks on the result.
        client
            .stream
            .send(Message::text(&sock_string))
            .await
            .map_err(|err| {
                eprintln!(
                    "{} Failed to send socket address to client: {err}",
                    Local::now()
                );
            })?;

        // Read the SHA-256 hash of the file from the client as a byte sequence.
        let msg = user_rx
            .next()
            .await
            .ok_or_else(|| eprintln!("{} The client closed the websocket early", Local::now()))?
            .map_err(|err| {
                eprintln!(
                    "{} Failed to receive message from client: {err}",
                    Local::now()
                );
            })?;

        // Ensure the correct number of bytes were sent.
        let mut hash = [0; 32];
        let bytes = msg.as_bytes();
        if bytes.len() != hash.len() {
            return Err(eprintln!(
                "{} Received invalid number of bytes for a SHA-256 hash from client",
                Local::now()
            ));
        }
        hash.copy_from_slice(bytes);

        // Add the client to the map of clients.
        if let Some(old_client) = clients.lock.write().await.insert(hash, client) {
            println!("{} Replaced client: {}", Local::now(), old_client.address);
        }
        Ok(())
    }

    // Springboard to the internal function and handle the result asynchronously.
    handle_internal(websocket, client_socket, clients)
        .await
        .unwrap_or_default();
}

/// Handle the fetch request for a specific file hash.
async fn handle_subscribe_fetch(hash_hex: String, clients: ClientMap) -> WithStatus<String> {
    // Validate the hash string is the correct length and can be decoded.
    let mut hash = [0; 32];
    if hash_hex.len() != 2 * hash.len()
        || faster_hex::hex_decode(hash_hex.as_bytes(), &mut hash).is_err()
    {
        eprintln!("{} Failed to decode hash", Local::now());
        return warp::reply::with_status(
            "Failed to decode hash".to_owned(),
            StatusCode::BAD_REQUEST,
        );
    }

    // Attempt to get the client from the map.
    let read_lock = clients.lock.read().await;
    let Some(client) = read_lock.get(&hash) else {
        eprintln!("{} Failed to find client for hash", Local::now());
        return warp::reply::with_status(
            "Failed to find client for hash".to_owned(),
            StatusCode::NOT_FOUND,
        );
    };

    // Send the client the address of the peer that has the file.
    warp::reply::with_status(client.address.to_string(), StatusCode::OK)
}
