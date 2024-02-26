use core::BiStream;
use std::{io::Write as _, num::NonZeroU16, path::Path, time::Duration};

use bytes::BufMut as _;
use file_yeet_shared::{local_now_fmt, HashBytes, MAX_SERVER_COMMUNICATION_SIZE};
use futures_util::{stream::FuturesUnordered, StreamExt};
use iced::Application;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

mod core;
mod gui;

/// The command line interface for `file_yeet_client`.
#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The address of the rendezvous server. Either an IP address or a hostname.
    #[arg(short, long)]
    server_address: Option<String>,

    /// The server port to connect to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    server_port: NonZeroU16,

    /// Override the port seen by the server to communicate a custom port to peers.
    /// Useful when port-forwarding.
    #[arg(short = 'o', long)]
    port_override: Option<NonZeroU16>,

    /// The IP address of local gateway to use when attempting the Port Control Protocol.
    /// If not specified, a default gateway will be searched for.
    #[arg(short, long)]
    gateway: Option<String>,

    /// When enabled the client will attempt NAT-PMP and PCP port mapping protocols.
    #[arg(short, long)]
    nat_map: bool,

    #[command(subcommand)]
    cmd: Option<FileYeetCommand>,
}

/// The subcommands for `file_yeet_client`.
#[derive(clap::Subcommand)]
enum FileYeetCommand {
    /// Publish a file to the server.
    Pub { file_path: String },
    /// Subscribe to a file from the server.
    Sub {
        sha256_hex: String,
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    // Parse command line arguments.
    use clap::Parser as _;
    let args = Cli::parse();

    // If no subcommand was provided, run the GUI.
    let Some(cmd) = args.cmd else {
        if let Err(e) = gui::AppState::run(iced::Settings::default()) {
            eprintln!("{} GUI failed to run: {e}", local_now_fmt());
        }

        return;
    };

    // Create a buffer for sending and receiving data within the payload size for `file_yeet`.
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    // Connect to the public file_yeet_server.
    let core::PreparedConnection {
        endpoint,
        server_connection,
        port_mapping,
    } = core::prepare_server_connection(
        args.server_address.as_deref(),
        args.server_port,
        args.gateway.as_deref(),
        if let Some(g) = args.port_override {
            core::PortMappingConfig::PortForwarding(g)
        } else if args.nat_map {
            core::PortMappingConfig::TryNatPmp
        } else {
            core::PortMappingConfig::None
        },
        &mut bb,
    )
    .await
    .expect("Failed to perform basic connection setup");

    // Determine if we are going to make a publish or subscribe request.
    match cmd {
        // Try to hash and publish the file to the rendezvous server.
        FileYeetCommand::Pub { file_path } => {
            let file_path = std::path::Path::new(&file_path);
            let mut hasher = Sha256::new();
            let mut reader = tokio::io::BufReader::new(
                tokio::fs::File::open(file_path)
                    .await
                    .expect("Failed to open the file"),
            );
            let mut hash_byte_buffer = [0; 8192];
            loop {
                let n = reader
                    .read(&mut hash_byte_buffer)
                    .await
                    .expect("Failed to read from the file");
                if n == 0 {
                    break;
                }

                hasher.update(&hash_byte_buffer[..n]);
            }
            let file_size = reader
                .seek(tokio::io::SeekFrom::End(0))
                .await
                .expect("Failed to seek to the end of the file");
            let hash: HashBytes = hasher.finalize().into();
            let mut hex_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            println!(
                "{} File {} has SHA-256 hash {} and size {file_size} bytes",
                local_now_fmt(),
                file_path.display(),
                faster_hex::hex_encode(&hash, &mut hex_bytes)
                    .expect("Failed to use a valid hex buffer"),
            );

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("{} Ctrl-C detected, cancelling the publish", local_now_fmt());
                }
                () = publish_loop(endpoint, server_connection.clone(), bb, hash, file_size, file_path) => {}
            }
        }

        // Try to get the file hash from the rendezvous server and peers.
        FileYeetCommand::Sub { sha256_hex, output } => {
            let mut hash = HashBytes::default();
            if let Err(e) = faster_hex::hex_decode(sha256_hex.as_bytes(), &mut hash) {
                eprintln!("{} Failed to parse hex hash: {e}", local_now_fmt());
                return;
            };

            // Determine the output file path to use.
            let output = output.as_ref().filter(|s| !s.is_empty()).map_or_else(
                || {
                    let mut output = std::env::temp_dir();
                    let mut hex_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
                    output.push(
                        faster_hex::hex_encode(&hash, &mut hex_bytes)
                            .expect("Failed to use a valid hex buffer"),
                    );
                    output
                },
                |o| o.clone().into(),
            );

            // Request all available peers from the server.
            let mut connection_attempts = match subscribe(endpoint, &server_connection, bb, hash)
                .await
            {
                Err(e) => {
                    return eprintln!("{} Failed to subscribe to the file: {e}", local_now_fmt())
                }
                Ok(c) => c,
            };

            // Iterate through the connection attempts as they resolve and use the first successful connection.
            let peer_connection = loop {
                match connection_attempts.next().await {
                    Some(Some((c, mut b))) => {
                        println!("{} Getting file size from peer...", local_now_fmt());

                        // Read the file size from the peer.
                        let Ok(file_size) = b.recv.read_u64().await else {
                            continue;
                        };
                        let Ok(consent) = file_consent_cli(file_size, &output) else {
                            continue;
                        };
                        if consent {
                            break Some((c, b, file_size));
                        }

                        println!("{} Download cancelled", local_now_fmt());

                        // Try to let the peer know that we cancelled the download.
                        // Don't worry about the result since we are done with this peer.
                        let _ =
                            tokio::time::timeout(Duration::from_millis(200), b.send.write_u8(0))
                                .await;
                    }
                    Some(None) => continue,
                    None => break None,
                }
            };

            // If no peer connection was successful, return an error.
            let Some((_peer_connection, peer_streams, file_size)) = peer_connection else {
                return println!("Failed to connect to any available peers");
            };

            // Try to download the requested file using the peer connection.
            // Pin the future to avoid a stack overflow. <https://rust-lang.github.io/rust-clippy/master/index.html#large_futures>
            Box::pin(core::download_from_peer(
                hash,
                peer_streams,
                file_size,
                &output,
            ))
            .await
            .expect("Failed to download from peer");
        }
    }

    // Close our connection to the server. Send a goodbye to be polite.
    server_connection.close(quinn::VarInt::from_u32(0), "Goodbye!".as_bytes());

    // Try to clean up the port mapping if one was made.
    if let Some(mapping) = port_mapping {
        if let Err((e, m)) = mapping.try_drop().await {
            eprintln!(
                "{} Failed to delete the port mapping with expiration {:?} : {e}",
                local_now_fmt(),
                m.expiration()
            );
        } else {
            println!(
                "{} Successfully deleted the created port mapping",
                local_now_fmt()
            );
        }
    }
}

/// Enter a loop to listen for the server to send peer socket addresses requesting our publish.
async fn publish_loop(
    endpoint: quinn::Endpoint,
    server_connection: quinn::Connection,
    mut bb: bytes::BytesMut,
    hash: HashBytes,
    file_size: u64,
    file_path: &Path,
) {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .expect("Failed to open a bi-directional QUIC stream for a socket ping request")
        .into();

    // Format a publish request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::Publish as u16);
    bb.put(&hash[..]);
    // Send the server a publish request.
    server_streams
        .send
        .write_all(&bb)
        .await
        .expect("Failed to send a publish request to the server");
    drop(bb);

    // Close the stream after completing the publish request.
    let _ = server_streams.send.finish().await;

    // Enter a loop to listen for the server to send peer connections.
    loop {
        println!(
            "{} Waiting for the server to introduce a peer...",
            local_now_fmt()
        );

        let data_len = server_streams
            .recv
            .read_u16()
            .await
            .expect("Failed to read a u16 response from the server")
            as usize;
        if data_len == 0 {
            eprintln!("{} Server encountered and error", local_now_fmt());
            break;
        }
        if data_len > MAX_SERVER_COMMUNICATION_SIZE {
            eprintln!("{} Server response length is invalid", local_now_fmt());
            break;
        }

        let mut scratch_space = [0; MAX_SERVER_COMMUNICATION_SIZE];
        let peer_string_bytes = &mut scratch_space[..data_len];
        if let Err(e) = server_streams.recv.read_exact(peer_string_bytes).await {
            eprintln!(
                "{} Failed to read a response from the server: {e}",
                local_now_fmt()
            );
            break;
        }

        // Parse the response as a peer socket address or skip this message.
        let peer_string = match std::str::from_utf8(peer_string_bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "{} Server did not send a valid UTF-8 response: {e}",
                    local_now_fmt()
                );
                continue;
            }
        };
        let peer_address = match peer_string.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("{} Failed to parse peer address: {e}", local_now_fmt());
                continue;
            }
        };

        // Attempt to connect to the peer using UDP hole punching.
        // TODO: Use tasks to handle multiple publish requests concurrently.
        let Some((_peer_connection, peer_streams)) = core::udp_holepunch(
            core::FileYeetCommandType::Pub,
            endpoint.clone(),
            endpoint
                .local_addr()
                .expect("Could not determine our local IP"),
            peer_address,
        )
        .await
        else {
            eprintln!("{} Failed to connect to peer", local_now_fmt());
            continue;
        };

        // Prepare a reader for the file to upload.
        let reader = tokio::io::BufReader::new(
            tokio::fs::File::open(file_path)
                .await
                .expect("Failed to open the file"),
        );

        // Try to upload the file to the peer connection.
        if let Err(e) = Box::pin(core::upload_to_peer(peer_streams, file_size, reader)).await {
            eprintln!("{} Failed to upload to peer: {e}", local_now_fmt());
        }
    }

    println!("Server connection closed");
}

async fn subscribe(
    endpoint: quinn::Endpoint,
    server_connection: &quinn::Connection,
    mut bb: bytes::BytesMut,
    hash: HashBytes,
) -> anyhow::Result<
    FuturesUnordered<impl std::future::Future<Output = Option<(quinn::Connection, BiStream)>>>,
> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to open a bi-directional QUIC stream for a socket ping request: {e}"
            )
        })?
        .into();

    // Send the server a subscribe request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash[..]);
    server_streams
        .send
        .write_all(&bb)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send a subscribe request to the server: {e}"))?;

    println!(
        "{} Requesting file with hash from the server...",
        local_now_fmt()
    );

    // Determine if the server is responding with a success or failure.
    let response_count = server_streams
        .recv
        .read_u16()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read a u16 response from the server: {e}"))?;

    let mut scratch_space = [0; MAX_SERVER_COMMUNICATION_SIZE];
    let connection_attempts = FuturesUnordered::new();
    if response_count == 0 {
        eprintln!("{} No publishers available for file hash", local_now_fmt());
        return Ok(connection_attempts);
    }
    let local_address = endpoint
        .local_addr()
        .map_err(|e| anyhow::anyhow!("Could not determine our local IP: {e}"))?;

    // Parse each peer socket address.
    for _ in 0..response_count {
        let address_len = server_streams
            .recv
            .read_u16()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response from server: {e}"))?
            as usize;
        let peer_string_bytes = &mut scratch_space[..address_len];
        server_streams
            .recv
            .read_exact(peer_string_bytes)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to read a valid UTF-8 response from the server: {e}")
            })?;
        let peer_address_str = std::str::from_utf8(peer_string_bytes)
            .map_err(|e| anyhow::anyhow!("Server did not send a valid UTF-8 response: {e}"))?;
        let peer_address = match peer_address_str.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{} Failed to parse peer address {peer_address_str}: {e}",
                    local_now_fmt()
                );
                continue;
            }
        };

        // Try to connect to multiple peers concurrently with a list of connection futures.
        connection_attempts.push(core::udp_holepunch(
            core::FileYeetCommandType::Sub,
            endpoint.clone(),
            local_address,
            peer_address,
        ));
    }

    Ok(connection_attempts)
}

/// Prompt the user for consent to download a file.
fn file_consent_cli(file_size: u64, output: &Path) -> Result<bool, std::io::Error> {
    // Ensure the user consents to downloading the file.
    if output.exists() {
        print!(
            "{} Download file of size {file_size} bytes and overwrite {}? <y/N>: ",
            local_now_fmt(),
            output.display()
        );
    } else {
        print!(
            "{} Download file of size {file_size} bytes to {}? <y/N>: ",
            local_now_fmt(),
            output.display()
        );
    }
    // Ensure the prompt is printed before reading from stdin.
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Return the user's consent.
    return Ok(input.trim_start().starts_with('y') || input.trim_start().starts_with('Y'));
}
