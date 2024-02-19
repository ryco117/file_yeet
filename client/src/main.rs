use core::BiStream;
use std::{
    io::Write as _,
    num::NonZeroU16,
    path::{Path, PathBuf},
    time::Duration,
};

use bytes::BufMut as _;
use file_yeet_shared::{local_now_fmt, HashBytes, MAX_SERVER_COMMUNICATION_SIZE};
use futures_util::{stream::FuturesUnordered, StreamExt};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

mod core;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The address of the rendezvous server. Either an IP address or a hostname.
    #[arg(short, long)]
    server_address: Option<String>,

    /// The server port to connect to.
    #[arg(short='p', long, default_value_t = NonZeroU16::new(file_yeet_shared::DEFAULT_PORT).unwrap())]
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
    cmd: FileYeetCommand,
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

    // Create a buffer for sending and receiving data within the payload size for `file_yeet`.
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    // Connect to the public file_yeet_server.
    let (endpoint, connection, port_mapping) = core::prepare_server_connection(
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
    .await;

    // Determine if we are going to make a publish or subscribe request.
    match &args.cmd {
        // Try to hash and publish the file to the rendezvous server.
        FileYeetCommand::Pub { file_path } => {
            let file_path = std::path::Path::new(file_path);
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
                () = publish_loop(endpoint, connection.clone(), bb, hash, file_size, reader) => {}
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

            subscribe(endpoint, &connection, bb, hash, output).await;
        }
    }

    // Close our connection to the server. Send a goodbye to be polite.
    connection.close(quinn::VarInt::from_u32(0), "Goodbye!".as_bytes());

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
    mut reader: tokio::io::BufReader<tokio::fs::File>,
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

        // Try to upload the file to the peer connection.
        if let Err(e) = upload_to_peer(peer_streams, file_size, &mut reader).await {
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
    output: PathBuf,
) {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream = server_connection
        .open_bi()
        .await
        .expect("Failed to open a bi-directional QUIC stream for a socket ping request")
        .into();

    // Send the server a subscribe request.
    bb.put_u16(file_yeet_shared::ClientApiRequest::Subscribe as u16);
    bb.put(&hash[..]);
    server_streams
        .send
        .write_all(&bb)
        .await
        .expect("Failed to send a subscribe request to the server");

    println!(
        "{} Requesting file with hash from the server...",
        local_now_fmt()
    );

    // Determine if the server is responding with a success or failure.
    let response_count = server_streams
        .recv
        .read_u16()
        .await
        .expect("Failed to read a u16 response from the server");
    if response_count == 0 {
        eprintln!("{} No publishers available for file hash", local_now_fmt());
        return;
    }

    let mut scratch_space = [0; MAX_SERVER_COMMUNICATION_SIZE];
    let mut connection_attempts = FuturesUnordered::new();
    let local_address = endpoint
        .local_addr()
        .expect("Could not determine our local IP");

    // Parse each peer socket address.
    for _ in 0..response_count {
        let address_len = server_streams
            .recv
            .read_u16()
            .await
            .expect("Failed to read response from server") as usize;
        let peer_string_bytes = &mut scratch_space[..address_len];
        server_streams
            .recv
            .read_exact(peer_string_bytes)
            .await
            .expect("Failed to read a valid UTF-8 response from the server");
        let peer_address_str = std::str::from_utf8(peer_string_bytes)
            .expect("Server did not send a valid UTF-8 response");
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
                let _ = tokio::time::timeout(Duration::from_millis(200), b.send.write_u8(0)).await;
            }
            Some(None) => continue,
            None => break None,
        }
    };

    if let Some((_peer_connection, peer_streams, file_size)) = peer_connection {
        // Try to download the requested file using the peer connection.
        if let Err(e) = download_from_peer(hash, peer_streams, file_size, output).await {
            eprintln!("{} Failed to download from peer: {e}", local_now_fmt());
        }
    } else {
        eprintln!("{} Failed to connect to any peers", local_now_fmt());
    }
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

/// Errors that may occur when downloading a file from a peer.
#[derive(Debug, thiserror::Error)]
enum DownloadError {
    #[error("An I/O error occurred: {0}")]
    IoError(std::io::Error),
    #[error("The downloaded file hash does not match the expected hash")]
    HashMismatch,
}

/// Download a file from the peer. Initiates the download by consenting to the peer to receive the file.
async fn download_from_peer(
    hash: HashBytes,
    mut peer_streams: BiStream,
    file_size: u64,
    output: PathBuf,
) -> Result<(), DownloadError> {
    // Open the file for writing.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output)
        .await
        .map_err(DownloadError::IoError)?;

    // Let the peer know that we accepted the download.
    peer_streams
        .send
        .write_u8(1)
        .await
        .map_err(DownloadError::IoError)?;
    peer_streams
        .send
        .finish()
        .await
        .map_err(|e| DownloadError::IoError(e.into()))?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; core::MAX_PEER_COMMUNICATION_SIZE];
    // Read from the peer and write to the file.
    let mut bytes_written = 0;
    let mut hasher = Sha256::new();
    while bytes_written < file_size {
        // Read a natural amount of bytes from the peer.
        let size = peer_streams
            .recv
            .read(&mut buf)
            .await
            .map_err(|e| DownloadError::IoError(e.into()))?
            .ok_or(DownloadError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Peer closed the upload early",
            )))?;
        if size > 0 {
            // Write the bytes to the file and update the hash.
            let bb = &buf[..size];
            let f = file.write_all(bb);
            // Update hash while future may be pending.
            hasher.update(bb);
            f.await.map_err(DownloadError::IoError)?;

            // Update the number of bytes written.
            bytes_written += size as u64;
        }
    }

    // Ensure the file hash is correct.
    let downloaded_hash = hasher.finalize();
    if hash != Into::<HashBytes>::into(downloaded_hash) {
        return Err(DownloadError::HashMismatch);
    }

    // Let the user know that the download is complete.
    println!(
        "{} Download complete: {}",
        local_now_fmt(),
        output.display()
    );
    Ok(())
}

/// Download a file from the peer.
async fn upload_to_peer(
    mut peer_streams: BiStream,
    file_size: u64,
    reader: &mut tokio::io::BufReader<tokio::fs::File>,
) -> anyhow::Result<()> {
    // Ensure that the file reader is at the start of the file before each upload.
    reader.rewind().await.expect("Failed to rewind the file");

    // Send the file size to the peer.
    peer_streams.send.write_u64(file_size).await?;

    // Read the peer's response to the file size.
    let response = peer_streams.recv.read_u8().await?;
    if response == 0 {
        println!("{} Peer cancelled the upload", local_now_fmt());
        return Ok(());
    }

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; core::MAX_PEER_COMMUNICATION_SIZE];
    // Read from the file and write to the peer.
    loop {
        // Read a natural amount of bytes from the file.
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Write the bytes to the peer.
        peer_streams.send.write_all(&buf[..n]).await?;
    }

    // Greacefully close our connection after all data has been sent.
    if let Err(e) = peer_streams.send.finish().await {
        eprintln!(
            "{} Failed to close the peer stream gracefully: {e}",
            local_now_fmt()
        );
    }

    // Let the user know that the upload is complete.
    println!("{} Upload complete!", local_now_fmt());
    Ok(())
}
