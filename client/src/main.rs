use std::{io::Write as _, num::NonZeroU16, path::Path};

use file_yeet_shared::{
    local_now_fmt, BiStream, HashBytes, GOODBYE_CODE, GOODBYE_MESSAGE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use iced::Application;
use tokio_util::sync::CancellationToken;

use crate::core::{humanize_bytes, FileYeetCommandType, PreparedConnection};

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
        // Run the GUI. Specify that the application should override the default exit behavior.
        if let Err(e) = gui::AppState::run(iced::Settings {
            window: iced::window::Settings {
                exit_on_close_request: false,
                ..iced::window::Settings::default()
            },
            flags: (args.server_address, args.port_override, args.nat_map),
            ..iced::Settings::default()
        }) {
            eprintln!("{} GUI failed to run: {e}", local_now_fmt());
        }

        return;
    };

    // Create a buffer for sending and receiving data within the payload size for `file_yeet`.
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    // Connect to the public file_yeet_server.
    let prepared_connection = core::prepare_server_connection(
        args.server_address.as_deref(),
        args.server_port,
        args.gateway.as_deref(),
        if let Some(g) = args.port_override {
            // Use the provided port override.
            core::PortMappingConfig::PortForwarding(g)
        } else if args.nat_map {
            // Try to create a new port mapping using NAT-PMP or PCP.
            core::PortMappingConfig::PcpNatPmp(None)
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
            if let Err(e) = publish_command(&prepared_connection, bb, file_path).await {
                eprintln!("{} Failed to publish the file: {e}", local_now_fmt());
            }
        }

        // Try to get the file hash from the rendezvous server and peers.
        FileYeetCommand::Sub { sha256_hex, output } => {
            if let Err(e) = subscribe_command(&prepared_connection, bb, sha256_hex, output).await {
                eprintln!("{} Failed to download the file: {e}", local_now_fmt());
            }
        }
    }

    // Close our connection to the server. Send a goodbye to be polite.
    prepared_connection
        .endpoint
        .close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

    // Try to clean up the port mapping if one was made.
    if let Some(mapping) = prepared_connection.port_mapping {
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

/// Handle the CLI command to publish a file.
async fn publish_command(
    prepared_connection: &PreparedConnection,
    bb: bytes::BytesMut,
    file_path: String,
) -> anyhow::Result<()> {
    let file_path = std::path::Path::new(&file_path);
    let (file_size, hash) = match core::file_size_and_hash(file_path, None).await {
        Ok(t) => t,
        Err(e) => anyhow::bail!("Failed to hash file: {e}"),
    };
    let mut hex_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
    println!(
        "{} File {} has SHA-256 hash {} and size {} bytes",
        local_now_fmt(),
        file_path.display(),
        faster_hex::hex_encode(&hash, &mut hex_bytes).expect("Failed to use a valid hex buffer"),
        humanize_bytes(file_size),
    );

    let core::PreparedConnection {
        endpoint,
        server_connection,
        ..
    } = prepared_connection;

    // Allow the publish loop to be cancelled by a Ctrl-C signal.
    let cancellation_token = CancellationToken::new();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("{} Ctrl-C detected, cancelling the publish", local_now_fmt());
            cancellation_token.cancel();
        }
        r = publish_loop(endpoint, server_connection, bb, hash, file_size, file_path, cancellation_token.clone()) => return r
    }

    Ok(())
}

/// Handle the CLI command to subscribe to a file.
async fn subscribe_command(
    prepared_connection: &PreparedConnection,
    mut bb: bytes::BytesMut,
    sha256_hex: String,
    output_path: Option<String>,
) -> anyhow::Result<()> {
    let mut hash = HashBytes::default();
    if let Err(e) = faster_hex::hex_decode(sha256_hex.as_bytes(), &mut hash) {
        anyhow::bail!("Failed to parse hex hash: {e}");
    };

    // Determine the output file path to use.
    let output = output_path.as_ref().filter(|s| !s.is_empty()).map_or_else(
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

    let core::PreparedConnection {
        endpoint,
        server_connection,
        ..
    } = prepared_connection;

    // Request all available peers from the server.
    let mut peers = match core::subscribe(server_connection, &mut bb, hash).await {
        Err(e) => anyhow::bail!("Failed to subscribe to the file: {e}"),
        Ok(c) => c,
    };
    bb.clear();

    // If no peers are available, quickly return.
    if peers.is_empty() {
        anyhow::bail!("No peers are available for the file");
    }

    // Try to connect to multiple peers concurrently with a list of connection futures.
    let mut connection_attempts = FuturesUnordered::new();
    for (peer_address, file_size) in peers.drain(..) {
        connection_attempts.push(async move {
            (
                core::udp_holepunch(
                    FileYeetCommandType::Sub,
                    hash,
                    endpoint.clone(),
                    peer_address,
                )
                .await,
                file_size,
            )
        });
    }

    // Iterate through the connection attempts as they resolve and use the first successful connection.
    let peer_connection = loop {
        match connection_attempts.next().await {
            Some((Some((c, b)), file_size)) => {
                let consent =
                    file_consent_cli(file_size, &output).expect("Failed to read user input");
                if consent {
                    break Some((c, b, file_size));
                }

                println!("{} Download cancelled", local_now_fmt());

                // Close the connection since this command can't have multiple connections to a peer.
                c.close(GOODBYE_CODE, &[]);
            }
            Some((None, _)) => continue,
            None => break None,
        }
    };

    // Try to get a successful peer connection.
    if let Some((peer_connection, mut peer_streams, file_size)) = peer_connection {
        // Try to download the requested file using the peer connection.
        // Pin the future to avoid a stack overflow. <https://rust-lang.github.io/rust-clippy/master/index.html#large_futures>
        if let Err(e) = Box::pin(core::download_from_peer(
            hash,
            &mut peer_streams,
            file_size,
            &output,
            None,
        ))
        .await
        {
            anyhow::bail!("Failed to download from peer: {e}");
        }

        peer_connection.close(GOODBYE_CODE, "Thanks for sharing".as_bytes());
    } else {
        anyhow::bail!("Failed to connect to any available peers");
    };

    Ok(())
}

/// Enter a loop to listen for the server to send peer socket addresses requesting our publish.
async fn publish_loop(
    endpoint: &quinn::Endpoint,
    server_connection: &quinn::Connection,
    bb: bytes::BytesMut,
    hash: HashBytes,
    file_size: u64,
    file_path: &Path,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream =
        crate::core::publish(server_connection, bb, hash, file_size).await?;

    // Enter a loop to listen for the server to send peer connections.
    loop {
        println!(
            "{} Waiting for the server to introduce a peer...",
            local_now_fmt()
        );

        // Await the server to send a peer connection.
        let Ok(peer_address) = crate::core::read_subscribing_peer(&mut server_streams.recv).await
        else {
            eprintln!("{} Failed to read the server's response", local_now_fmt());
            break;
        };

        let cancellation_token = cancellation_token.clone();
        let endpoint = endpoint.clone();
        let file_path = file_path.to_path_buf();
        tokio::task::spawn(async move {
            tokio::select! {
                // Ensure the publish tasks are cancellable.
                () = cancellation_token.cancelled() => {}

                // Try to connect to the peer and upload the file.
                () = async move {
                    // Attempt to connect to the peer using UDP hole punching.
                    let Some((_peer_connection, mut peer_streams)) = core::udp_holepunch(
                        FileYeetCommandType::Pub,
                        hash,
                        endpoint,
                        peer_address,
                    )
                    .await
                    else {
                        eprintln!("{} Failed to connect to peer", local_now_fmt());
                        return;
                    };

                    let file = match tokio::fs::File::open(file_path).await {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("{} Failed to open the file: {e}", local_now_fmt());
                            return;
                        }
                    };

                    // Prepare a reader for the file to upload.
                    let reader = tokio::io::BufReader::new(file);

                    // Try to upload the file to the peer connection.
                    if let Err(e) = Box::pin(core::upload_to_peer(&mut peer_streams, file_size, reader, None)).await {
                        eprintln!("{} Failed to upload to peer: {e}", local_now_fmt());
                    }
                } => {}
            }
        });
    }

    Ok(println!("{} Server connection closed", local_now_fmt()))
}

/// Prompt the user for consent to download a file.
fn file_consent_cli(file_size: u64, output: &Path) -> Result<bool, std::io::Error> {
    let file_size = humanize_bytes(file_size);

    // Ensure the user consents to downloading the file.
    if output.exists() {
        print!(
            "{} Download file of size {file_size} and overwrite {}? <y/N>: ",
            local_now_fmt(),
            output.display()
        );
    } else {
        print!(
            "{} Download file of size {file_size} to {}? <y/N>: ",
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
