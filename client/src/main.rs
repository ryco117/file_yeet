use std::{io::Write as _, num::NonZeroU16, path::Path};

use file_yeet_shared::{
    BiStream, HashBytes, GOODBYE_CODE, GOODBYE_MESSAGE, MAX_SERVER_COMMUNICATION_SIZE,
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::core::{humanize_bytes, FileYeetCommandType, PreparedConnection};

mod core;
mod gui;
#[cfg(all(target_os = "windows", not(debug_assertions)))]
mod win_cmd;

/// The command line interface for `file_yeet_client`.
#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// The address of the rendezvous server. Either an IP address or a hostname.
    #[arg(short, long)]
    server_address: Option<String>,

    /// The server port to connect to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    server_port: NonZeroU16,

    /// Override the port seen by the server to communicate a custom external port to peers.
    /// Useful when manually port forwarding.
    /// Takes precedence over the `nat_map` option.
    #[arg(short = 'x', long)]
    external_port_override: Option<NonZeroU16>,

    /// Require the client to bind to a specific local port.
    /// Useful when manually port forwarding.
    #[arg(short, long)]
    internal_port: Option<NonZeroU16>,

    /// The IP address of local gateway to use when attempting the Port Control Protocol.
    /// If not specified, a default gateway will be searched for.
    #[arg(short, long)]
    gateway: Option<String>,

    /// When enabled the client will attempt NAT-PMP and PCP port mapping protocols.
    #[arg(short, long)]
    nat_map: bool,

    /// Enable verbose debug logging.
    #[arg(short, long)]
    verbose: bool,

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

fn main() {
    // Parse command line arguments.
    use clap::Parser as _;
    let args = Cli::parse();

    // Initialize logging.
    {
        use tracing_subscriber::prelude::*;

        let filter = if cfg!(debug_assertions) || args.verbose {
            tracing_subscriber::filter::Targets::new()
                .with_target(core::APP_TITLE, tracing::Level::DEBUG)
        } else {
            tracing_subscriber::filter::Targets::new()
                .with_target(core::APP_TITLE, tracing::Level::INFO)
        };
        let subscriber = tracing_subscriber::registry();
        if args.verbose {
            subscriber
                .with(tracing_subscriber::fmt::layer().pretty())
                .with(filter)
                .init();
        } else {
            subscriber
                .with(tracing_subscriber::fmt::layer().compact())
                .with(filter)
                .init();
        }
    }

    // If no subcommand was provided, run the GUI.
    let Some(cmd) = args.cmd else {
        // If Windows, ensure we aren't displaying an unwanted console window.
        #[cfg(all(target_os = "windows", not(debug_assertions)))]
        if !args.verbose {
            tracing::info!("Freeing Windows console for GUI");
            win_cmd::free_allocated_console();
        }

        // Run the GUI. Specify that the application should override the default exit behavior.
        if let Err(e) = iced::application(
            gui::AppState::title(),
            gui::AppState::update,
            gui::AppState::view,
        )
        .subscription(gui::AppState::subscription)
        .theme(gui::AppState::theme)
        .font(gui::EMOJI_FONT)
        .window(iced::window::Settings {
            min_size: Some(iced::Size::new(850., 300.)),
            exit_on_close_request: false,
            ..Default::default()
        })
        .run_with(|| gui::AppState::new(args))
        {
            tracing::error!("GUI failed to run: {e}");
        }

        tracing::info!("Closing GUI...");
        return;
    };

    // Create a buffer for sending and receiving data within the payload size for `file_yeet`.
    let mut bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

    // Begin an asynchronous runtime outside of the GUI event loop to handle the command line request.
    let async_runtime = tokio::runtime::Runtime::new().unwrap();
    async_runtime.block_on(async move {
        // Connect to the specified file_yeet server.
        let prepared_connection = core::prepare_server_connection(
            args.server_address.as_deref(),
            args.server_port,
            args.gateway.as_deref(),
            args.internal_port,
            if let Some(g) = args.external_port_override {
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

        let mut task_master = TaskTracker::new();
        let cancellation_token = CancellationToken::new();

        if let Some(port_mapping) = &prepared_connection.port_mapping {
            let mut port_mapping = port_mapping.clone();
            let cancellation_token = cancellation_token.clone();

            // Spawn a task to routinely renew the port mapping.
            task_master.spawn(async move {
                let mut last_lifetime = port_mapping.lifetime() as u64;
                let mut interval = core::new_renewal_interval(last_lifetime).await;

                loop {
                    // Ensure the waiting period is cancellable.
                    tokio::select! {
                        () = cancellation_token.cancelled() => break,
                        _ = interval.tick() => {}
                    }

                    // Attempt a port mapping renewal.
                    match core::renew_port_mapping(&mut port_mapping).await {
                        Err(e) => tracing::warn!("Failed to renew port mapping: {e}"),
                        Ok(changed) if changed => {
                            let lifetime = port_mapping.lifetime() as u64;
                            if lifetime != last_lifetime {
                                last_lifetime = lifetime;
                                interval = core::new_renewal_interval(lifetime).await;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }

        // Create a background task to handle incoming peer connections.
        task_master.spawn(core::ConnectionsManager::manage_incoming_loop(
            prepared_connection.endpoint.clone(),
        ));

        // Determine if we are going to make a publish or subscribe request.
        match cmd {
            // Try to hash and publish the file to the rendezvous server.
            FileYeetCommand::Pub { file_path } => {
                if let Err(e) = publish_command(
                    &prepared_connection,
                    bb,
                    file_path,
                    &mut task_master,
                    cancellation_token,
                )
                .await
                {
                    tracing::error!("Failed to publish the file: {e}");
                }
            }

            // Try to get the file hash from the rendezvous server and peers.
            FileYeetCommand::Sub { sha256_hex, output } => {
                if let Err(e) =
                    subscribe_command(&prepared_connection, bb, sha256_hex, output).await
                {
                    tracing::error!("Failed to download the file: {e}");
                }

                // Download has completed, cancel any background tasks.
                cancellation_token.cancel();
            }
        }

        // Close our connection to the server. Send a goodbye to be polite.
        prepared_connection
            .endpoint
            .close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

        // Close the tracker after no more tasks should be spawned.
        task_master.close();

        // Wait for the server's tasks to finish.
        task_master.wait().await;

        // Try to clean up the port mapping if one was made.
        if let Some(mapping) = prepared_connection.port_mapping {
            if let Err((e, m)) = mapping.try_drop().await {
                tracing::warn!(
                    "Failed to delete the port mapping with expiration {} : {e}",
                    core::instant_to_datetime_string(m.expiration()),
                );
            } else {
                tracing::info!("Successfully deleted the port mapping");
            }
        }
    });
}

/// Handle the CLI command to publish a file.
#[tracing::instrument(skip_all)]
async fn publish_command(
    prepared_connection: &PreparedConnection,
    bb: bytes::BytesMut,
    file_path: String,
    task_master: &mut TaskTracker,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    let file_path = std::path::Path::new(&file_path);
    let (file_size, hash) = match core::file_size_and_hash(file_path, None).await {
        Ok(t) => t,
        Err(e) => anyhow::bail!("Failed to hash file: {e}"),
    };
    tracing::info!(
        "File {} has SHA-256 hash {} and size {} bytes",
        file_path.display(),
        &hash,
        humanize_bytes(file_size),
    );

    let core::PreparedConnection {
        endpoint,
        server_connection,
        ..
    } = prepared_connection;

    // Allow the publish loop to be cancelled by a Ctrl-C signal.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C detected, cancelling the publish");
            cancellation_token.cancel();
        }
        r = publish_loop(endpoint, server_connection, bb, hash, file_size, file_path, cancellation_token.clone(), task_master) => return r
    }

    Ok(())
}

/// Handle the CLI command to subscribe to a file.
#[tracing::instrument(skip_all)]
async fn subscribe_command(
    prepared_connection: &PreparedConnection,
    mut bb: bytes::BytesMut,
    sha256_hex: String,
    output_path: Option<String>,
) -> anyhow::Result<()> {
    let mut hash = HashBytes::default();
    if let Err(e) = faster_hex::hex_decode(sha256_hex.as_bytes(), &mut hash.bytes) {
        anyhow::bail!("Failed to parse hex hash: {e}");
    };

    // Determine the output file path to use.
    let output = output_path.as_ref().filter(|s| !s.is_empty()).map_or_else(
        || {
            let mut output = std::env::temp_dir();
            let mut hex_bytes = [0; 2 * file_yeet_shared::HASH_BYTE_COUNT];
            output.push(
                faster_hex::hex_encode(&hash.bytes, &mut hex_bytes)
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
    let mut peers = match core::subscribe(server_connection, &mut bb, hash, None).await {
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
        let local_endpoint = endpoint.clone();
        connection_attempts.push(async move {
            core::udp_holepunch(FileYeetCommandType::Sub, hash, local_endpoint, peer_address)
                .await
                .map(|(c, b)| (c, b, file_size))
        });
    }

    // Iterate through the connection attempts as they resolve.
    // Allow the user to accept or reject the download from each peer until the first accepted connection.
    let peer_connection = loop {
        match connection_attempts.next().await {
            Some(Some((c, b, file_size))) => {
                let consent =
                    file_consent_cli(file_size, &output).expect("Failed to read user input");
                if consent {
                    break Some((c, b, file_size));
                }

                // Close the connection because we won't download from this peer.
                tracing::info!("Download rejected");
                c.close(GOODBYE_CODE, &[]);
            }

            // If the connection attempt failed, skip the peer.
            Some(None) => {}

            // If no more connections are available, break the loop.
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
            &mut bb,
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
#[tracing::instrument(skip_all)]
async fn publish_loop(
    endpoint: &quinn::Endpoint,
    server_connection: &quinn::Connection,
    bb: bytes::BytesMut,
    hash: HashBytes,
    file_size: u64,
    file_path: &Path,
    cancellation_token: CancellationToken,
    task_master: &mut TaskTracker,
) -> anyhow::Result<()> {
    // Create a bi-directional stream to the server.
    let mut server_streams: BiStream =
        crate::core::publish(server_connection, bb, hash, file_size).await?;

    // Enter a loop to listen for the server to send peer addresses.
    loop {
        tracing::info!("Waiting for the server to introduce a peer...");

        // Await the server to send a peer connection.
        let peer_address =
            match crate::core::read_subscribing_peer(&mut server_streams.recv, None).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Failed to read the server's response: {e}");
                    break;
                }
            };

        let cancellation_token = cancellation_token.clone();
        let endpoint = endpoint.clone();
        let file_path = file_path.to_path_buf();
        task_master.spawn(async move {
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
                        tracing::warn!("Failed to connect to peer");
                        return;
                    };

                    let file = match tokio::fs::File::open(file_path).await {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::error!("Failed to open the file to publish: {e}");
                            return;
                        }
                    };

                    // Prepare a reader for the file to upload.
                    let reader = tokio::io::BufReader::new(file);

                    // Try to upload the file to the peer connection.
                    if let Err(e) = Box::pin(core::upload_to_peer(&mut peer_streams, file_size, reader, None)).await {
                        tracing::warn!("Failed to upload to peer: {e}");
                    }
                } => {}
            }
        });
    }

    tracing::info!("Server connection closed");
    Ok(())
}

/// Prompt the user for consent to download a file.
fn file_consent_cli(file_size: u64, output: &Path) -> Result<bool, std::io::Error> {
    let file_size = humanize_bytes(file_size);

    // Ensure the user consents to downloading the file.
    if output.exists() {
        print!(
            "!! Download file of size {file_size} and overwrite {}? <y/N>: ",
            output.display()
        );
    } else {
        print!(
            "!! Download file of size {file_size} to {}? <y/N>: ",
            output.display()
        );
    }
    // Ensure the prompt is printed before reading from stdin.
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    // Return the user's consent.
    Ok(input.trim_start().starts_with('y') || input.trim_start().starts_with('Y'))
}
