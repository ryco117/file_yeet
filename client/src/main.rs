use std::{io::Write as _, num::NonZeroU16, path::Path, sync::Arc};

use file_yeet_shared::{
    BiStream, HashBytes, GOODBYE_CODE, GOODBYE_MESSAGE, MAX_SERVER_COMMUNICATION_SIZE,
};
use futures_util::{stream::FuturesUnordered, StreamExt};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::core::{humanize_bytes, FileYeetCommandType, PreparedConnection, HASH_EXT_REGEX};

mod core;
mod gui;
mod logging;
mod settings;
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
    #[arg(short = 'p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
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

    /// Log to stdout instead of trying to log to a file.
    #[arg(short, long)]
    log_to_stdout: bool,

    #[command(subcommand)]
    cmd: Option<FileYeetCommand>,
}

/// The subcommands for `file_yeet_client`.
#[derive(clap::Subcommand)]
enum FileYeetCommand {
    /// Publish a file to the server. Peers will download from this client directly.
    Pub { file_path: String },

    /// Subscribe to a file from the server.
    Sub {
        /// The SHA-256 hash of the file to download with optional file extension, formatted `hash[:ext]`.
        /// A valid example is 3a948d839c93992627c938a174859d837195f837367a68385619357849a6547d:png
        hash_ext: String,

        /// Optional destination file path. Defaults to the current directory with the hash as the name [with the chosen extension].
        output: Option<String>,
    },
}

fn main() {
    use clap::Parser as _;

    // Warn the user if this is a debug build.
    #[cfg(debug_assertions)]
    println!("Debug build: YOUR & PEER PUBLIC IP ADDRESS may be included in your logs!");

    // Parse command line arguments.
    let args = Cli::parse();

    // Initialize logging based on the command line arguments.
    let _guard = logging::init(&args);

    // If no subcommand was provided, run the GUI.
    let Some(cmd) = args.cmd else {
        // If Windows, ensure we aren't displaying an unwanted console window.
        // NOTE: The "real" solution is to use `windows_subsystem = "windows"`,
        //       but this makes even `--help` not possible, among other undesirable behavior.
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
            FileYeetCommand::Sub { hash_ext, output } => {
                if let Err(e) = subscribe_command(
                    &prepared_connection,
                    bb,
                    hash_ext,
                    output,
                    &mut task_master,
                    cancellation_token.clone(),
                )
                .await
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
    let display_path = file_path.display();
    let file_bytes = humanize_bytes(file_size);
    if let Some(ext) = file_path.extension().and_then(std::ffi::OsStr::to_str) {
        tracing::info!(
            "File {display_path} has SHA-256 hash {hash}:{ext} and size {file_bytes} bytes",
        );
    } else {
        tracing::info!("File {display_path} has SHA-256 hash {hash} and size {file_bytes} bytes");
    }

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
    hash_ext: String,
    output_path: Option<String>,
    task_master: &mut TaskTracker,
    cancellation_token: CancellationToken,
) -> anyhow::Result<()> {
    // Parse the hash and optional extension with regex.
    let (hash_hex, ext) = match HASH_EXT_REGEX.captures(&hash_ext) {
        Some(c) => (
            c.get(1)
                .ok_or_else(|| anyhow::anyhow!("File hash not given in valid format"))?
                .as_str(),
            c.get(2).map(|m| m.as_str()),
        ),
        None => anyhow::bail!("Failed to parse the hash and optional extension"),
    };

    let mut hash = HashBytes::default();
    if let Err(e) = faster_hex::hex_decode(hash_hex.as_bytes(), &mut hash.bytes) {
        anyhow::bail!("Failed to parse hex hash: {e}");
    }

    // Determine the output file path to use.
    let output = {
        let mut output = output_path
            .as_ref()
            .filter(|s| !s.trim().is_empty())
            .map_or_else(
                || std::path::PathBuf::from(hash_hex),
                std::path::PathBuf::from,
            );

        // If an extension hint was provided, use it as the default extension.
        if let Some(ext) = ext {
            if output.extension().is_none() {
                //  TODO: Wait for `add_extension` to be stabilized.
                //  https://github.com/rust-lang/rust/issues/127292
                output.set_extension(ext);
            }
        }
        output
    };

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
            Some(Some((c, mut b, file_size))) => {
                let consent =
                    file_consent_cli(file_size, &output).expect("Failed to read user input");
                if consent {
                    break Some((c, b, file_size));
                }

                // Try to gracefully reject the download in the background.
                task_master.spawn(async move {
                    // Reject the download gracefully.
                    if let Ok(()) = core::reject_download_request(&mut b).await {
                        // Close the connection because we won't download from this peer.
                        tracing::debug!("Download rejected");
                    }
                    c.close(GOODBYE_CODE, &[]);
                });
            }

            // If the connection attempt failed, skip the peer.
            Some(None) => {}

            // If no more connections are available, break the loop.
            None => break None,
        }
    };

    // If no connections were viable or accepted, then bail.
    let Some((peer_connection, mut peer_streams, file_size)) = peer_connection else {
        anyhow::bail!("Failed to connect to any available peers");
    };

    // Create a background task to update the download progress visually.
    let progress = Arc::new(tokio::sync::RwLock::new(0));
    let progress_clone = progress.clone();
    task_master.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        let mut last_instant = interval.tick().await;
        let mut last_progress = 0;
        let empty_progress = "          ";
        let full_progress = "██████████";

        println!();
        while !cancellation_token.is_cancelled() {
            // Wait for the next interval tick and get the current time.
            let now = interval.tick().await;
            if cancellation_token.is_cancelled() {
                break;
            }

            // Estimate the download speed.
            let bytes_read = *progress.read().await;
            let speed = (bytes_read - last_progress) as f64
                / now.duration_since(last_instant).as_secs_f64();
            let human_speed = human_bytes::human_bytes(speed);

            last_instant = now;
            last_progress = bytes_read;

            // Print the current state of the download.
            #[allow(clippy::cast_possible_truncation)]
            let progress_chars = ((bytes_read * empty_progress.len() as u64) / file_size) as usize;
            println!(
                "\x1bM[{}{}] {human_speed}/s",
                &full_progress[..3 * progress_chars],
                &empty_progress[progress_chars..]
            );
        }
    });

    // Try to download the requested file using the accepted peer connection.
    // Pin the future to avoid a stack overflow. <https://rust-lang.github.io/rust-clippy/master/index.html#large_futures>
    if let Err(e) = core::download_from_peer(
        hash,
        &mut peer_streams,
        file_size,
        &output,
        Some(&progress_clone),
    )
    .await
    {
        anyhow::bail!("Failed to download from peer: {e}");
    }

    peer_connection.close(GOODBYE_CODE, "Thanks for sharing".as_bytes());

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
                    let Some((peer_connection, mut peer_streams)) = core::udp_holepunch(
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

                    // Close the connection to the peer.
                    core::ConnectionsManager::instance().remove_peer(&peer_connection.remote_address()).await;
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
