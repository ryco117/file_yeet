use std::{net::SocketAddr, num::NonZeroU16};

use file_yeet_shared::HashBytes;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::PublishersRef;

/// Accept admin TCP connections on localhost and spawn a task for each one.
#[tracing::instrument(skip_all)]
pub async fn server_loop(
    admin_port: NonZeroU16,
    publishers: PublishersRef,
    endpoint: quinn::Endpoint,
    cancellation_token: CancellationToken,
    task_master: TaskTracker,
) {
    let server_start = std::time::Instant::now();

    let admin_addr = SocketAddr::from(([127, 0, 0, 1], admin_port.get()));
    let listener = TcpListener::bind(admin_addr)
        .await
        .expect("Failed to bind admin server");
    tracing::info!("Admin server listening on {admin_addr}");
    loop {
        tokio::select! {
            () = cancellation_token.cancelled() => break,
            result = listener.accept() => {
                let (stream, addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("Admin server failed to accept connection: {e}");
                        break;
                    }
                };

                // Guard against accepting connections that arrive just as shutdown begins.
                if cancellation_token.is_cancelled() {
                    break;
                }

                tracing::debug!("Admin connection from {addr}");
                let publishers = publishers.clone();
                let endpoint = endpoint.clone();
                let cancel = cancellation_token.clone();
                task_master.spawn(async move {
                    tokio::select! {
                        () = cancel.cancelled() => {}
                        () = handle_admin_connection(stream, publishers, endpoint, server_start) => {}
                    }
                });
            }
        }
    }
}

/// Handle one admin TCP connection using a simple line-based text protocol.
///
/// Supported commands: `connections`, `hashes`, `help`.
/// The connection is closed on EOF or a write error.
/// Input is read into a fixed-size stack buffer — no client-controlled allocation.
#[tracing::instrument(skip_all)]
async fn handle_admin_connection(
    stream: TcpStream,
    publishers: PublishersRef,
    endpoint: quinn::Endpoint,
    server_start: std::time::Instant,
) {
    // The maximum byte length accepted for a single admin command line (excluding line endings).
    const MAX_ADMIN_CMD_LEN: usize = 64;

    let (mut read_half, mut write_half) = stream.into_split();

    // Fixed-size receive buffer: room for the max command plus CR+LF.
    let mut buf = [0u8; MAX_ADMIN_CMD_LEN + 2];
    let mut filled = 0usize;

    if write_half
        .write_all(b"file_yeet admin server. Type 'help' for available commands.\n")
        .await
        .is_err()
    {
        return;
    }

    loop {
        // Read more bytes into the unfilled portion of the buffer.
        let n = match read_half.read(&mut buf[filled..]).await {
            Ok(0) | Err(_) => return, // EOF or read error
            Ok(n) => n,
        };
        filled += n;

        // Process all complete lines in the buffer.
        while let Some(nl) = buf[..filled].iter().position(|&b| b == b'\n') {
            // Trim the trailing newline and any CR.
            let raw = &buf[..nl];
            let cmd = std::str::from_utf8(raw).map_or("", |s| s.trim_end_matches('\r').trim());

            let response: std::borrow::Cow<'static, str> = match cmd {
                "connections" => {
                    format!("Active connections: {}\n", endpoint.open_connections()).into()
                }
                "hashes" => {
                    // Snapshot under the lock, then release before writing.
                    let snapshot: Vec<(HashBytes, usize)> = {
                        let lock = publishers.read().await;
                        lock.iter().map(|(h, m)| (*h, m.len())).collect()
                    };
                    if snapshot.is_empty() {
                        "No hashes currently being published\n".into()
                    } else {
                        let mut resp = String::new();
                        for (hash, count) in snapshot {
                            use std::fmt::Write as _;
                            let _ = writeln!(
                                resp,
                                "{hash} ({count} publisher{}",
                                if count == 1 { "" } else { "s" }
                            );
                        }
                        resp.into()
                    }
                }
                "uptime" => {
                    let uptime_seconds = server_start.elapsed().as_secs();
                    format!(
                        "Server uptime: {} days, {} hours, {} minutes, {} seconds\n",
                        uptime_seconds / 86400,
                        (uptime_seconds % 86400) / 3600,
                        (uptime_seconds % 3600) / 60,
                        uptime_seconds % 60
                    )
                    .into()
                }
                "help" => concat!(
                    "Admin commands:\n",
                    "  connections  Show the number of active QUIC connections\n",
                    "  hashes       List file hashes currently being published\n",
                    "  uptime       Show the server uptime\n",
                    "  help         Show this help message\n",
                )
                .into(),
                _ => "Unknown command. Type 'help' for available commands.\n".into(),
            };

            if let Err(e) = write_half.write_all(response.as_bytes()).await {
                tracing::error!("Failed to write to admin client: {e}");
                return;
            }

            // Shift remaining bytes to the front of the buffer.
            buf.copy_within(nl + 1..filled, 0);
            filled -= nl + 1;
        }

        // If the buffer is full with no newline, the command is too long — reject and reset.
        if filled == buf.len() {
            if let Err(e) = write_half.write_all(b"Command too long\n").await {
                tracing::error!("Failed to write to admin client: {e}");
                break;
            }
            filled = 0;
        }
    }
}
