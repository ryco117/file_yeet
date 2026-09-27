use std::sync::atomic::AtomicU64;

use file_yeet_shared::BiStream;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

use crate::core::{file::FileAccessError, peer::PEER_COMMUNICATION_BUFFER_SIZE};

/// Errors that may occur when uploading a file to a peer.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// File access encountered an error.
    #[error("File access encountered an error: {0}")]
    FileAccess(#[from] FileAccessError),

    /// File read early EOF.
    #[error("File read encountered an early EOF")]
    EarlyEof,

    /// Failed to write to the peer.
    #[error("Failed to write to the peer: {0}")]
    Write(#[from] quinn::WriteError),
}

/// Upload the requested file segment to the peer.
/// The reader will be positioned at the start of the requested segment before the upload begins.
#[tracing::instrument(skip(peer_streams, reader, byte_progress))]
pub async fn upload_to_peer(
    peer_streams: &mut BiStream,
    start_index: u64,
    upload_length: u64,
    mut reader: tokio::io::BufReader<tokio::fs::File>,
    byte_progress: Option<&AtomicU64>,
) -> Result<(), UploadError> {
    // Ensure that the file reader is at the starting index for the upload.
    reader
        .seek(std::io::SeekFrom::Start(start_index))
        .await
        .map_err(FileAccessError::Seek)?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; PEER_COMMUNICATION_BUFFER_SIZE];
    let mut bytes_sent = 0;

    // Read from the file and write to the peer.
    while bytes_sent < upload_length {
        // Read a natural amount of bytes from the file.
        let mut n = reader.read(&mut buf).await.map_err(FileAccessError::Read)?;

        if n == 0 {
            // Ensure we bail out if we reach the end of the file before expected
            // since this indicates the file has likely changed underneath us.
            return Err(UploadError::EarlyEof);
        }

        // Ensure we don't send more bytes than were requested in the range.
        let remaining = upload_length - bytes_sent;
        if n as u64 > remaining {
            // `remaining` must be able to fit in `usize` since it is less than `n: usize`.
            #[allow(clippy::cast_possible_truncation)]
            let remaining = remaining as usize;

            n = remaining;
        }

        // Write the bytes to the peer.
        peer_streams.send.write_all(&buf[..n]).await?;

        // Update the number of bytes read.
        bytes_sent += n as u64;

        // Update the caller with the number of bytes sent to the peer.
        if let Some(progress) = byte_progress.as_ref() {
            progress.store(bytes_sent, std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Gracefully close our connection after all data has been sent.
    if let Err(e) = peer_streams.send.stopped().await {
        tracing::warn!("Failed to close the peer stream gracefully: {e}");
    }

    // Let the user know that the upload is complete.
    tracing::info!("Upload complete!");
    Ok(())
}
