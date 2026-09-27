use std::{path::Path, sync::atomic::AtomicU64};

use file_yeet_shared::{BiStream, HashBytes, GOODBYE_CODE};
use sha2::Digest as _;
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};

use crate::core::{file::FileAccessError, peer::PEER_COMMUNICATION_BUFFER_SIZE, Hasher};

/// The range of bytes to download and an optional starting hash state.
/// If no hasher is provided, no hash will be computed or verified as the download occurs.
pub struct DownloadOffsetState {
    pub range: std::ops::Range<u64>,
    pub hasher: Option<(Hasher, Option<HashBytes>)>,
}
impl DownloadOffsetState {
    /// Create a new download offset state with a specific range and optional hasher.
    pub fn new(range: std::ops::Range<u64>, hasher: Option<(Hasher, Option<HashBytes>)>) -> Self {
        Self { range, hasher }
    }
}

/// Errors that may occur when downloading a file from a peer.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("A file access error occurred: {0}")]
    FileAccess(#[from] FileAccessError),

    #[error("An error occurred reading from peer: {0}")]
    QuicRead(#[from] quinn::ReadError),

    #[error("An error occurred sending to peer: {0}")]
    QuicWrite(#[from] quinn::WriteError),

    #[error("Unexpected end of file")]
    UnexpectedEof,

    #[error("The downloaded file hash does not match the expected hash")]
    HashMismatch,
}
impl DownloadError {
    /// Return whether the error is recoverable and the download can be retried.
    pub fn is_recoverable(&self) -> bool {
        match self {
            DownloadError::FileAccess(_)
            | DownloadError::QuicRead(_)
            | DownloadError::QuicWrite(_)
            | DownloadError::UnexpectedEof => true,

            DownloadError::HashMismatch => false,
        }
    }
}

/// Download a slice of a file from the peer. Initiates the download by specifying the range of bytes to download.
/// The caller is responsible for opening the file but this function will seek to the specified starting offset before writing.
/// The caller may optionally provide an `AtomicU64` to track the number of bytes downloaded so far.
/// If a hasher is provided in the `file_offsets`, the downloaded data will update the hash state.
/// Furthermore, if an expected hash is provided in the `file_offsets` then the final hash will be verified against it and an error will be returned if there is a mismatch.
#[tracing::instrument(skip(peer_streams, file, file_offsets, byte_progress))]
pub async fn download_partial_from_peer(
    peer_streams: &mut BiStream,
    file: &mut tokio::fs::File,
    file_offsets: DownloadOffsetState,
    byte_progress: Option<&AtomicU64>,
) -> Result<(), DownloadError> {
    // Determine the range of bytes to download and an existing hasher state.
    let DownloadOffsetState { range, mut hasher } = file_offsets;
    tracing::debug!("Downloading partial file from peer: Bytes {range:?}");

    // Seek to the requested offset.
    file.seek(std::io::SeekFrom::Start(range.start))
        .await
        .map_err(FileAccessError::Seek)?;

    // Get the number of bytes to download.
    let download_size = range.end.saturating_sub(range.start);

    // Let the peer know which range we want to download using this QUIC stream.
    let mut bb = [0u8; size_of::<u64>() * 2];
    bb[..size_of::<u64>()].copy_from_slice(range.start.to_be_bytes().as_slice());
    bb[size_of::<u64>()..].copy_from_slice(download_size.to_be_bytes().as_slice());
    peer_streams.send.write_all(&bb).await?;

    // Create a scratch space for reading data from the stream.
    let mut buf = [0; PEER_COMMUNICATION_BUFFER_SIZE];

    // Read from the peer and write to the file.
    let mut bytes_written = 0;
    while bytes_written < download_size {
        // Read a natural amount of bytes from the peer.
        let size = peer_streams
            .recv
            .read(&mut buf)
            .await?
            .ok_or(DownloadError::UnexpectedEof)?;

        if size > 0 {
            // Ensure we don't write more bytes than were requested in the handshake.
            let size = usize::try_from(download_size - bytes_written).map_or(size, |x| x.min(size));

            // Write the bytes to the file and update the hash.
            let bb = &buf[..size];

            // Update hash if requested.
            if let Some((hasher, _)) = hasher.as_mut() {
                hasher.update(bb);
            }

            // Write the bytes to the file.
            file.write_all(bb).await.map_err(FileAccessError::Write)?;

            // Update the number of bytes written.
            let size = size as u64;
            bytes_written += size;

            // Update the caller with the number of bytes written.
            if let Some(progress) = byte_progress {
                progress.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    // No more data is required from this stream.
    // Let the peer know they can close their end of the stream.
    if let Err(e) = peer_streams.recv.stop(GOODBYE_CODE) {
        tracing::debug!("Failed to close the peer stream gracefully: {e}");
    }

    if let Some((hasher, Some(expected_hash))) = hasher.take() {
        // Ensure the file hash is correct.
        if expected_hash == hasher.finalize().into() {
            tracing::info!("Validated download hash");
        } else {
            return Err(DownloadError::HashMismatch);
        }
    }

    Ok(())
}

/// Reject a download request gracefully by sending a null download range to the peer.
#[tracing::instrument(skip_all)]
pub async fn reject_download_request(peer_streams: &mut BiStream) -> Result<(), DownloadError> {
    // Send a null download range to the peer to reject the download gracefully.
    let bytes = [0u8; size_of::<u64>() * 2];
    peer_streams.send.write_all(&bytes).await?;

    Ok(())
}

/// Download a file from the peer to the specified file path.
#[tracing::instrument(skip(peer_streams, byte_progress))]
pub async fn download_from_peer(
    expected_hash: HashBytes,
    peer_streams: &mut BiStream,
    file_size: u64,
    output_path: &Path,
    byte_progress: Option<&AtomicU64>,
) -> Result<(), DownloadError> {
    tracing::info!("Downloading entire file from peer...");

    // Specify that we want to download the entire file.
    let file_offsets =
        DownloadOffsetState::new(0..file_size, Some((Hasher::default(), Some(expected_hash))));

    // Open the file for writing, truncating if the file already exists.
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output_path)
        .await
        .map_err(FileAccessError::Open)?;

    Box::pin(download_partial_from_peer(
        peer_streams,
        &mut file,
        file_offsets,
        byte_progress,
    ))
    .await?;

    // Let the user know that the download is complete.
    tracing::info!("Download complete");
    Ok(())
}
