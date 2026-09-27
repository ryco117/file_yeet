use std::path::Path;

use file_yeet_shared::HashBytes;
use sha2::Digest as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncSeekExt as _},
    sync::RwLock,
};

use crate::core::Hasher;

/// Helper to create an output file with the desired size.
/// The work is not guaranteed to be fast.
#[tracing::instrument()]
pub async fn create_sized_file(file_size: u64, output_path: &Path) -> Result<(), std::io::Error> {
    tracing::debug!("Creating output file with desired size");
    let file = tokio::fs::File::create(output_path).await?;
    file.set_len(file_size).await?;
    Ok(())
}

/// Errors that may occur when making file access attempts.
#[derive(Debug, thiserror::Error)]
pub enum FileAccessError {
    /// Failed to open the file.
    #[error("Failed to open the file: {0}")]
    Open(std::io::Error),

    /// Failed to seek in the file.
    #[error("Failed to seek in the file: {0}")]
    Seek(std::io::Error),

    /// Failed to read from the file.
    #[error("Failed to read from the file: {0}")]
    Read(std::io::Error),

    /// Failed to write to the file.
    #[error("Failed to write to the file: {0}")]
    Write(std::io::Error),
}

/// Open a file and build a SHA-256 hasher from its current contents.
/// Returns the open file, the number of bytes hashed, and the hasher state.
/// The file read position will be after the last byte that was read into the hasher.
#[tracing::instrument(skip(progress))]
pub async fn file_size_and_hasher(
    file_path: &Path,
    progress: Option<&RwLock<f32>>,
) -> Result<(tokio::fs::File, u64, Hasher), FileAccessError> {
    tracing::debug!("Opening file and calculating hash state");
    let mut hasher = Hasher::new();
    let mut file = tokio::fs::File::open(file_path)
        .await
        .map_err(FileAccessError::Open)?;

    // Get the file size so we can report progress.
    // It also lets us set a finite size to read.
    let file_size = file
        .seek(std::io::SeekFrom::End(0))
        .await
        .map_err(FileAccessError::Seek)?;

    // Reset the reader to the start of the file.
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(FileAccessError::Seek)?;

    let size_float = file_size as f32;
    let mut hash_byte_buffer = [0; 16 * 1024];
    let mut bytes_hashed = 0;
    while bytes_hashed < file_size {
        let n = file
            .read(&mut hash_byte_buffer)
            .await
            .map_err(FileAccessError::Read)?;
        if n == 0 {
            break;
        }

        hasher.update(&hash_byte_buffer[..n]);
        bytes_hashed += n as u64;

        // Update the caller with the number of bytes read.
        if let Some(progress) = progress.as_ref() {
            *progress.write().await = bytes_hashed as f32 / size_float;
        }
    }

    // Return the number of bytes hashed.
    tracing::debug!("Hashed {bytes_hashed} bytes");
    Ok((file, bytes_hashed, hasher))
}

/// Get a file's size and its SHA-256 hash.
#[tracing::instrument(skip(progress))]
pub async fn file_size_and_hash(
    file_path: &Path,
    progress: Option<&RwLock<f32>>,
) -> Result<(u64, HashBytes), FileAccessError> {
    let (_, size, hasher) = Box::pin(file_size_and_hasher(file_path, progress)).await?;
    let hash = HashBytes::new(hasher.finalize().into());

    tracing::debug!("Calculated hash for file: {hash:#}");
    Ok((size, hash))
}
