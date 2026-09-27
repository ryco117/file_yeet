use std::{
    net::SocketAddr,
    num::NonZeroUsize,
    path::Path,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use file_yeet_shared::{BiStream, HashBytes, GOODBYE_CODE};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use sha2::Digest as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::core::{
    default_transport_config, read_error_from_io, ConnectionsManager, FileAccessError,
    FileYeetCommandType, Hasher,
};

/// Define a sane number of maximum retries.
pub const MAX_PEER_CONNECTION_ATTEMPTS: NonZeroUsize = NonZeroUsize::new(10).unwrap();

/// Scratch space size in bytes for peer communication.
pub const PEER_COMMUNICATION_BUFFER_SIZE: usize = 16 * 1024;

/// Sane default timeout for peer connection attempts. Should try to connect for a longer time than listening.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Sane default timeout for listening for a peer.
pub const PEER_HOLEPUNCH_LISTEN_TIMEOUT: Duration = Duration::from_millis(1500);

/// Lazily initialized shared QUIC client configuration that skips certificate verification.
/// Used for peer-to-peer connections where we use self-signed certificates and don't want to rely on a CA.
/// # Panics
/// If the QUIC client configuration cannot be created from the Rustls client configuration.
static SKIP_CERT_VERIFICATION_CONFIG: std::sync::LazyLock<Arc<QuicClientConfig>> =
    std::sync::LazyLock::new(|| {
        let config = QuicClientConfig::try_from(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipServerCertVerification::new())
                .with_no_client_auth(),
        )
        .expect("Failed to create a QUIC client configuration");

        Arc::new(config)
    });

/// Build a QUIC client config that will skip server verification.
/// # Panics
/// If the QUIC client configuration cannot be created from the Rustls client configuration.
pub fn configure_peer_verification() -> quinn::ClientConfig {
    let mut client_config = quinn::ClientConfig::new(SKIP_CERT_VERIFICATION_CONFIG.clone());
    client_config.transport_config(default_transport_config());
    client_config
}

/// Errors that may occur when turning a peer connection into a bi-directional stream.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionIntoStreamError {
    /// Failed to establish a QUIC connection to the peer.
    #[error("Failed to establish a QUIC connection to the peer: {0}")]
    ConnectionFailed(#[from] quinn::ConnectionError),

    /// Failed to read exact bytes from the peer stream. Only occurs with `FileYeetCommandType::Pub`.
    #[error("Failed to read from the peer stream: {0}")]
    ReadExactFailed(#[from] quinn::ReadExactError),

    /// The requested hash from the peer does not match the expected hash. Only occurs with `FileYeetCommandType::Pub`.
    #[error("Requested hash from the peer does not match the expected hash")]
    HashMismatch,

    /// Failed to write to the peer stream. Only occurs with `FileYeetCommandType::Sub`.
    #[error("Failed to write to the peer stream: {0}")]
    WriteFailed(#[from] quinn::WriteError),
}

/// Try to finalize a peer connection attempt by turning it into a bi-directional stream.
#[tracing::instrument(skip_all)]
pub async fn connection_into_stream(
    connection: &quinn::Connection,
    expected_hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Result<BiStream, ConnectionIntoStreamError> {
    match cmd {
        FileYeetCommandType::Pub => {
            // Let the downloading peer initiate a bi-directional stream.
            let mut r = connection.accept_bi().await;
            if let Ok(s) = &mut r {
                let mut requested_hash = HashBytes::default();
                s.1.read_exact(&mut requested_hash.bytes).await?;

                // Ensure the requested hash matches the expected file hash.
                if requested_hash != expected_hash {
                    return Err(ConnectionIntoStreamError::HashMismatch);
                }
                tracing::debug!("New peer stream accepted");
            }
            r
        }
        FileYeetCommandType::Sub => {
            // Open a bi-directional stream to the publishing peer.
            let mut r = connection.open_bi().await;
            if let Ok(s) = &mut r {
                s.0.write_all(&expected_hash.bytes).await?;
                tracing::debug!("New peer stream opened");
            }
            r
        }
    }
    .map(std::convert::Into::into)
    .map_err(std::convert::Into::into)
}

/// Make outgoing connection attempts to a peer at the given address.
/// Logs each connection attempt and early exits on configuration errors.
#[tracing::instrument(skip_all)]
async fn connect(endpoint: quinn::Endpoint, peer_address: SocketAddr) -> Option<quinn::Connection> {
    // Set a sane number of connection attempts
    let mut connect_attempt = 0;

    // Ensure we have retries left and there isn't already a peer `Connection` to use.
    while connect_attempt < MAX_PEER_CONNECTION_ATTEMPTS.get() {
        let connect_attempt_print = connect_attempt + 1;
        if cfg!(debug_assertions) {
            tracing::debug!(
                "Connection attempt #{connect_attempt_print} to peer at {peer_address}"
            );
        } else {
            tracing::debug!("Connection attempt #{connect_attempt_print} to peer");
        }

        match endpoint.connect(peer_address, "peer") {
            Ok(connecting) => {
                let connection = match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Failed to connect to peer: {e}");
                        connect_attempt += 1;
                        continue;
                    }
                };

                if cfg!(debug_assertions) {
                    tracing::info!("Connected to peer at {peer_address}");
                } else {
                    tracing::info!("Connected to peer");
                }
                return Some(connection);
            }

            Err(e) => {
                tracing::warn!("Failed to connect to peer with unrecoverable error: {e}");
                return None;
            }
        }
    }

    tracing::debug!("Failed to connect to peer after all attempts");
    None
}

/// Attempt to connect to peer using UDP hole punching.
/// Specifically, both peers attempt outgoing connections while listening for incoming connections.
#[tracing::instrument(skip(endpoint, hash, peer_address))]
pub async fn udp_holepunch(
    cmd: FileYeetCommandType,
    hash: HashBytes,
    endpoint: quinn::Endpoint,
    peer_address: SocketAddr,
) -> Option<(quinn::Connection, BiStream)> {
    // Poll incoming connections that are handled by a background task.
    let manager = ConnectionsManager::instance();
    let listen_future = manager.await_peer(peer_address, PEER_HOLEPUNCH_LISTEN_TIMEOUT);

    // Attempt to connect to the peer's public address.
    let connect_future =
        tokio::time::timeout(PEER_CONNECT_TIMEOUT, connect(endpoint, peer_address));

    // Return the peer stream if we have one.
    let (listen_stream, connect_stream) = futures_util::join!(listen_future, connect_future);
    let connect_stream = connect_stream.ok().flatten();
    let connections =
        // TODO: It could be interesting and possible to create a more general stream negotiation.
        //       For example, if each peer sent a random nonce over each stream, and the nonces were XOR'd per stream,
        //       the result could be used to determine which stream to use (highest/lowest resulting nonce after XOR).
        match cmd {
            FileYeetCommandType::Pub => listen_stream.map(|c| (c, true)).into_iter().chain(connect_stream.map(|c| (c, false)).into_iter()),
            FileYeetCommandType::Sub => connect_stream.map(|c| (c, false)).into_iter().chain(listen_stream.map(|c| (c, true)).into_iter()),
        };

    for (connection, managed_connection) in connections {
        if let Ok(peer_streams) = connection_into_stream(&connection, hash, cmd).await {
            // Let the user know that a connection is established. A bi-directional stream is ready to use.
            tracing::info!("Peer connection established");

            // If the connection is not managed, add it to the manager.
            if !managed_connection {
                manager.accept_peer(connection.clone()).await;
            }

            return Some((connection, peer_streams));
        }
    }
    None
}

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

/// Errors that may occur when uploading a file to a peer.
#[derive(Debug, thiserror::Error)]
pub enum ReadPubRangeError {
    /// Failed to read file index data and got a `ReadError`.
    #[error("Failed to read file index data: {0}")]
    ReadFileIndexFailedWithError(quinn::ReadError),

    /// Failed to read file index data and got an `ErrorKind`.
    #[error("Failed to read file index data: {0}")]
    ReadFileIndexFailedWithKind(std::io::ErrorKind),

    /// Peer requested an invalid range, exceeds file size.
    #[error("Peer requested an invalid range, exceeds file size")]
    InvalidRange,

    /// Peer requested an invalid range, 64-bit overflow 🫠.
    #[error("Peer requested an invalid range, 64-bit overflow 🫠")]
    RangeOverflow,
}

/// Read the upload range from the peer.
/// Guarantees the start index and range length can be safely used or returns an error.
#[tracing::instrument(skip(peer_streams))]
pub async fn read_publish_range(
    peer_streams: &mut BiStream,
    file_size: u64,
) -> Result<(u64, u64), ReadPubRangeError> {
    // Read the peer's desired upload range.
    let start_index = peer_streams.recv.read_u64().await.map_err(|e| {
        read_error_from_io(
            e,
            ReadPubRangeError::ReadFileIndexFailedWithError,
            ReadPubRangeError::ReadFileIndexFailedWithKind,
        )
    })?;
    let upload_length = peer_streams.recv.read_u64().await.map_err(|e| {
        read_error_from_io(
            e,
            ReadPubRangeError::ReadFileIndexFailedWithError,
            ReadPubRangeError::ReadFileIndexFailedWithKind,
        )
    })?;

    // Sanity check the upload range.
    let end_index = match start_index.checked_add(upload_length) {
        Some(end) if end > file_size => Err(ReadPubRangeError::InvalidRange),
        None => Err(ReadPubRangeError::RangeOverflow),
        Some(end) => Ok(end),
    }?;
    tracing::info!("Peer requested upload range: Bytes {start_index}..{end_index}");

    Ok((start_index, upload_length))
}

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

/// Upload the file to the peer. Ensure they consent to the file size before sending the file.
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

/// Allow peers to connect using self-signed certificates.
/// Necessary for using the QUIC protocol with peer-to-peer connections where
/// peers likely won't have a certificate signed by a certificate authority.
#[derive(Debug)]
struct SkipServerCertVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerCertVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

/// Skip server certificate verification. Still verify signatures.
impl rustls::client::danger::ServerCertVerifier for SkipServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A peer connection representing a single request/command.
/// Peers may have multiple connections to the same peer for different requests.
#[derive(Clone, Debug)]
pub struct PeerRequestStream {
    pub connection: quinn::Connection,
    pub bistream: Arc<tokio::sync::Mutex<BiStream>>,
}
impl PeerRequestStream {
    /// Make a new `PeerConnection` from a QUIC connection and a bi-directional stream.
    #[must_use]
    pub fn new(connection: quinn::Connection, streams: BiStream) -> Self {
        Self {
            connection,
            bistream: Arc::new(tokio::sync::Mutex::new(streams)),
        }
    }
}
impl From<(quinn::Connection, BiStream)> for PeerRequestStream {
    fn from((connection, streams): (quinn::Connection, BiStream)) -> Self {
        Self::new(connection, streams)
    }
}
