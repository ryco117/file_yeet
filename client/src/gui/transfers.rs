use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU64,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::HashBytes;
use iced::{widget, Element};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{
    core::{
        humanize_bytes,
        intervals::{FileIntervals, RangeData},
        FileYeetCommandType,
    },
    gui::{
        remove_nonce_for_peer, text_horizontal_scrollbar, timed_tooltip, CancelOrPause,
        CreateOrExistingPublish, Message, Nonce, NonceItem, PeerRequestStream, ERROR_RED_COLOR,
    },
};

/// The rate at which transfer speed text is updated.
const TRANSFER_SPEED_UPDATE_INTERVAL: Duration = Duration::from_millis(400);

/// The recoverable state of a failed transfer.
#[derive(Clone, Debug)]
pub enum RecoverableState {
    /// The failure is likely recoverable, and the transfer will resume from existing partial progress.
    Recoverable(Option<Arc<FileIntervals<std::ops::Range<u64>>>>),

    /// The failure is not recoverable and the transfer must be restarted from scratch.
    NonRecoverable,
}

/// The result of a file download with a peer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DownloadResult {
    /// The transfer succeeded.
    #[error("Transfer succeeded")]
    Success,

    /// The transfer failed. Boolean field is `true` when the failure is recoverable.
    #[error("{0}")]
    Failure(Arc<String>, RecoverableState),

    /// The transfer was cancelled.
    #[error("Transfer cancelled")]
    Cancelled,
}

/// The result of a file upload with a peer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum UploadResult {
    /// The transfer succeeded at uploading the specified range.
    #[error("Transfer succeeded")]
    Success(std::ops::Range<u64>),

    /// The transfer failed with the specified error message.
    #[error("{0}")]
    Failure(Arc<String>),

    /// The transfer was cancelled.
    #[error("Transfer cancelled")]
    Cancelled,
}

/// The progress of a file transfer at a moment in time.
#[derive(Clone, Debug)]
pub struct TransferSnapshot {
    /// The instant at which the snapshot was taken.
    instant: Instant,

    /// The total number of bytes transferred at the last update.
    bytes_transferred: u64,

    /// A human readable string representing the current transfer speed.
    human_readable: String,
}
impl TransferSnapshot {
    /// Create a new snapshot of the transfer progress.
    #[must_use]
    pub fn new() -> Self {
        Self {
            instant: Instant::now(),
            bytes_transferred: 0,
            human_readable: String::new(),
        }
    }

    /// Update the snapshot with the current progress.
    /// Each successive call requires the `bytes_transferred` to be non-decreasing,
    /// otherwise the speed will not be updated and a warning will be logged.
    pub fn update(&mut self, bytes_transferred: u64) {
        let byte_difference = bytes_transferred.checked_sub(self.bytes_transferred);
        self.bytes_transferred = bytes_transferred;

        let now = Instant::now();
        let duration = (now - self.instant).as_secs_f64();
        self.instant = now;

        if let (Some(byte_difference), true) = (byte_difference, duration > 0.) {
            let bytes_per_second = human_bytes::human_bytes(byte_difference as f64 / duration);
            self.human_readable = format!("{bytes_per_second}/s");
        } else {
            tracing::warn!(
                "Transfer snapshot given invalid parameters: {duration}, {byte_difference:?}"
            );
        }
    }
}

/// A download from a single peer.
#[derive(Debug)]
pub struct DownloadSinglePeer {
    pub peer_string: String,
    pub peer: quinn::Connection,
    pub progress_lock: Arc<RwLock<u64>>,
}

#[derive(Debug)]
pub struct DownloadPartRange {
    /// The byte range for this part.
    pub range: std::ops::Range<u64>,

    /// An atomic lock for the progress of this range.
    pub progress_lock: Arc<RwLock<u64>>,

    /// A bool to quickly check whether the progress is complete.
    /// It should be true if and only if `progress_lock` equals the length of `range`.
    pub completed: bool,
}
impl DownloadPartRange {
    /// Create a new download part range.
    pub fn new(range: std::ops::Range<u64>) -> Self {
        Self {
            range,
            progress_lock: Arc::new(RwLock::new(0)),
            completed: false,
        }
    }

    /// Create a new download part range which is already completed.
    pub fn new_completed(range: std::ops::Range<u64>) -> Self {
        let size = range.end - range.start;
        Self {
            range,
            progress_lock: Arc::new(RwLock::new(size)),
            completed: true,
        }
    }
}
impl RangeData for DownloadPartRange {
    fn start(&self) -> u64 {
        self.range.start
    }
    fn end(&self) -> u64 {
        self.range.end
    }
}

/// A download from multiple peers.
#[derive(Debug)]
pub struct DownloadMultiPeer {
    pub peers: HashMap<usize, quinn::Connection>,
    pub peers_string: String,
    pub intervals: FileIntervals<DownloadPartRange>,
}
impl DownloadMultiPeer {
    /// Create a comma-separated string of peer addresses.
    pub fn peers_to_string(peers: &HashMap<usize, quinn::Connection>) -> String {
        peers
            .values()
            .map(|conn| conn.remote_address().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The strategy used for the download transfer.
#[derive(Debug)]
pub enum DownloadStrategy {
    SinglePeer(DownloadSinglePeer),
    MultiPeer(DownloadMultiPeer),
}

/// The state of a download transfer with a peer.
#[derive(Debug)]
pub enum DownloadState {
    /// The transfer is awaiting a connection attempt.
    Connecting,

    /// The transfer is awaiting user confirmation with a list of connected peers.
    Consent(nonempty::NonEmpty<PeerRequestStream>),

    /// The transfer is in progress.
    Transferring {
        strategy: DownloadStrategy,
        progress_animation: f32,
        snapshot: TransferSnapshot,
    },

    /// The transfer has been paused.
    Paused(Option<FileIntervals<std::ops::Range<u64>>>),

    /// Hashing the output file for resuming a partial download or verifying a result.
    //  TODO: Include a `progress_animation` field to allow for efficient reading of the hash progress.
    HashingFile(Arc<RwLock<f32>>),

    /// The transfer has completed.
    Done(DownloadResult),
}
impl DownloadState {
    /// If the progress state contains a peer connection, return it.
    /// Otherwise, return `None`.
    pub fn connections(&self) -> Box<dyn std::iter::Iterator<Item = &quinn::Connection> + '_> {
        match self {
            // Connections in these states.
            DownloadState::Consent(peers) => Box::new(peers.iter().map(|p| &p.connection)),
            DownloadState::Transferring {
                strategy: DownloadStrategy::SinglePeer(DownloadSinglePeer { peer, .. }),
                ..
            } => Box::new(std::iter::once(peer)),
            DownloadState::Transferring {
                strategy: DownloadStrategy::MultiPeer(DownloadMultiPeer { peers, .. }),
                ..
            } => Box::new(peers.values()),

            // No connections in the remaining states.
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Helper to create a new `DownloadState::Transferring {}` state.
    pub fn new_transferring(strategy: DownloadStrategy) -> Self {
        DownloadState::Transferring {
            strategy,
            progress_animation: 0.,
            snapshot: TransferSnapshot::new(),
        }
    }
}

/// The state of an upload transfer with a peer.
#[derive(Debug)]
pub enum UploadState {
    /// The transfer is in progress.
    Transferring {
        peer: quinn::Connection,
        progress_lock: Arc<RwLock<u64>>,
        progress_animation: f32,
        requested_size: Arc<RwLock<Option<NonZeroU64>>>,
        snapshot: TransferSnapshot,
    },

    /// The transfer has completed.
    Done(UploadResult),
}
impl UploadState {
    /// If the progress state contains a peer connection, return it.
    /// Otherwise, return `None`.
    pub fn connection(&self) -> Option<&quinn::Connection> {
        match self {
            // Connection in these states.
            UploadState::Transferring {
                peer: connection, ..
            } => Some(connection),

            // No connection in remaining states.
            UploadState::Done(_) => None,
        }
    }
}

/// A file transfer with a peer in any state.
#[derive(Debug)]
pub struct TransferBase {
    pub nonce: Nonce,
    pub hash: HashBytes,
    pub hash_hex: String,
    pub file_size: u64,
    pub path: Arc<PathBuf>,
    pub cancellation_token: CancellationToken,
}
pub trait Transfer {
    /// Get the base information common to all transfers.
    fn base(&self) -> &TransferBase;

    /// Update fields related to animations.
    fn update_animation(&mut self);

    /// Draw the transfer item.
    fn draw(&self, mouse_move_elapsed: &Duration) -> iced::Element<'_, Message>;
}

/// A download transfer and state information.
#[derive(Debug)]
pub struct DownloadTransfer {
    pub base: TransferBase,
    pub progress: DownloadState,
}
impl NonceItem for DownloadTransfer {
    fn nonce(&self) -> Nonce {
        self.base.nonce
    }
}
impl Transfer for DownloadTransfer {
    fn base(&self) -> &TransferBase {
        &self.base
    }
    fn update_animation(&mut self) {
        if let DownloadState::Transferring {
            strategy,
            progress_animation,
            snapshot,
            ..
        } = &mut self.progress
        {
            // Get the total bytes transferred at the current moment.
            let bytes_transferred = match strategy {
                DownloadStrategy::SinglePeer(DownloadSinglePeer { progress_lock, .. }) => {
                    *progress_lock.blocking_read()
                }
                DownloadStrategy::MultiPeer(DownloadMultiPeer { intervals, .. }) => intervals
                    .ranges()
                    .iter()
                    .fold(0u64, |acc, r| acc + *r.progress_lock.blocking_read()),
            };

            // Update the progress bar with the fraction of the file downloaded.
            *progress_animation = bytes_transferred as f32 / self.base.file_size as f32;

            // Update the transfer speed in human readable units.
            if snapshot
                .instant
                .elapsed()
                .gt(&TRANSFER_SPEED_UPDATE_INTERVAL)
            {
                snapshot.update(bytes_transferred);
            }
        }
    }
    fn draw(&self, mouse_move_elapsed: &Duration) -> iced::Element<'_, Message> {
        // Helper for creating standard buttons with tooltips.
        let tooltip_button = |text: &'static str, message: Message, tooltip: &'static str| {
            timed_tooltip(
                widget::button(widget::text(text).size(12)).on_press(message),
                tooltip,
                mouse_move_elapsed,
            )
        };

        // Try to get a transfer rate string or `None`.
        let rate = match &self.progress {
            DownloadState::Transferring { snapshot, .. } => Some(snapshot.human_readable.clone()),
            _ => None,
        };

        let progress = match &self.progress {
            DownloadState::Connecting => Element::from("Connecting..."),

            DownloadState::Consent(_) => widget::row!(
                widget::text(format!(
                    "Accept download of size {}",
                    humanize_bytes(self.base.file_size)
                ))
                .width(iced::Length::Fill),
                widget::button(widget::text("Accept").size(12))
                    .on_press(Message::AcceptDownload(self.base.nonce)),
                widget::button(widget::text("Reject").size(12))
                    .on_press(Message::RejectDownload(self.base.nonce)),
            )
            .spacing(12)
            .into(),

            DownloadState::Transferring {
                progress_animation: p,
                ..
            } => widget::row!(
                "Transferring...",
                widget::progress_bar(0.0..=1., *p).girth(24),
                tooltip_button(
                    "Pause",
                    Message::CancelOrPauseTransfer(
                        self.base.nonce,
                        FileYeetCommandType::Sub,
                        CancelOrPause::Pause,
                    ),
                    "Pause the download, it can be safely resumed",
                ),
                tooltip_button(
                    "Cancel",
                    Message::CancelOrPauseTransfer(
                        self.base.nonce,
                        FileYeetCommandType::Sub,
                        CancelOrPause::Cancel,
                    ),
                    "Cancel the download, abandoning progress",
                ),
            )
            .spacing(6)
            .align_y(iced::Alignment::Center)
            .into(),

            DownloadState::Paused(_) => widget::row!(
                "Download is paused",
                widget::space().width(iced::Length::Fill),
                tooltip_button(
                    "Resume",
                    Message::ResumePausedDownload(self.base.nonce),
                    "Attempt to resume the download",
                ),
                tooltip_button(
                    "Cancel",
                    Message::CancelOrPauseTransfer(
                        self.base.nonce,
                        FileYeetCommandType::Sub,
                        CancelOrPause::Cancel,
                    ),
                    "Cancel the download, abandoning progress",
                ),
            )
            .spacing(6)
            .into(),

            DownloadState::HashingFile(progress_lock) => widget::row!(
                "Hashing file...",
                widget::progress_bar(0.0..=1., *progress_lock.blocking_read()).girth(24),
                tooltip_button(
                    "Cancel",
                    Message::CancelOrPauseTransfer(
                        self.base.nonce,
                        FileYeetCommandType::Sub,
                        CancelOrPause::Cancel,
                    ),
                    "Cancel the download, abandoning progress",
                ),
            )
            .spacing(6)
            .into(),

            DownloadState::Done(r) => {
                let remove = tooltip_button(
                    "Remove",
                    Message::RemoveFromTransfers(self.base.nonce, FileYeetCommandType::Sub),
                    "Remove from list, file is untouched",
                );
                let result_text = widget::text(r.to_string())
                    .width(iced::Length::Fill)
                    .color_maybe(match r {
                        DownloadResult::Failure(_, _) => Some(ERROR_RED_COLOR),
                        _ => None,
                    });
                widget::row!(
                    result_text,
                    match r {
                        DownloadResult::Success => {
                            let publish_button = tooltip_button(
                                "Publish",
                                Message::PublishFileHashed {
                                    publish: CreateOrExistingPublish::Create(
                                        self.base.path.clone(),
                                    ),
                                    hash: self.base.hash,
                                    file_size: self.base.file_size,
                                    new_hash: true,
                                },
                                "Publish the file without re-hashing",
                            );
                            Element::<Message>::from(
                                widget::row!(
                                    tooltip_button(
                                        "Open",
                                        Message::OpenFile(self.base.path.clone()),
                                        "Open with the system's default launcher",
                                    ),
                                    publish_button,
                                    remove,
                                )
                                .spacing(12),
                            )
                        }
                        DownloadResult::Failure(_, RecoverableState::Recoverable(_)) => {
                            Element::<Message>::from(
                                widget::row!(
                                    widget::button(widget::text("Retry").size(12))
                                        .on_press(Message::ResumePausedDownload(self.base.nonce)),
                                    remove
                                )
                                .spacing(12),
                            )
                        }
                        _ => remove,
                    },
                )
                .into()
            }
        };

        let peer_str = match &self.progress {
            // Use the only active peer's string in single-peer downloads.
            DownloadState::Transferring {
                strategy: DownloadStrategy::SinglePeer(DownloadSinglePeer { peer_string, .. }),
                ..
            } => peer_string,

            // Use the comma-separated peers string for multi-peer downloads.
            DownloadState::Transferring {
                strategy: DownloadStrategy::MultiPeer(DownloadMultiPeer { peers_string, .. }),
                ..
            } => peers_string,

            // Default to empty string for other states.
            _ => "",
        };
        widget::container(widget::column!(
            progress,
            widget::row!(
                widget::text(&self.base.hash_hex).size(12),
                widget::space().width(iced::Length::Fill),
                rate.map_or_else(
                    || widget::space().into(),
                    |r| Element::from(widget::text(r).size(12)),
                ),
            ),
            widget::row!(
                widget::text(peer_str).size(12),
                widget::scrollable(
                    widget::text(self.base.path.to_string_lossy())
                        .size(12)
                        .align_x(iced::Alignment::End),
                )
                .direction(text_horizontal_scrollbar())
                .width(iced::Length::Fill)
                .height(26),
            )
            .spacing(6),
        ))
        .style(widget::container::dark)
        .width(iced::Length::Fill)
        .padding([6, 12]) // Extra padding on the right because of optional scrollbar.
        .into()
    }
}

/// An upload transfer and state information.
#[derive(Debug)]
pub struct UploadTransfer {
    pub base: TransferBase,
    pub peer_string: String,
    pub progress: UploadState,
}
impl NonceItem for UploadTransfer {
    fn nonce(&self) -> Nonce {
        self.base.nonce
    }
}
impl Transfer for UploadTransfer {
    fn base(&self) -> &TransferBase {
        &self.base
    }
    fn update_animation(&mut self) {
        if let UploadState::Transferring {
            progress_lock,
            progress_animation,
            requested_size,
            snapshot,
            ..
        } = &mut self.progress
        {
            let bytes_transferred = *progress_lock.blocking_read();
            if let Some(requested_size) = *requested_size.blocking_read() {
                // Update the progress bar with the most recent value.
                *progress_animation = bytes_transferred as f32 / requested_size.get() as f32;
            }

            // Update the transfer speed in human readable units.
            if snapshot
                .instant
                .elapsed()
                .gt(&TRANSFER_SPEED_UPDATE_INTERVAL)
            {
                snapshot.update(bytes_transferred);
            }
        }
    }
    fn draw(&self, mouse_move_elapsed: &Duration) -> iced::Element<'_, Message> {
        // Helper for creating standard buttons with tooltips.
        let tooltip_button = |text: &'static str, message: Message, tooltip: &'static str| {
            timed_tooltip(
                widget::button(widget::text(text).size(12)).on_press(message),
                tooltip,
                mouse_move_elapsed,
            )
        };

        let (progress, rate_or_size) = match &self.progress {
            UploadState::Transferring {
                progress_animation: p,
                snapshot,
                ..
            } => {
                let progress = widget::row!(
                    "Transferring...",
                    widget::progress_bar(0.0..=1., *p).girth(24),
                    tooltip_button(
                        "Cancel",
                        Message::CancelOrPauseTransfer(
                            self.base.nonce,
                            FileYeetCommandType::Pub,
                            CancelOrPause::Cancel,
                        ),
                        "Cancel the upload. The peer may attempt to recover the transfer later",
                    ),
                )
                .spacing(6)
                .align_y(iced::Alignment::Center);

                (progress, snapshot.human_readable.clone())
            }

            UploadState::Done(result) => {
                let remove = tooltip_button(
                    "Remove",
                    Message::RemoveFromTransfers(self.base.nonce, FileYeetCommandType::Pub),
                    "Remove from list, file is untouched",
                );
                let text_string = if let UploadResult::Success(r) = result {
                    humanize_bytes(r.end - r.start)
                } else {
                    String::new()
                };
                let result_text = widget::text(result.to_string())
                    .width(iced::Length::Fill)
                    .color_maybe(match result {
                        UploadResult::Failure(_) => Some(ERROR_RED_COLOR),
                        _ => None,
                    });

                (widget::row!(result_text, remove), text_string)
            }
        };

        widget::container(widget::column!(
            progress,
            widget::row!(
                widget::text(&self.base.hash_hex).size(12),
                widget::space().width(iced::Length::Fill),
                Element::from(widget::text(rate_or_size).size(12)),
            ),
            widget::row!(
                widget::text(&self.peer_string).size(12),
                widget::scrollable(
                    widget::text(self.base.path.to_string_lossy())
                        .size(12)
                        .align_x(iced::Alignment::End),
                )
                .direction(text_horizontal_scrollbar())
                .width(iced::Length::Fill)
                .height(26),
            )
            .spacing(6),
        ))
        .style(widget::container::dark)
        .width(iced::Length::Fill)
        .padding([6, 12]) // Extra padding on the right because of optional scrollbar.
        .into()
    }
}

/// Complete a download with the given result.
/// Handles removing peer nonces from the active peers maps.
#[tracing::instrument(skip(progress, result, peers))]
pub fn update_download_result(
    progress: &mut DownloadState,
    result: DownloadResult,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    // Avoid overwriting certain completed states.
    match progress {
        // Handle a paused transfer.
        DownloadState::Paused(_) => {
            // If the transfer result is cancelled, ignore it.
            // This is expected if the transfer was paused.
            if matches!(result, DownloadResult::Cancelled) {
                tracing::debug!("Download was paused and then cancelled, expected race condition");
                return;
            }
        }

        // Handle a transfer that is already done.
        DownloadState::Done(done) => {
            // If we are cancelling twice, this is a more forgivable double-result.
            if matches!(result, DownloadResult::Cancelled)
                && matches!(done, DownloadResult::Cancelled)
            {
                tracing::debug!("Download already marked as cancelled");
            } else {
                tracing::warn!("Download already marked as done: {done}");
            }
            return;
        }

        _ => {}
    }

    // If the download was connected to a peer, remove the nonce from transactions.
    for connection in progress.connections() {
        remove_nonce_for_peer(connection, peers, nonce);
    }

    // Mark the transfer as done.
    *progress = DownloadState::Done(result);
}

/// Complete an upload with the given result.
#[tracing::instrument(skip(progress, result, peers))]
pub fn update_upload_result(
    progress: &mut UploadState,
    result: UploadResult,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    // Handle a transfer that is already done.
    if let UploadState::Done(done) = progress {
        // If we are cancelling twice, this is a more forgivable double-result.
        if matches!(result, UploadResult::Cancelled) && matches!(done, UploadResult::Cancelled) {
            tracing::debug!("Upload already marked as cancelled");
        } else {
            tracing::warn!("Upload already marked as done: {done}");
        }
        return;
    }

    // If the upload was connected to a peer, remove the nonce from transactions.
    if let Some(connection) = progress.connection() {
        // Upload nonces should only be removed when not successful.
        // This is to ensure healthy connections are not closed before peers have completed all their downloads. (I.e., peers may be about to open a new request stream.)
        if matches!(result, UploadResult::Success(_)) {
            tracing::debug!("Not removing nonces for successful uploads");
        } else {
            remove_nonce_for_peer(connection, peers, nonce);
        }
    }

    // Mark the transfer as done.
    *progress = UploadState::Done(result);
}
