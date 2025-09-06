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
    core::{humanize_bytes, FileYeetCommandType},
    gui::{
        remove_nonce_for_peer, text_horizontal_scrollbar, timed_tooltip, CancelOrPause, Message,
        Nonce, PeerRequestStream, ERROR_RED_COLOR,
    },
};

/// The rate at which transfer speed text is updated.
const TRANSFER_SPEED_UPDATE_INTERVAL: Duration = Duration::from_millis(400);

/// The result of a file download with a peer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DownloadResult {
    /// The transfer succeeded.
    #[error("Transfer succeeded")]
    Success,

    /// The transfer failed. Has bool indicating whether the failure is recoverable.
    #[error("{0}")]
    Failure(Arc<String>, bool),

    /// The transfer was cancelled.
    #[error("Transfer cancelled")]
    Cancelled,
}

/// The result of a file upload with a peer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum UploadResult {
    /// The transfer succeeded.
    #[error("Transfer succeeded")]
    Success,

    /// The transfer failed.
    #[error("{0}")]
    Failure(Arc<String>),

    /// The transfer was cancelled.
    #[error("Transfer cancelled")]
    Cancelled,
}

/// The progress of a file transfer at a moment in time.
#[derive(Clone, Debug)]
pub struct TransferSnapshot {
    instant: Instant,
    bytes_transferred: u64,
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

/// The state of a download transfer with a peer.
#[derive(Debug)]
pub enum DownloadState {
    /// The transfer is awaiting a connection attempt.
    Connecting,

    /// The transfer is awaiting user confirmation.
    Consent(PeerRequestStream),

    /// The transfer is in progress.
    Transferring {
        peer: quinn::Connection,
        progress_lock: Arc<RwLock<u64>>,
        progress_animation: f32,
        snapshot: TransferSnapshot,
    },

    /// The transfer has been paused.
    Paused(Option<SocketAddr>),

    /// Resuming a download by hashing the partial file.
    ResumingHash(Arc<RwLock<f32>>),

    /// The transfer has completed.
    Done(DownloadResult),
}
impl DownloadState {
    /// If the progress state contains a peer connection, return it.
    /// Otherwise, return `None`.
    pub fn connection(&self) -> Option<&quinn::Connection> {
        match self {
            // Connection in these states.
            DownloadState::Consent(PeerRequestStream { connection, .. })
            | DownloadState::Transferring {
                peer: connection, ..
            } => Some(connection),

            // No connection in remaining states.
            _ => None,
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
    pub peer_string: String,
    pub peer_socket: Option<SocketAddr>,
    pub path: Arc<PathBuf>,
    pub cancellation_token: CancellationToken,
}
pub trait Transfer {
    fn base(&self) -> &TransferBase;

    /// Update fields related to the progress animation.
    fn update_animation(&mut self);

    /// Draw the transfer item in the GUI.
    fn draw(&self, mouse_move_elapsed: &Duration) -> iced::Element<'_, Message>;
}

/// A download transfer and state information.
#[derive(Debug)]
pub struct DownloadTransfer {
    pub base: TransferBase,
    pub progress: DownloadState,
}
impl Transfer for DownloadTransfer {
    fn base(&self) -> &TransferBase {
        &self.base
    }
    fn update_animation(&mut self) {
        if let DownloadState::Transferring {
            progress_lock,
            progress_animation,
            snapshot,
            ..
        } = &mut self.progress
        {
            // Update the progress bar with the most recent value.
            let bytes_transferred = *progress_lock.blocking_read();
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

        // Try to get a transfer rate string or None.
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
                widget::progress_bar(0.0..=1., *p).height(24),
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

            DownloadState::Paused(peer) => widget::row!(
                "Download is paused",
                widget::horizontal_space(),
                tooltip_button(
                    "Resume",
                    Message::ResumePausedDownload(self.base.nonce, *peer),
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

            DownloadState::ResumingHash(progress_lock) => widget::row!(
                "Resuming with partial hash...",
                widget::progress_bar(0.0..=1., *progress_lock.blocking_read()).height(24),
                tooltip_button(
                    "Cancel",
                    Message::CancelOrPauseTransfer(
                        self.base.nonce,
                        FileYeetCommandType::Sub,
                        CancelOrPause::Cancel,
                    ),
                    "Cancel attempting to resume the download",
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
                            Element::<Message>::from(
                                widget::row!(
                                    tooltip_button(
                                        "Open",
                                        Message::OpenFile(self.base.path.clone()),
                                        "Open with the system's default launcher",
                                    ),
                                    remove
                                )
                                .spacing(12),
                            )
                        }
                        DownloadResult::Failure(_, true) => {
                            Element::<Message>::from(
                                widget::row!(
                                    widget::button(widget::text("Retry").size(12)).on_press(
                                        Message::ResumePausedDownload(
                                            self.base.nonce,
                                            self.base.peer_socket
                                        )
                                    ),
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

        widget::container(widget::column!(
            progress,
            widget::row!(
                widget::text(&self.base.hash_hex).size(12),
                widget::horizontal_space(),
                rate.map_or_else(
                    || widget::horizontal_space().into(),
                    |r| Element::from(widget::text(r).size(12)),
                ),
            ),
            widget::row!(
                widget::text(&self.base.peer_string).size(12),
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
    pub progress: UploadState,
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

        // Try to get a transfer rate string or None.
        let rate = match &self.progress {
            UploadState::Transferring { snapshot, .. } => Some(snapshot.human_readable.clone()),
            UploadState::Done(_) => None,
        };

        let progress = match &self.progress {
            UploadState::Transferring {
                progress_animation: p,
                ..
            } => widget::row!(
                "Transferring...",
                widget::progress_bar(0.0..=1., *p).height(24),
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
            .align_y(iced::Alignment::Center),

            UploadState::Done(r) => {
                let remove = tooltip_button(
                    "Remove",
                    Message::RemoveFromTransfers(self.base.nonce, FileYeetCommandType::Pub),
                    "Remove from list, file is untouched",
                );
                let result_text = widget::text(r.to_string())
                    .width(iced::Length::Fill)
                    .color_maybe(match r {
                        UploadResult::Failure(_) => Some(ERROR_RED_COLOR),
                        _ => None,
                    });
                widget::row!(result_text, remove,)
            }
        };

        widget::container(widget::column!(
            progress,
            widget::row!(
                widget::text(&self.base.hash_hex).size(12),
                widget::horizontal_space(),
                rate.map_or_else(
                    || widget::horizontal_space().into(),
                    |r| Element::from(widget::text(r).size(12)),
                ),
            ),
            widget::row!(
                widget::text(&self.base.peer_string).size(12),
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
pub fn update_download_result(
    progress: &mut DownloadState,
    result: DownloadResult,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
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
            // If we are cancelling twice, ignore the second cancellation.
            // Otherwise, this is an unexpected double-result.
            if !matches!(result, DownloadResult::Cancelled)
                || !matches!(done, DownloadResult::Cancelled)
            {
                tracing::warn!("Download already marked as done {done}");
            }
            return;
        }

        _ => {}
    }

    // If the download was connected to a peer, remove the nonce from transactions.
    if let Some(connection) = progress.connection() {
        remove_nonce_for_peer(connection, peers, nonce);
    }

    // Mark the transfer as done.
    *progress = DownloadState::Done(result);
}

/// Complete an upload with the given result.
pub fn update_upload_result(
    progress: &mut UploadState,
    result: UploadResult,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    // Handle a transfer that is already done.
    if let UploadState::Done(done) = progress {
        // If we are cancelling twice, ignore the second cancellation.
        // Otherwise, this is an unexpected double-result.
        if !matches!(result, UploadResult::Cancelled) || !matches!(done, UploadResult::Cancelled) {
            tracing::warn!("Upload already marked as done {done}");
        }
        return;
    }

    // If the upload was connected to a peer, remove the nonce from transactions.
    if let Some(connection) = progress.connection() {
        remove_nonce_for_peer(connection, peers, nonce);
    }

    // Mark the transfer as done.
    *progress = UploadState::Done(result);
}
