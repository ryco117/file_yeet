use std::{path::PathBuf, sync::Arc, time::Duration};

use file_yeet_shared::{BiStream, HashBytes, ReadIpPortError};
use iced::widget;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::{
    core::FileAccessError,
    gui::{
        generate_nonce, text_horizontal_scrollbar, timed_tooltip, IncomingPublishSession, Message,
        Nonce, NonceItem, ERROR_RED_COLOR,
    },
    settings::SavedPublish,
};

/// The result of a file publish request.
#[derive(Debug, thiserror::Error)]
pub enum PublishFileFailure {
    #[error("{0}")]
    FileAccess(#[from] FileAccessError),

    #[error("{0}")]
    Publish(#[from] crate::core::PublishError),

    #[error("{0}")]
    SocketRead(#[from] ReadIpPortError),
}

/// The result of a publish request.
#[derive(Clone, Debug)]
pub enum PublishRequestResult {
    Success(IncomingPublishSession),
    Failure(Arc<PublishFileFailure>),
    Cancelled,
}

/// A file actively being published to the server.
#[derive(Clone, Debug)]
pub struct Publish {
    pub server_streams: Arc<tokio::sync::Mutex<BiStream>>,
    pub hash: HashBytes,
    pub hash_hex: String,
    pub file_size: u64,
    pub human_readable_size: String,
}

/// The state of a file publish request.
#[derive(Clone, Debug)]
pub enum PublishState {
    /// The file is being hashed, with progress given in the range [0., 1.].
    Hashing(Arc<RwLock<f32>>),

    /// The publish request is active.
    Publishing(Publish),

    /// The publish request has encountered an unrecoverable error.
    Failure(Arc<PublishFileFailure>, Option<(HashBytes, u64)>),

    /// The publish request was cancelled by the user.
    Cancelled(Option<(HashBytes, u64)>),
}
impl PublishState {
    /// Get the hash and file size of the publish request, if available.
    pub fn hash_and_file_size(&self) -> Option<(HashBytes, u64)> {
        match self {
            PublishState::Publishing(publish) => Some((publish.hash, publish.file_size)),
            PublishState::Cancelled(hfs) | PublishState::Failure(_, hfs) => *hfs,
            PublishState::Hashing(_) => None,
        }
    }
}

/// An item in the list of publishing requests.
#[derive(Clone, Debug)]
pub struct PublishItem {
    pub nonce: Nonce,
    pub path: Arc<PathBuf>,
    pub cancellation_token: CancellationToken,
    pub state: PublishState,
}
impl PublishItem {
    /// Make a new publish item in the hashing state.
    pub fn new(path: Arc<PathBuf>, progress_lock: Arc<RwLock<f32>>) -> Self {
        Self {
            nonce: generate_nonce(),
            path,
            cancellation_token: CancellationToken::new(),
            state: PublishState::Hashing(progress_lock),
        }
    }
}
impl NonceItem for PublishItem {
    fn nonce(&self) -> Nonce {
        self.nonce
    }
}
impl From<PublishItem> for SavedPublish {
    fn from(item: PublishItem) -> Self {
        Self::new(item.path.as_ref().clone(), item.state.hash_and_file_size())
    }
}
impl From<&PublishItem> for SavedPublish {
    fn from(item: &PublishItem) -> Self {
        Self::new(item.path.as_ref().clone(), item.state.hash_and_file_size())
    }
}

/// Draw the publishes view for the main connected page.
pub fn draw_publishes<'a>(
    publishes: &'a [PublishItem],
    mouse_move_elapsed: &Duration,
) -> iced::Element<'a, Message> {
    // Helper for creating standard buttons with tooltips.
    let tooltip_button = |text: &'static str, message: Message, tooltip: &'static str| {
        timed_tooltip(
            widget::button(widget::text(text).size(14)).on_press(message),
            tooltip,
            mouse_move_elapsed,
        )
    };

    let publish_views = publishes.iter().map(|pi| {
        let file_path_scrollable =
            widget::scrollable(widget::text(pi.path.to_string_lossy()).size(12))
                .direction(text_horizontal_scrollbar())
                .width(iced::Length::Fill)
                .height(26);
        widget::container(
            match &pi.state {
                // Display a publish in the hashing state.
                PublishState::Hashing(progress) => widget::row!(
                    widget::column!(
                        widget::row!(
                            widget::text("Hashing...").size(12),
                            widget::progress_bar(0.0..=1., *progress.blocking_read()).girth(12),
                        )
                        .spacing(6),
                        file_path_scrollable,
                    ),
                    tooltip_button(
                        "Cancel",
                        Message::CancelPublish(pi.nonce),
                        "Cancel the hashing process. The publish is not removed",
                    ),
                ),

                // Display an active `Publish` item.
                PublishState::Publishing(p) => widget::row!(
                    widget::column!(
                        widget::row!(
                            widget::text(&p.hash_hex).size(12),
                            widget::text("-").size(12),
                            widget::text(&p.human_readable_size).size(12)
                        )
                        .spacing(10),
                        file_path_scrollable,
                    ),
                    timed_tooltip(
                        widget::button(
                            widget::text("📋")
                                .size(14)
                                .font(iced::Font::with_name("Noto Emoji"))
                        )
                        .on_press(Message::CopyHash(pi.nonce)),
                        "Copy hash to clipboard",
                        mouse_move_elapsed,
                    ),
                    tooltip_button(
                        "Rehash",
                        Message::RehashPublish(pi.nonce),
                        "Rehash the file, necessary if the file has changed",
                    ),
                    tooltip_button(
                        "Cancel",
                        Message::CancelPublish(pi.nonce),
                        "Stop accepting new uploads for this file. The hash is not forgotten",
                    ),
                ),

                // Display a publish in the failure state.
                PublishState::Failure(e, _) => widget::row!(
                    widget::column!(
                        widget::text(format!("Failed to publish: {e}"))
                            .color(ERROR_RED_COLOR)
                            .size(12),
                        file_path_scrollable,
                    )
                    .width(iced::Length::Fill),
                    tooltip_button(
                        "Retry",
                        Message::RetryPublish(pi.nonce),
                        "Attempt to publish again",
                    ),
                    tooltip_button(
                        "Remove",
                        Message::RemovePublish(pi.nonce),
                        "Remove this item, forgetting the hash. The file is untouched",
                    ),
                ),

                // Display a publish that was intentionally cancelled.
                PublishState::Cancelled(_) => widget::row!(
                    widget::column!(widget::text("Cancelled").size(12), file_path_scrollable)
                        .width(iced::Length::Fill),
                    tooltip_button(
                        "Retry",
                        Message::RetryPublish(pi.nonce),
                        "Attempt to publish again",
                    ),
                    tooltip_button(
                        "Remove",
                        Message::RemovePublish(pi.nonce),
                        "Remove the publish, forgetting the hash. The file is untouched",
                    ),
                ),
            }
            .align_y(iced::Alignment::Center)
            .spacing(12),
        )
        .width(iced::Length::Fill)
        .style(widget::container::dark)
        .padding([6, 12]) // Extra padding on the right because of optional scrollbar.
        .into()
    });

    widget::column(publish_views).spacing(6).into()
}
