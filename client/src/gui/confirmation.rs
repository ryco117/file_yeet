use std::borrow::Cow;

use crate::{
    core::FileYeetCommandType,
    gui::{Message, Nonce},
};

/// The information to display in a confirmation dialog, and the action to take if the user confirms.
#[derive(Clone, Debug)]
pub struct ConfirmationDialog {
    pub title: Cow<'static, str>,
    pub message: Cow<'static, str>,
    pub confirm_action: Box<Message>,
}

/// A confirmation dialog for leaving a server. This will cancel all active transfers, but any partial download progress will be saved.
pub fn leave_server() -> ConfirmationDialog {
    ConfirmationDialog {
        title: Cow::Borrowed("Leave Server?"),
        message: Cow::Borrowed("Are you sure you want to leave the server? All active transfers will be cancelled. Any partial download progress will be saved."),
        confirm_action: Box::new(Message::SafelyLeaveServer),
    }
}

/// A confirmation dialog for cancelling a specific download. No progress is saved for resuming.
pub fn cancel_download(nonce: Nonce) -> ConfirmationDialog {
    ConfirmationDialog {
        title: Cow::Borrowed("Cancel Download?"),
        message: Cow::Borrowed(
            "Are you sure you want to cancel this download? All progress will be lost.",
        ),
        confirm_action: Box::new(Message::CancelTransfer(nonce, FileYeetCommandType::Sub)),
    }
}

/// A confirmation dialog for cancelling a specific upload. The peer may attempt to recover the transfer later if the file is still being published.
pub fn cancel_upload(nonce: Nonce) -> ConfirmationDialog {
    ConfirmationDialog {
        title: Cow::Borrowed("Cancel Upload?"),
        message: Cow::Borrowed("Are you sure you want to cancel this upload? The peer may attempt to recover the transfer later if the file is still being published."),
        confirm_action: Box::new(Message::CancelTransfer(
            nonce,
            FileYeetCommandType::Pub,
        )),
    }
}
