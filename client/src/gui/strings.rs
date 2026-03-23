//! This file contains (mostly user-facing) strings used in the GUI.
//! This module is to help transition to the code supporting multiple languages in the future, reduce string duplication, and make it easier to edit user-facing strings that appear in multiple places.

// Simple button/label strings.
pub const ACCEPT: &str = "Accept";
pub const CANCEL: &str = "Cancel";
pub const CANCELLED: &str = "Cancelled";
pub const REMOVE: &str = "Remove";
pub const RETRY: &str = "Retry";

// Server connection strings.
pub const INVALID_PORT_FORWARD: &str = "Invalid port forward. Defaults to no port mappings";
pub const WARNING_SKIPPING_SERVER_VERIFICATION: &str = "Warning: Skipping server certificate verification isn't recommended as it opens the connection up to eaves-dropping and manipulation";
pub const LOST_CONNECTION_TO_SERVER: &str = "Lost connection to server";

// Publish strings.
pub const PUBLISH_PATH_EXISTS: &str = "Publish using this path already exists";
pub const PUBLISHES_NOT_SORTED_BY_NONCE: &str =
    "Publishes not sorted by nonce after adding new publish";
pub const REMOVE_PUBLISH_TOOLTIP: &str =
    "Remove this item, forgetting the hash. The file is not touched";
pub const RETRY_PUBLISH_TOOLTIP: &str = "Attempt to publish again";

// Download strings.
pub const DOWNLOAD_NOT_MULTI_PEER_TRANSFERRING: &str =
    "Download not in multi-peer transferring state";
pub const CANCEL_DOWNLOAD_TOOLTIP: &str = "Cancel the download, abandoning progress";
pub const RETRY_DOWNLOAD_TOOLTIP: &str =
    "Retry the download attempt, reusing any saved partial progress";

// Transfer strings. Remnant of when uploads/downloads shared more code.
pub const TRANSFERRING_ELLIPSIS: &str = "Transferring...";
pub const REMOVE_TRANSFER_TOOLTIP: &str = "Remove this item. The file is not touched";

// Peer strings.
pub const REUSE_EXISTING_PEER_DEBUG: &str = "Reusing existing connection to peer";
pub const CREATING_NEW_CONNECTION_DEBUG: &str = "Creating new connection to peer";
