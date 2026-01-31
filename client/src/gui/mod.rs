use std::{
    collections::{hash_map, HashMap, HashSet},
    ffi::OsStr,
    net::SocketAddr,
    num::{NonZeroU16, NonZeroU64},
    ops::Div as _,
    path::PathBuf,
    sync::{
        atomic::{self, AtomicU64},
        Arc,
    },
    time::{Duration, Instant},
};

use circular_buffer::CircularBuffer;
use file_yeet_shared::{
    BiStream, HashBytes, DEFAULT_PORT, GOODBYE_CODE, GOODBYE_MESSAGE, MAX_SERVER_COMMUNICATION_SIZE,
};
use futures_util::FutureExt as _;
use iced::{widget, window, Element};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::{
    core::{
        humanize_bytes,
        intervals::{
            self, merge_adjacent_ranges, FileIntervals, RangeData as _, DOWNLOAD_CHUNK_INTERVAL_MIN,
        },
        peer_connection_into_stream, udp_holepunch, ConnectionsManager, FileYeetCommandType,
        Hasher, PortMappingConfig, PrepareConnectionError, PreparedConnection,
        ReadSubscribingPeerError, SubscribeError, HASH_EXT_REGEX, MAX_PEER_COMMUNICATION_SIZE,
        PEER_CONNECT_TIMEOUT, SERVER_CONNECTION_TIMEOUT,
    },
    gui::{
        publish::{draw_publishes, Publish, PublishItem, PublishRequestResult, PublishState},
        transfers::{
            update_download_result, update_upload_result, DownloadMultiPeer, DownloadPartRange,
            DownloadResult, DownloadSinglePeer, DownloadState, DownloadStrategy, DownloadTransfer,
            DownloadTransferringState, MultiPeerDownloadResult, RecoverableState, Transfer,
            TransferBase, TransferSnapshot, UploadResult, UploadState, UploadTransfer,
        },
    },
    settings::{
        load_settings, save_settings, AppSettings, PortMappingSetting, SavedDownload, SavedPublish,
    },
};

mod publish;
mod subscriptions;
mod transfers;

/// The string corresponding to a regex pattern for matching valid IPv6 addresses.
const IPV6_REGEX_STR: &str = r"(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3,3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))";

/// The string corresponding to a regex pattern for matching valid IPv4 addresses.
const IPV4_REGEX_STR: &str =
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

/// Lazily initialized regex for parsing server addresses.
/// Produces match groups `host` and `port` for the server address and optional port.
static SERVER_ADDRESS_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(&format!(
        "^\\s*(?:(?P<host>{IPV4_REGEX_STR}|\\[{IPV6_REGEX_STR}\\]|[^:]+)(?::(?P<port>\\d+))?|(?P<unbraced_ipv6_host>{IPV6_REGEX_STR}))\\s*$"
    ))
    .expect("Failed to compile the server address regex")
});

/// The maximum time to wait for a clean shutdown before forcing the application to exit.
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The red used to display errors to the user.
const ERROR_RED_COLOR: iced::Color = iced::Color::from_rgb(1., 0.35, 0.45);

/// Font capable of rendering emojis.
pub static EMOJI_FONT: &[u8] = include_bytes!("../../NotoEmoji-Regular.ttf");

/// The delay of mouse inactivity before showing tooltips.
const TOOLTIP_WAIT_DURATION: Duration = Duration::from_millis(500);

/// The maximum number of lines to keep in the status message history.
const MAX_LOG_HISTORY_LINES: usize = 256;

/// Maximum time to wait to gracefully reject a download.
const MAX_REJECT_TIMEOUT: Duration = Duration::from_millis(250);

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

/// Nonce used to identifying items locally.
type Nonce = u64;

/// Generate a unique nonce using atomic increment.
pub fn generate_nonce() -> Nonce {
    // Global atomic counter for generating unique nonces.
    static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

    NONCE_COUNTER.fetch_add(1, atomic::Ordering::Relaxed)
}

trait NonceItem {
    /// Get the nonce of this item.
    fn nonce(&self) -> Nonce;
}

/// The information to create a new publish item, or the nonce of an existing one.
#[derive(Clone, Debug)]
pub enum CreateOrExistingPublish {
    Create(Arc<PathBuf>),
    Existing(Nonce),
}

/// The result of a subscribe request.
#[derive(Clone, Debug)]
pub struct IncomingSubscribePeers {
    pub peers_with_size: Vec<(SocketAddr, u64)>,
    pub path: PathBuf,
    pub hash: HashBytes,
}
impl IncomingSubscribePeers {
    #[must_use]
    pub fn new(peers_with_size: Vec<(SocketAddr, u64)>, path: PathBuf, hash: HashBytes) -> Self {
        Self {
            peers_with_size,
            path,
            hash,
        }
    }
}

/// The result of a publish request. The bi-directional stream maintains the publish session.
#[derive(Clone, Debug)]
pub struct IncomingPublishSession {
    pub server_streams: Arc<tokio::sync::Mutex<BiStream>>,
    pub hash: HashBytes,
    pub file_size: u64,
}
impl IncomingPublishSession {
    #[must_use]
    pub fn new(server_streams: BiStream, hash: HashBytes, file_size: u64) -> Self {
        Self {
            server_streams: Arc::new(tokio::sync::Mutex::new(server_streams)),
            hash,
            file_size,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferView {
    Publishes,
    Downloads,
}

/// The labels for the transfer view radio buttons.
const TRANSFER_VIEWS: [TransferView; 2] = [TransferView::Publishes, TransferView::Downloads];
impl TransferView {
    fn to_str(self) -> &'static str {
        match self {
            TransferView::Publishes => "Uploads",
            TransferView::Downloads => "Downloads",
        }
    }
}

/// The state of the connection to a `file_yeet` server and peers.
#[derive(Debug)]
struct ConnectedState {
    /// Local QUIC endpoint for server and peer connections.
    endpoint: quinn::Endpoint,

    /// Connection with the server.
    server: quinn::Connection,

    /// The external address of the client, as seen from the server.
    external_address: (SocketAddr, String),

    /// The hash input field for creating new subscribe requests.
    hash_input: String,

    /// Map of peer socket addresses to QUIC connections.
    peers: HashMap<SocketAddr, HashSet<Nonce>>,

    /// List of download requests to peers.
    downloads: Vec<DownloadTransfer>,

    /// List of file uploads to peers.
    uploads: Vec<UploadTransfer>,

    /// List of file publish requests to the server.
    publishes: Vec<PublishItem>,

    /// The transfer view being shown.
    transfer_view: TransferView,
}
impl ConnectedState {
    fn new(
        endpoint: quinn::Endpoint,
        server: quinn::Connection,
        external_address: (SocketAddr, String),
    ) -> Self {
        Self {
            endpoint,
            server,
            external_address,
            hash_input: String::new(),
            peers: HashMap::new(),
            downloads: Vec::new(),
            uploads: Vec::new(),
            publishes: Vec::new(),
            transfer_view: TransferView::Publishes,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CancelOrPause {
    Cancel,
    Pause,
}

/// The state of the connection to a `file_yeet` server.
#[derive(Debug, Default)]
#[allow(clippy::large_enum_variant)]
enum ConnectionState {
    /// No server connection is active.
    #[default]
    Disconnected,

    /// Connecting to the server or safely closing the application.
    Stalling { start: Instant, tick: Instant },

    /// A connection to the server is active.
    Connected(ConnectedState),
}
impl ConnectionState {
    /// Make a new `ConnectionState` in the stalling state.
    pub fn new_stalling() -> Self {
        let now = Instant::now();
        Self::Stalling {
            start: now,
            tick: now,
        }
    }
}

/// Manages the status message and its history.
#[derive(Default)]
struct StatusManager {
    pub message: Option<String>,
    pub history: CircularBuffer<MAX_LOG_HISTORY_LINES, String>,
    pub history_visible: bool,
}

/// The state of the application for interacting with the GUI.
#[derive(Default)]
pub struct AppState {
    connection_state: ConnectionState,
    options: AppSettings,
    status_manager: StatusManager,
    modal: bool,
    safely_closing: bool,
    save_on_exit: bool,
    port_mapping: Option<crab_nat::PortMapping>,
    main_window: Option<window::Id>,
    last_mouse_move: Option<Instant>,
}

/// The messages that can be sent to the update loop of the application.
//  TODO: Message docs should be descriptive of what the message does, not necessarily how it was triggered. Messages can have multiple sources
#[derive(Clone, Debug)]
pub enum Message {
    /// The `Id` of the main (oldest) window, if one exists.
    MainWindowId(Option<window::Id>),

    /// The server text field was changed.
    ServerAddressChanged(String),

    /// The text field for the internal port was changed.
    InternalPortTextChanged(String),

    /// The port mapping radio button was changed.
    PortMappingRadioChanged(PortMappingSetting),

    /// The port forward text field was changed.
    PortForwardTextChanged(String),

    /// The gateway text field was changed.
    GatewayTextChanged(String),

    /// The connect button was clicked.
    ConnectClicked,

    /// A moment in time has passed, update the animations.
    AnimationTick,

    /// Toggle showing the status message history.
    ToggleStatusHistory,

    /// The result of a server connection attempt.
    ConnectResulted(Result<crate::core::PreparedConnection, Arc<PrepareConnectionError>>),

    /// The port mapping has been updated.
    PortMappingUpdated(Option<crab_nat::PortMapping>),

    /// Copy the server address to the clipboard.
    CopyServer,

    /// Leave the server and disconnect.
    SafelyLeaveServer,

    /// All async actions to leave a server have completed.
    LeftServer,

    /// A peer has requested a new transfer from an existing connection.
    PeerRequestedTransfer((HashBytes, PeerRequestStream)),

    /// The transfer view radio buttons were changed.
    TransferViewChanged(TransferView),

    /// The hash input field was changed.
    HashInputChanged(String),

    /// The publish button was clicked.
    PublishClicked,

    /// Initiate publishing of the chosen file or publish item.
    PublishChosenItem(CreateOrExistingPublish),

    /// Cancelled choosing a file path to publish.
    PublishPathCancelled,

    /// Create or update a publish item with a known hash. The hash may be from disk or freshly calculated.
    PublishFileHashed {
        publish: CreateOrExistingPublish,
        hash: HashBytes,
        file_size: u64,
        new_hash: bool,
    },

    /// The result of a publish request.
    PublishRequestResulted(Nonce, PublishRequestResult),

    /// The result of trying to receive a peer from the server.
    PublishPeerReceived(Nonce, Result<SocketAddr, Arc<ReadSubscribingPeerError>>),

    /// The result of trying to connect to a peer to publish to.
    PublishPeerConnectResulted(Nonce, Option<PeerRequestStream>),

    /// The subscribe button was clicked or the hash field was submitted.
    SubscribeStarted,

    /// The file path to save to, if chosen, and the hash text of the file.
    SubscribePathChosen(Option<PathBuf>, String),

    /// A download is being recreated from the open transfers at last close.
    SubscribeRecreated(SavedDownload),

    /// A subscribe request to the server has resulted.
    SubscribePeersResult(Result<IncomingSubscribePeers, Arc<SubscribeError>>),

    /// A subscribe connection attempt was completed.
    SubscribePeerConnectResulted(Nonce, Vec<PeerRequestStream>),

    // A download was accepted, initiate the download.
    AcceptDownload(Nonce),

    // A download was rejected, remove the download.
    RejectDownload(Nonce),

    /// Copy a hash to the clipboard.
    CopyHash(Nonce),

    /// Rehash a file that was previously published.
    RehashPublish(Nonce),

    /// Cancel publishing a file.
    CancelPublish(Nonce),

    /// Retry publishing a file.
    RetryPublish(Nonce),

    /// Remove a publish item.
    RemovePublish(Nonce),

    /// Cancel or pause a transfer that is in-progress.
    CancelOrPauseTransfer(Nonce, FileYeetCommandType, CancelOrPause),

    /// Change a download's `publish_on_success` toggle.
    PublishOnSuccessToggle(Nonce, bool),

    /// The resume button was pressed for a paused (or recoverable) download.
    ResumePausedDownload(Nonce),

    /// A resume attempt to get a partial file hash completed.
    ResumeFromPartialHashFile(
        Nonce,
        Result<(Hasher, u64, PeerRequestStream), Option<Arc<String>>>,
    ),

    /// The result of a download attempt.
    DownloadTransferResulted(Nonce, DownloadResult),

    /// The result of an attempt to initialize a multi-peer download by allocating the output file.
    PrepareMultiPeerDownloadResulted(
        Nonce,
        Result<nonempty::NonEmpty<PeerRequestStream>, Arc<std::io::Error>>,
    ),

    /// The result of a chunk download from a peer in a multi-peer download.
    /// `usize` is the connection ID in the multi-peer download.
    MultiPeerDownloadTransferResulted(Nonce, std::ops::Range<u64>, usize, MultiPeerDownloadResult),

    /// An attempt to resume a multi-peer download from saved state has failed.
    SaveFailedMultiPeerDownloadResume(Nonce, Arc<String>),

    /// The result of an upload attempt.
    UploadTransferResulted(Nonce, UploadResult),

    /// Open the file using the system launcher for that file type.
    OpenFile(Arc<PathBuf>),

    /// A completed transfer is being removed from its list.
    RemoveFromTransfers(Nonce, FileYeetCommandType),

    /// An unhandled event occurred.
    UnhandledEvent(iced::window::Id, iced::Event),

    /// Exit the application immediately. Ensure we aren't waiting for async tasks forever.
    ForceExit,
}

/// The application state and logic.
impl AppState {
    /// Create a new application state.
    pub fn new(args: &crate::Cli) -> (Self, iced::Task<Message>) {
        let mut status_manager = StatusManager::default();

        // Get base settings from the settings file, or default.
        // If there is an error, show the error message and use default settings.
        let mut settings = load_settings().unwrap_or_else(|e| {
            log_status_change::<LogErrorStatus>(
                &mut status_manager,
                format!("Failed to load settings: {e}"),
            );
            AppSettings::default()
        });

        {
            // The CLI arguments take final precedence on start.
            let crate::Cli {
                server_address,
                external_port_override,
                internal_port,
                gateway,
                nat_map,
                ..
            } = args;

            let mut used_cli = false;
            if let Some(server_address) = server_address.clone().filter(|s| !s.is_empty()) {
                settings.server_address = server_address;
                used_cli = true;
            }
            if let Some(gateway) = gateway.clone().filter(|g| !g.is_empty()) {
                settings.gateway_address = Some(gateway);
                used_cli = true;
            }
            if let Some(port) = internal_port {
                settings.internal_port_text = port.to_string();
                used_cli = true;
            }
            if let Some(port) = external_port_override {
                settings.port_forwarding_text = port.to_string();
                settings.port_mapping = PortMappingSetting::PortForwarding(Some(*port));
            } else if (!used_cli && matches!(settings.port_mapping, PortMappingSetting::None))
                || *nat_map
            {
                // Default to enabling NAT-PMP/PCP if no port forwarding is set.
                // Average users may not know that this is usually the best option for them.
                settings.port_mapping = PortMappingSetting::TryPcpNatPmp;
            }
        }

        // Create the initial state with the settings.
        let mut initial_state = Self {
            options: settings,
            status_manager,
            ..Self::default()
        };

        // Get the ID of the main window.
        let window_task = window::oldest().map(Message::MainWindowId);

        // Try connecting immediately if the server address is already set.
        if initial_state.options.server_address.is_empty() {
            // Just return the initial state.
            (initial_state, window_task)
        } else {
            // Attempt to connect to the given server on start.
            let connect_task = initial_state.update_connect_clicked();
            (initial_state, window_task.chain(connect_task))
        }
    }

    /// Update the application state based on a message.
    #[tracing::instrument(skip_all)]
    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            // Set the ID of the main window.
            Message::MainWindowId(id) => {
                tracing::debug!("Main window ID set to {id:?}");
                self.main_window = id;
                iced::Task::none()
            }

            // Handle the server address being changed.
            Message::ServerAddressChanged(address) => {
                tracing::debug!("Server address changed to {address}");
                self.options.server_address = address;
                self.save_on_exit = true;
                iced::Task::none()
            }

            Message::InternalPortTextChanged(text) => {
                tracing::debug!("Internal port text changed to {text}");
                self.options.internal_port_text = text;
                self.save_on_exit = true;
                iced::Task::none()
            }
            Message::PortMappingRadioChanged(selection) => {
                self.update_port_radio_changed(selection)
            }
            Message::PortForwardTextChanged(text) => self.update_port_forward_text(text),
            Message::GatewayTextChanged(text) => self.update_gateway_text(text),
            Message::ConnectClicked => self.update_connect_clicked(),
            Message::AnimationTick => self.update_animation_tick(),
            Message::ToggleStatusHistory => self.update_show_status_logs(),
            Message::ConnectResulted(r) => self.update_connect_resulted(r),
            Message::PortMappingUpdated(mapping) => self.update_port_mapping(mapping),

            // Copy the connected server address to the clipboard.
            Message::CopyServer => {
                tracing::debug!("Copying server address to clipboard");
                iced::clipboard::write(self.options.server_address.clone())
            }

            Message::SafelyLeaveServer => self.safely_close(CloseType::Connections),

            // All async actions to leave a server have completed.
            Message::LeftServer => {
                tracing::debug!("Left server, now disconnected");
                self.safely_closing = false;
                self.connection_state = ConnectionState::Disconnected;
                iced::Task::none()
            }

            // A peer has requested a new transfer from an existing connection.
            Message::PeerRequestedTransfer((hash, peer_request)) => {
                self.update_peer_requested_transfer(hash, peer_request)
            }

            // The transfer view radio buttons were changed.
            Message::TransferViewChanged(view) => {
                if let ConnectionState::Connected(connected_state) = &mut self.connection_state {
                    tracing::debug!("Transfer view changed to {view:?}");
                    connected_state.transfer_view = view;
                } else {
                    tracing::warn!("Transfer view changed to {view:?} while not connected");
                }
                iced::Task::none()
            }

            // Handle the hash input being changed.
            Message::HashInputChanged(hash) => {
                if let ConnectionState::Connected(ConnectedState { hash_input, .. }) =
                    &mut self.connection_state
                {
                    tracing::debug!("Hash input changed to '{hash}'");
                    *hash_input = hash;
                } else {
                    tracing::warn!("Hash input changed to '{hash}' while not connected");
                }
                iced::Task::none()
            }

            // Handle the publish button being clicked by picking a file to publish.
            Message::PublishClicked => {
                tracing::debug!("Publish button clicked");

                // Clear the status message before starting the publish attempt.
                self.clear_status_message();

                // Let state know that a modal dialog is open.
                self.modal = true;

                iced::Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file to publish")
                        .pick_file(),
                    |f| {
                        f.map_or(Message::PublishPathCancelled, |f| {
                            Message::PublishChosenItem(CreateOrExistingPublish::Create(Arc::new(
                                f.into(),
                            )))
                        })
                    },
                )
            }

            Message::PublishChosenItem(publish) => self.update_publish_chosen_item(publish),
            Message::PublishPathCancelled => {
                tracing::debug!("Publish choice cancelled");
                self.modal = false;
                iced::Task::none()
            }
            Message::PublishFileHashed {
                publish,
                hash,
                file_size,
                new_hash,
            } => self.update_publish_file_hashed(publish, hash, file_size, new_hash),
            Message::PublishRequestResulted(nonce, r) => {
                self.update_publish_request_resulted(nonce, r)
            }
            Message::PublishPeerReceived(nonce, r) => self.update_publish_peer_received(nonce, r),
            Message::PublishPeerConnectResulted(pub_nonce, peer) => {
                self.update_publish_peer_connect_resulted(pub_nonce, peer)
            }
            Message::SubscribeStarted => self.update_subscribe_started(),
            Message::SubscribePathChosen(path, hash_hex) => {
                self.update_subscribe_path_chosen(path, &hash_hex)
            }
            Message::SubscribeRecreated(transfer_base) => {
                self.update_subscribe_recreated(transfer_base)
            }
            Message::SubscribePeersResult(r) => self.update_subscribe_peers_result(r),
            Message::SubscribePeerConnectResulted(nonce, r) => {
                self.update_subscribe_connect_resulted(nonce, r)
            }
            Message::AcceptDownload(nonce) => self.update_accept_download(nonce),
            Message::RejectDownload(nonce) => self.update_reject_download(nonce),
            Message::CopyHash(nonce) => self.update_copy_hash(nonce),
            Message::RehashPublish(nonce) => self.update_rehash_publish(nonce),
            Message::CancelPublish(nonce) => self.update_cancel_publish(nonce),
            Message::RetryPublish(nonce) => self.update_retry_publish(nonce),
            Message::RemovePublish(nonce) => self.update_remove_publish(nonce),
            Message::CancelOrPauseTransfer(nonce, transfer_type, cancel_or_pause) => {
                self.update_cancel_or_pause(nonce, transfer_type, cancel_or_pause)
            }
            Message::PublishOnSuccessToggle(nonce, publish_on_success) => {
                self.update_publish_on_success_toggle(nonce, publish_on_success)
            }
            Message::ResumePausedDownload(nonce) => self.update_resume_paused(nonce),
            Message::ResumeFromPartialHashFile(nonce, result) => {
                self.update_resume_partial_hash(nonce, result)
            }
            Message::DownloadTransferResulted(nonce, r) => self.update_download_resulted(nonce, r),
            Message::PrepareMultiPeerDownloadResulted(nonce, r) => {
                self.update_prepare_multi_peer_download_resulted(nonce, r)
            }
            Message::MultiPeerDownloadTransferResulted(nonce, range, connection_id, result) => self
                .update_multi_peer_download_transfer_resulted(nonce, range, connection_id, result),
            Message::SaveFailedMultiPeerDownloadResume(nonce, e) => {
                self.update_save_failed_multi_peer_download_resume(nonce, e)
            }
            Message::UploadTransferResulted(nonce, r) => self.update_upload_resulted(nonce, r),

            // Handle the `Open` button being pressed.
            Message::OpenFile(path) => {
                tracing::debug!("Opening file: {}", path.to_string_lossy());
                open::that(path.as_ref()).unwrap_or_else(|e| {
                    log_status_change::<LogErrorStatus>(
                        &mut self.status_manager,
                        format!("Failed to open file: {e}"),
                    );
                });
                iced::Task::none()
            }

            Message::RemoveFromTransfers(nonce, transfer_type) => {
                self.update_remove_from_transfers(nonce, transfer_type)
            }

            // Handle an event that iced did not handle itself.
            Message::UnhandledEvent(window, event) => match event {
                // Check for a close window request to allow safe closing.
                iced::Event::Window(window::Event::CloseRequested) => {
                    tracing::debug!("`CloseRequested` event received from window {window}");

                    if self.main_window.map_or_else(
                        || {
                            log_status_change::<LogErrorStatus>(
                                &mut self.status_manager,
                                "Main window not available at close event".to_owned(),
                            );
                            false
                        },
                        |w| w != window,
                    ) || self.safely_closing
                    {
                        // Allow force closing if the safe exit is taking too long for the user.
                        // Also allows non-main windows to close immediately.
                        iced::window::close(window)
                    } else {
                        // Start the safe exit process.
                        self.safely_close(CloseType::Application)
                    }
                }

                // Check for mouse movement to update whether tooltips display.
                iced::Event::Mouse(iced::mouse::Event::CursorMoved { .. }) => {
                    // Update the time of last cursor movement.
                    self.last_mouse_move = Some(Instant::now());
                    iced::Task::none()
                }

                // Silently ignore all other events.
                _ => iced::Task::none(),
            },

            // Exit the application immediately.
            Message::ForceExit => {
                tracing::debug!("Force exit requested");
                self.main_window.map_or_else(
                    || {
                        log_status_change::<LogErrorStatus>(
                            &mut self.status_manager,
                            "Main window not available at force exit".to_owned(),
                        );
                        iced::exit()
                    },
                    iced::window::close,
                )
            }
        }
    }

    /// Listen for events that should be translated into messages.
    #[tracing::instrument(skip(self))]
    pub fn subscription(&self) -> iced::Subscription<Message> {
        match &self.connection_state {
            // Listen for close events and animation ticks when connecting/stalling.
            ConnectionState::Stalling { .. } => subscriptions::stalling(),

            ConnectionState::Connected(ConnectedState {
                endpoint,
                external_address,
                publishes,
                ..
            }) => subscriptions::connected(
                endpoint,
                &external_address.0,
                self.port_mapping.as_ref(),
                publishes,
            ),

            // Listen for application close events when disconnected.
            ConnectionState::Disconnected => subscriptions::disconnected(),
        }
    }

    /// Draw the application GUI.
    pub fn view(&self) -> Element<'_, Message> {
        // Get the time since the last mouse movement.
        let mouse_move_elapsed = self
            .last_mouse_move
            .as_ref()
            .map(Instant::elapsed)
            .unwrap_or_default();

        // Create a different top-level page based on the connection state.
        let page: Element<Message> = if self.status_manager.history_visible {
            let content = widget::column(
                self.status_manager
                    .history
                    .iter()
                    .map(|t| widget::text(t).color(ERROR_RED_COLOR).into()),
            )
            .spacing(6);
            widget::column![
                widget::space().height(iced::Length::Fill),
                widget::scrollable(content)
                    .spacing(0)
                    .width(iced::Length::Fill)
            ]
            .into()
        } else {
            match &self.connection_state {
                // Display a prompt for the server address when disconnected.
                ConnectionState::Disconnected => self.view_disconnected_page(),

                // Display a spinner while connecting/stalling.
                &ConnectionState::Stalling { start, tick } => {
                    if self.safely_closing {
                        widget::column!(
                            Self::view_connecting_page(start, tick, MAX_SHUTDOWN_WAIT),
                            widget::text("Closing, please wait...").size(24),
                            widget::text(
                                "Pressing close a second time will cancel safety operations."
                            )
                            .size(16),
                            widget::space().height(iced::Length::Fill),
                        )
                        .spacing(4)
                        .align_x(iced::Alignment::Center)
                        .into()
                    } else {
                        Self::view_connecting_page(start, tick, SERVER_CONNECTION_TIMEOUT)
                    }
                }

                // Display the main application controls when connected.
                ConnectionState::Connected(connected_state) => {
                    self.view_connected_page(connected_state, &mouse_move_elapsed)
                }
            }
        };

        // Always display the status bar at the bottom.
        let status_bar = widget::row![
            if let Some(status_manager) = &self.status_manager.message {
                Element::from(
                    widget::text(status_manager)
                        .color(ERROR_RED_COLOR)
                        .width(iced::Length::Fill)
                        .height(iced::Length::Shrink),
                )
            } else {
                widget::space().width(iced::Length::Fill).into()
            },
            timed_tooltip(
                widget::button("Status History").on_press_maybe(
                    (!self.status_manager.history.is_empty()
                        || self.status_manager.history_visible)
                        .then_some(Message::ToggleStatusHistory)
                ),
                "Toggle visibility of the status history. Disabled if the history is empty",
                &mouse_move_elapsed,
            )
        ]
        .align_y(iced::Alignment::Center);
        widget::column!(page, horizontal_line(), status_bar)
            .spacing(4)
            .padding(6)
            .into()
    }

    /// Prefer a dark theme.
    #[allow(clippy::unused_self)]
    pub fn theme(&self) -> iced::Theme {
        iced::Theme::Dark
    }

    /// Draw the disconnected page with a server address input and connect button.
    fn view_disconnected_page(&self) -> iced::Element<'_, Message> {
        let mut server_address = widget::text_input(
            "Server address. E.g., localhost:7828",
            &self.options.server_address,
        );

        let connect_button = widget::button("Connect")
            .on_press_maybe((!self.modal).then_some(Message::ConnectClicked));
        let mut internal_port_text = widget::text_input(
            "E.g., 12345. Leave empty to use any available port",
            &self.options.internal_port_text,
        );
        let mut port_forward_text =
            widget::text_input("E.g., 8888", &self.options.port_forwarding_text);

        if !self.modal {
            server_address = server_address
                .on_input(Message::ServerAddressChanged)
                .on_submit(Message::ConnectClicked);

            internal_port_text = internal_port_text.on_input(Message::InternalPortTextChanged);
            if let PortMappingSetting::PortForwarding(_) = &self.options.port_mapping {
                port_forward_text = port_forward_text.on_input(Message::PortForwardTextChanged);
            }
        }

        // Ignore the data field in the radio selection status.
        let selected_mapping = match self.options.port_mapping {
            PortMappingSetting::PortForwarding(_) => PortMappingSetting::PortForwarding(None),
            other => other,
        };

        // Create a bottom section for choosing port forwarding/mapping options.
        let choose_port_mapping = widget::column!(
            widget::row!("Internal Port to Bind", internal_port_text).spacing(12),
            widget::radio(
                PortMappingSetting::None.to_label(),
                PortMappingSetting::None,
                Some(selected_mapping),
                Message::PortMappingRadioChanged,
            ),
            widget::row!(
                widget::radio(
                    PortMappingSetting::PortForwarding(None).to_label(),
                    PortMappingSetting::PortForwarding(None),
                    Some(selected_mapping),
                    Message::PortMappingRadioChanged,
                ),
                port_forward_text,
            )
            .spacing(32),
            widget::radio(
                PortMappingSetting::TryPcpNatPmp.to_label(),
                PortMappingSetting::TryPcpNatPmp,
                Some(selected_mapping),
                Message::PortMappingRadioChanged,
            ),
        )
        .spacing(6);

        // Create a text input for the gateway address.
        let gateway = widget::row!(
            "Gateway address:",
            widget::text_input(
                "Gateway address (e.g. 192.168.1.1), or leave empty",
                self.options.gateway_address.as_deref().unwrap_or_default()
            )
            .on_input(Message::GatewayTextChanged)
        )
        .spacing(6)
        .align_y(iced::Alignment::Center);

        widget::container(
            widget::column!(
                widget::space().height(iced::Length::Fill),
                server_address,
                connect_button,
                widget::space().height(iced::Length::FillPortion(2)),
                choose_port_mapping,
                gateway,
            )
            .align_x(iced::Alignment::Center)
            .spacing(6),
        )
        .center_x(iced::Length::Fill)
        .center_y(iced::Length::Fill)
        .padding(12)
        .into()
    }

    /// Draw the connecting page with a spinner.
    fn view_connecting_page<'a>(
        start: Instant,
        tick: Instant,
        max_duration: Duration,
    ) -> iced::Element<'a, Message> {
        let fraction_waited = (tick - start)
            .as_secs_f32()
            .div(max_duration.as_secs_f32())
            .min(1.);
        let spinner =
            widget::container::Container::new(widget::progress_bar(0.0..=1., fraction_waited))
                .padding(24)
                .center_x(iced::Length::Fill)
                .center_y(iced::Length::Fill);

        Element::<'a>::from(spinner)
    }

    /// Draw the transfer view for the main connected page.
    fn draw_transfers<'a, I, T: Transfer + 'a>(
        transfers: I,
        mouse_move_elapsed: &Duration,
    ) -> iced::Element<'a, Message>
    where
        I: IntoIterator<Item = &'a T>,
    {
        widget::column(transfers.into_iter().map(|t| t.draw(mouse_move_elapsed)))
            .spacing(6)
            .into()
    }

    /// Draw the main application controls when connected to a server.
    fn view_connected_page<'a, 'b: 'a>(
        &'b self,
        connected_state: &'a ConnectedState,
        mouse_move_elapsed: &Duration,
    ) -> iced::Element<'a, Message> {
        // Define the elements that we want to be modal-aware first.
        let mut publish_button = widget::button("Yeet");
        let mut download_button = widget::button("Yoink");
        let mut hash_text_input = widget::text_input("Hash", &connected_state.hash_input);
        let mut leave_server_button = widget::button(widget::text("Leave").size(14));

        // Disable the inputs while a modal is open.
        if !self.modal {
            publish_button = publish_button.on_press(Message::PublishClicked);
            hash_text_input = hash_text_input.on_input(Message::HashInputChanged);
            leave_server_button = leave_server_button.on_press(Message::SafelyLeaveServer);

            // Enable the download button if the hash is valid.
            if HASH_EXT_REGEX.is_match(&connected_state.hash_input) {
                download_button = download_button.on_press(Message::SubscribeStarted);
                hash_text_input = hash_text_input.on_submit(Message::SubscribeStarted);
            }
        }

        // Apply tooltips to the buttons.
        let publish_button = timed_tooltip(
            publish_button,
            "Choose a file to share with peers",
            mouse_move_elapsed,
        );
        let download_button = timed_tooltip(
            download_button,
            "Download file with specified hash. Disabled if the hash is invalid",
            mouse_move_elapsed,
        );
        let leave_server_button = timed_tooltip(
            leave_server_button,
            "Leave the server, stop active transfers, and save publishes and downloads",
            mouse_move_elapsed,
        );

        // Define a header exposing the server address we are connected to
        // and how the server sees us (our external IP address).
        let header = widget::row!(
            "Server address:",
            widget::text(&self.options.server_address),
            timed_tooltip(
                widget::button(
                    widget::text("📋")
                        .size(14)
                        .font(iced::Font::with_name("Noto Emoji"))
                )
                .on_press(Message::CopyServer),
                "Copy server address to clipboard",
                mouse_move_elapsed,
            ),
            leave_server_button,
            widget::space().width(iced::Length::Fill),
            "Our External Address:",
            widget::text(&connected_state.external_address.1),
        )
        .align_y(iced::alignment::Alignment::Center)
        .spacing(6);

        // Hash input and download button.
        let download_input = widget::row!(hash_text_input, download_button).spacing(6);

        // Radio buttons for choosing the transfer view.
        let transfer_view_choice = widget::row(std::iter::once("View: ".into()).chain(
            TRANSFER_VIEWS.iter().map(|l| {
                widget::radio(
                    l.to_str(),
                    *l,
                    Some(connected_state.transfer_view),
                    Message::TransferViewChanged,
                )
                .size(16)
                .spacing(8)
                .into()
            }),
        ))
        .spacing(12);

        // Create a view of transfers.
        let transfer_content = match connected_state.transfer_view {
            // Create a list of published files and uploads.
            TransferView::Publishes => {
                match (
                    connected_state.publishes.is_empty(),
                    connected_state.uploads.is_empty(),
                ) {
                    // Both are empty, show nothing.
                    (true, true) => iced::widget::space().into(),

                    // Only uploads are empty, show publishes.
                    (false, true) => draw_publishes(&connected_state.publishes, mouse_move_elapsed),

                    // Only publishes are empty, show uploads.
                    (true, false) => {
                        Self::draw_transfers(&connected_state.uploads, mouse_move_elapsed)
                    }

                    // Show both publishes and uploads. Separate them with a line.
                    (false, false) => widget::column!(
                        draw_publishes(&connected_state.publishes, mouse_move_elapsed),
                        horizontal_line(),
                        Self::draw_transfers(&connected_state.uploads, mouse_move_elapsed),
                    )
                    .spacing(12)
                    .into(),
                }
            }

            // Create a list of download attempts.
            TransferView::Downloads => {
                Self::draw_transfers(&connected_state.downloads, mouse_move_elapsed)
            }
        };

        widget::container(
            widget::column!(
                header,
                horizontal_line(),
                widget::row!(
                    publish_button,
                    widget::space().width(iced::Length::Fixed(10.)),
                    download_input,
                )
                .spacing(6),
                transfer_view_choice,
                widget::scrollable(transfer_content).spacing(0),
            )
            .spacing(12),
        )
        .width(iced::Length::Fill)
        .height(iced::Length::Fill)
        .padding(6)
        .into()
    }

    /// Handle the port mapping radio button being changed.
    #[tracing::instrument(skip(self))]
    fn update_port_radio_changed(&mut self, selection: PortMappingSetting) -> iced::Task<Message> {
        tracing::debug!("Port radio UI changed");
        self.options.port_mapping = match selection {
            PortMappingSetting::None => {
                self.clear_status_message();
                PortMappingSetting::None
            }
            PortMappingSetting::PortForwarding(_) => PortMappingSetting::PortForwarding({
                let o = self
                    .options
                    .port_forwarding_text
                    .trim()
                    .parse::<NonZeroU16>();
                if let Err(e) = &o {
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        format!("{INVALID_PORT_FORWARD}: {e}"),
                    );
                } else {
                    self.clear_status_message();
                }
                o.ok()
            }),
            PortMappingSetting::TryPcpNatPmp => {
                self.clear_status_message();
                PortMappingSetting::TryPcpNatPmp
            }
        };
        self.save_on_exit = true;
        iced::Task::none()
    }

    /// Update the state after the port forward text field was changed.
    #[tracing::instrument(skip(self))]
    fn update_port_forward_text(&mut self, text: String) -> iced::Task<Message> {
        tracing::debug!("Port forward text UI changed");
        self.options.port_forwarding_text = text;
        if let PortMappingSetting::PortForwarding(port) = &mut self.options.port_mapping {
            match self
                .options
                .port_forwarding_text
                .trim()
                .parse::<NonZeroU16>()
            {
                Ok(p) => {
                    *port = Some(p);
                    self.clear_status_message();
                }
                Err(e) => {
                    *port = None;
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        format!("{INVALID_PORT_FORWARD}: {e}"),
                    );
                }
            }
        }
        self.save_on_exit = true;
        iced::Task::none()
    }

    /// Update the state after the gateway text field was changed.
    #[tracing::instrument(skip(self))]
    fn update_gateway_text(&mut self, text: String) -> iced::Task<Message> {
        tracing::debug!("Gateway text UI changed");
        if text.trim().is_empty() {
            self.options.gateway_address = None;
        } else {
            self.options.gateway_address = Some(text);
        }
        self.save_on_exit = true;
        iced::Task::none()
    }

    /// Update the state after the connect button was clicked.
    #[tracing::instrument(skip_all)]
    fn update_connect_clicked(&mut self) -> iced::Task<Message> {
        tracing::debug!("Connect button clicked");

        // Clear the status message before starting the connection attempt.
        self.clear_status_message();

        // Determine if a valid server address was entered.
        let regex_match = if self.options.server_address.trim().is_empty() {
            // If empty, use sane defaults.
            "localhost".clone_into(&mut self.options.server_address);
            Some((self.options.server_address.clone(), DEFAULT_PORT))
        } else {
            // Otherwise, parse the server address and optional port.
            SERVER_ADDRESS_REGEX
                .captures(&self.options.server_address)
                .and_then(|captures| {
                    let host = if let Some(host) = captures.name("host").map(|h| h.as_str()) {
                         if host.starts_with('[') && host.ends_with(']') {
                             // Strip the brackets from the host.
                             // These are used (by IPv6) to disambiguate colons between host and port.
                             host.get(1..host.len() - 1).unwrap()
                         } else {
                             host
                         }
                    } else {
                        captures
                            .name("unbraced_ipv6_host")
                            .expect("Unexpected error: One of `host` and `unbraced_ipv6_host` must be captured in a successful map")
                            .as_str()
                    };

                    // If there is no port, use the default port. Otherwise, validate the input.
                    let port = captures.name("port").map_or(Some(DEFAULT_PORT), |p| {
                        p.as_str().parse::<NonZeroU16>().ok()
                    })?;

                    Some((host.to_owned(), port))
                })
        };

        // If the server address is invalid, display an error message and return.
        let Some((server_address, port)) = regex_match else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "Invalid server address".to_owned(),
            );
            return iced::Task::none();
        };

        // Validate the internal port.
        let internal_port = {
            let text = self.options.internal_port_text.trim();
            if text.is_empty() {
                None
            } else if let Ok(n) = text.parse::<NonZeroU16>() {
                Some(n)
            } else {
                log_status_change::<LogWarnStatus>(
                    &mut self.status_manager,
                    "Invalid internal port".to_owned(),
                );
                return iced::Task::none();
            }
        };

        tracing::debug!("Trying connection to server {server_address}:{port}");

        // Set the state to `Stalling` before starting the connection attempt.
        self.connection_state = ConnectionState::new_stalling();

        // Try to get the user's intent from the GUI options.
        let port_mapping = match self.options.port_mapping {
            PortMappingSetting::None | PortMappingSetting::PortForwarding(None) => {
                PortMappingConfig::None
            }
            PortMappingSetting::PortForwarding(Some(port)) => {
                PortMappingConfig::PortForwarding(port)
            }
            PortMappingSetting::TryPcpNatPmp => {
                PortMappingConfig::PcpNatPmp(self.port_mapping.take())
            }
        };
        let gateway = self.options.gateway_address.clone();

        // Try to connect to the server in a new task.
        iced::Task::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::prepare_server_connection(
                    Some(&server_address),
                    port,
                    gateway.as_deref(),
                    internal_port,
                    port_mapping,
                    &mut bb,
                )
                .await
                .map_err(Arc::new)
            },
            Message::ConnectResulted,
        )
    }

    /// Update the state after a tick when animations are occurring.
    #[tracing::instrument(skip_all)]
    fn update_animation_tick(&mut self) -> iced::Task<Message> {
        match &mut self.connection_state {
            // Update the spinner when connecting/stalling.
            ConnectionState::Stalling { tick, .. } => *tick = Instant::now(),

            // Update the progress of transfers when connected.
            ConnectionState::Connected(ConnectedState {
                downloads, uploads, ..
            }) => {
                downloads
                    .iter_mut()
                    .for_each(DownloadTransfer::update_animation);
                uploads
                    .iter_mut()
                    .for_each(UploadTransfer::update_animation);
            }

            // Do nothing in other states.
            ConnectionState::Disconnected => {}
        }
        iced::Task::none()
    }

    /// Update the state to show or hide the status logs.
    fn update_show_status_logs(&mut self) -> iced::Task<Message> {
        self.status_manager.history_visible = !self.status_manager.history_visible;
        iced::Task::none()
    }

    /// Update the state after a connection attempt to the server completed.
    fn update_connect_resulted(
        &mut self,
        result: Result<PreparedConnection, Arc<PrepareConnectionError>>,
    ) -> iced::Task<Message> {
        match result {
            Ok(prepared) => {
                let PreparedConnection {
                    endpoint,
                    server_connection,
                    external_address,
                    port_mapping,
                } = prepared;
                self.connection_state = ConnectionState::Connected(ConnectedState::new(
                    endpoint,
                    server_connection,
                    external_address,
                ));
                self.port_mapping = port_mapping;

                // Attempt to recreate previous publish and download tasks.
                if !self.options.last_publishes.is_empty()
                    || !self.options.last_downloads.is_empty()
                {
                    if !self.options.last_downloads.is_empty() {
                        // Consider the settings file to be out of sync if we are recreating downloads.
                        self.save_on_exit = true;
                    }

                    let tasks = self
                        .options
                        .last_publishes
                        .drain(..)
                        .map(|p| {
                            let message = if let Some(hfs) = p.hash_and_file_size {
                                Message::PublishFileHashed {
                                    publish: CreateOrExistingPublish::Create(Arc::new(p.path)),
                                    hash: hfs.0,
                                    file_size: hfs.1,
                                    new_hash: false, // The hash is from disk, not a new hash.
                                }
                            } else {
                                Message::PublishChosenItem(CreateOrExistingPublish::Create(
                                    Arc::new(p.path),
                                ))
                            };
                            iced::Task::done(message)
                        })
                        .chain(
                            self.options
                                .last_downloads
                                .drain(..)
                                .map(|d| iced::Task::done(Message::SubscribeRecreated(d))),
                        );

                    return iced::Task::batch(tasks);
                }
            }
            Err(e) => {
                log_status_change::<LogErrorStatus>(
                    &mut self.status_manager,
                    format!("Error connecting: {e}"),
                );
                self.connection_state = ConnectionState::Disconnected;
            }
        }
        iced::Task::none()
    }

    /// Update the state after a port mapping renewal led to a state change.
    #[tracing::instrument(skip_all)]
    fn update_port_mapping(
        &mut self,
        port_mapping: Option<crab_nat::PortMapping>,
    ) -> iced::Task<Message> {
        if let Some(port_mapping) = port_mapping {
            tracing::debug!("Port mapping updated: {port_mapping:?}");
            self.port_mapping = Some(port_mapping);
        } else {
            tracing::warn!("Port mapping renewal failed");
        }
        iced::Task::none()
    }

    /// Update after an existing peer requested a new file transfer.
    #[tracing::instrument(skip(self, peer_request))]
    fn update_peer_requested_transfer(
        &mut self,
        hash: HashBytes,
        peer_request: PeerRequestStream,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("Peer requested transfer while not connected");
            return iced::Task::none();
        };

        // Find the publish-nonce corresponding to the hash.
        let Some(nonce) = publishes.iter_mut().find_map(|pi| match &pi.state {
            PublishState::Publishing(p) if p.hash == hash => Some(pi.nonce),
            _ => None,
        }) else {
            tracing::warn!("Peer requested transfer for unknown hash");
            return iced::Task::none();
        };

        tracing::debug!("Peer requested transfer with nonce {nonce}");
        self.update_publish_peer_connect_resulted(nonce, Some(peer_request))
    }

    /// Begins a publish request with the chosen file, starting from determining the hash.
    #[tracing::instrument(skip(self))]
    fn update_publish_chosen_item(
        &mut self,
        publish: CreateOrExistingPublish,
    ) -> iced::Task<Message> {
        tracing::debug!("Publish dialog closed");
        self.modal = false;

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Task::none();
        };

        // Ensure the transfer view is set to publishing to see the new item.
        *transfer_view = TransferView::Publishes;

        let (progress, cancellation_token, nonce, path) = match publish {
            // If a new publish is requested, create the desired `PublishItem`.
            CreateOrExistingPublish::Create(path) => {
                // Ensure the file path is not already being published.
                if publishes.iter().any(|p| p.path == path) {
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        "File is already being published".to_owned(),
                    );
                    return iced::Task::none();
                }

                // Create a new publish item with necessary state.
                let progress = Arc::new(RwLock::new(0.));
                let publish = PublishItem::new(path.clone(), progress.clone());
                let cancellation_token = publish.cancellation_token.clone();
                let nonce = publish.nonce;
                publishes.push(publish);

                if cfg!(debug_assertions) && !is_nonce_sorted(publishes) {
                    tracing::error!("Publishes not sorted by nonce after adding new publish");
                    sort_nonce(publishes);
                }

                (progress, cancellation_token, nonce, path)
            }

            // If an existing publish is requested, find it by nonce.
            CreateOrExistingPublish::Existing(nonce) => {
                let publish = binary_find_nonce_mut(publishes, nonce);
                if let Some((_, publish)) = publish {
                    let progress = Arc::new(RwLock::new(0.));
                    publish.state = PublishState::Hashing(progress.clone());
                    (
                        progress,
                        publish.cancellation_token.clone(),
                        nonce,
                        publish.path.clone(),
                    )
                } else {
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        "Publish chosen for unknown item".to_owned(),
                    );
                    return iced::Task::none();
                }
            }
        };

        hash_publish_task(nonce, path, cancellation_token, progress)
    }

    /// Take a file and hash info and create a new publish request.
    #[tracing::instrument(skip(self))]
    fn update_publish_file_hashed(
        &mut self,
        publish: CreateOrExistingPublish,
        hash: HashBytes,
        file_size: u64,
        new_hash: bool,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            server,
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Publish file hashed while not connected");
            return iced::Task::none();
        };

        // Ensure we don't publish the same file twice.
        // TODO: Also check for duplicate hashes in existing publishes which have had their hash computed.
        if let CreateOrExistingPublish::Create(p) = &publish {
            if publishes.iter().any(|pi| {
                if pi.path.as_ref().eq(p.as_ref()) {
                    // Duplicate file path.
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        PUBLISH_PATH_EXISTS.to_owned(),
                    );
                    true
                } else if pi
                    .state
                    .hash_and_file_size()
                    .is_some_and(|(h, _)| h == hash)
                {
                    // Duplicate file hash.
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        format!(
                            "Already publishing hash {hash} for {}",
                            pi.path.to_string_lossy()
                        ),
                    );
                    true
                } else {
                    false
                }
            }) {
                return iced::Task::none();
            }
        }

        let saving_hash = new_hash && file_size > 1_000_000_000; // If the file is larger than 1GB, save the hash to disk.
        if saving_hash {
            // Before saving the new hash to disk, create `last_publishes`.
            self.options.last_publishes = if let CreateOrExistingPublish::Existing(nonce) = publish
            {
                publishes
                    .iter()
                    .filter_map(|p| {
                        // If the publish item already exists, do not include it in the saved list yet.
                        // We will add it later with the correct hash and file size.
                        if p.nonce == nonce {
                            None
                        } else {
                            Some(SavedPublish::from(p))
                        }
                    })
                    .collect()
            } else {
                publishes.iter().map(SavedPublish::from).collect()
            };
        }

        let (nonce, cancellation_token, path) = match publish {
            CreateOrExistingPublish::Create(path) => {
                let publish = PublishItem::new(path, Arc::new(RwLock::new(1.)));
                let cancellation_token = publish.cancellation_token.clone();
                let nonce = publish.nonce;
                publishes.push(publish);

                if cfg!(debug_assertions) && !is_nonce_sorted(publishes) {
                    tracing::error!("Publishes not sorted by nonce after adding new publish");
                    sort_nonce(publishes);
                }

                // Since we have added a new publish, make them the current view.
                *transfer_view = TransferView::Publishes;

                (nonce, cancellation_token, &publishes.last().unwrap().path)
            }

            CreateOrExistingPublish::Existing(nonce) => {
                let publish = binary_find_nonce(publishes, nonce);
                if let Some((_, publish)) = publish {
                    (nonce, publish.cancellation_token.clone(), &publish.path)
                } else {
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        "Publish file hashed for unknown item".to_owned(),
                    );
                    return iced::Task::none();
                }
            }
        };

        if saving_hash {
            tracing::info!("File is larger than 1GB, saving hash to disk early");

            // Append the new publish to the list of last publishes.
            self.options.last_publishes.push(SavedPublish::new(
                path.as_ref().clone(),
                Some((hash, file_size)),
            ));

            if let Err(e) = save_settings(&self.options) {
                log_status_change::<LogErrorStatus>(
                    &mut self.status_manager,
                    format!("Failed to save settings: {e}"),
                );
                self.save_on_exit = true;
            } else {
                tracing::debug!("Settings saved after hashing file");
                self.save_on_exit = false;
            }
        } else if new_hash {
            // Mark that the change in publishes needs to be saved.
            self.save_on_exit = true;
        }

        let server = server.clone();
        iced::Task::perform(
            async move {
                tracing::debug!("Attempting to publish file");
                tokio::select! {
                    // Allow cancelling the publish request thread.
                    () = cancellation_token.cancelled() => PublishRequestResult::Cancelled,

                    r = async move {
                        // Create a memory buffer with sufficient capacity for the publish request.
                        let bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

                        // Create a bi-directional stream to the server for this publish request.
                        match crate::core::publish(&server, bb, hash, file_size).await {
                            Ok(b) => PublishRequestResult::Success(IncomingPublishSession::new(b, hash, file_size)),
                            Err(e) => PublishRequestResult::Failure(Arc::new(e.into())),
                        }
                    } => r,
                }
            }.instrument(tracing::info_span!("Publish request to server", %hash)),
            move |r| Message::PublishRequestResulted(nonce, r),
        )
    }

    /// Update after the server has accepted a publish request, or there was an error.
    #[tracing::instrument(skip(self, result))]
    fn update_publish_request_resulted(
        &mut self,
        nonce: Nonce,
        result: PublishRequestResult,
    ) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            match (result, binary_find_nonce_mut(publishes, nonce)) {
                (
                    PublishRequestResult::Success(IncomingPublishSession {
                        server_streams,
                        hash,
                        file_size,
                    }),
                    Some((_, publish)),
                ) => {
                    tracing::info!("Publish request succeeded for {hash}");
                    publish.state = PublishState::Publishing(Publish {
                        server_streams,
                        hash,
                        hash_hex: hash.to_string(),
                        file_size,
                        human_readable_size: humanize_bytes(file_size),
                    });
                }
                (PublishRequestResult::Failure(e), Some((_, publish))) => {
                    tracing::error!("Publish request failed: {e}");
                    publish.state = PublishState::Failure(e, publish.state.hash_and_file_size());
                }
                (PublishRequestResult::Cancelled, Some((_, publish))) => {
                    tracing::debug!("Publish request cancelled");
                    publish.state = PublishState::Cancelled(publish.state.hash_and_file_size());
                }
                (_, None) => {
                    tracing::warn!("Publish request resulted with an unknown nonce");
                }
            }
        }
        iced::Task::none()
    }

    /// Update after the server has sent a peer to publish to, or there was an error.
    #[tracing::instrument(skip(self, result))]
    fn update_publish_peer_received(
        &mut self,
        nonce: Nonce,
        result: Result<SocketAddr, Arc<ReadSubscribingPeerError>>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            publishes,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Peer received while not connected");
            return iced::Task::none();
        };

        let publish = binary_find_nonce(publishes, nonce).and_then(|(_, p)| {
            if let PublishState::Publishing(publishing) = &p.state {
                Some(publishing.clone())
            } else {
                None
            }
        });
        match (result, publish) {
            // Attempt a new request stream from an existing or new peer connection.
            (Ok(peer), Some(publish)) => {
                if cfg!(debug_assertions) {
                    tracing::debug!("Received peer {peer} for publish {}", &publish.hash);
                } else {
                    tracing::debug!("Received peer for publish {}", &publish.hash);
                }

                let data = if let Some(c) = ConnectionsManager::instance().get_connection_sync(peer)
                {
                    if cfg!(debug_assertions) {
                        tracing::debug!("Reusing connection to peer {peer}");
                    } else {
                        tracing::debug!("Reusing connection to peer");
                    }
                    PeerConnectionOrTarget::Connection(c)
                } else {
                    if cfg!(debug_assertions) {
                        tracing::debug!("Creating new connection to peer {peer}");
                    } else {
                        tracing::debug!("Creating new connection to peer");
                    }
                    PeerConnectionOrTarget::Target(endpoint.clone(), peer)
                };
                let hash = publish.hash;
                iced::Task::perform(
                    try_peer_connection(data, hash, FileYeetCommandType::Pub),
                    move |r| Message::PublishPeerConnectResulted(nonce, r),
                )
            }

            // An error occurred while receiving the peer address.
            (Err(e), _) => {
                tracing::warn!("Error receiving peer: {e}");
                iced::Task::none()
            }

            // No publish item matching the nonce was found.
            (_, None) => {
                tracing::warn!("Peer received for unknown publish nonce {nonce}");
                iced::Task::none()
            }
        }
    }

    /// Update after a connection attempt to a peer for publishing has completed.
    #[tracing::instrument(skip(self, peer))]
    fn update_publish_peer_connect_resulted(
        &mut self,
        pub_nonce: Nonce,
        peer: Option<PeerRequestStream>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers,
            uploads,
            publishes,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Publish peer connect resulted while not connected");
            return iced::Task::none();
        };
        let Some(peer) = peer else {
            tracing::debug!("Peer connection attempt failed for publish nonce {pub_nonce}");
            return iced::Task::none();
        };

        let Some((publishing, path)) =
            binary_find_nonce(publishes, pub_nonce).and_then(|(_, pi)| {
                if let PublishState::Publishing(p) = &pi.state {
                    Some((p, pi.path.clone()))
                } else {
                    None
                }
            })
        else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "Peer connected for unknown publish item".to_owned(),
            );
            return iced::Task::none();
        };

        let upload_nonce = generate_nonce();
        let progress_lock = Arc::new(RwLock::new(0));
        let cancellation_token = CancellationToken::new();
        let peer_string = peer.connection.remote_address().to_string();
        let requested_size = Arc::new(RwLock::new(None));
        uploads.push(UploadTransfer {
            base: TransferBase {
                nonce: upload_nonce,
                hash: publishing.hash,
                hash_hex: publishing.hash.to_string(),
                file_size: publishing.file_size,
                path: path.clone(),
                cancellation_token: cancellation_token.clone(),
            },
            peer_string,
            progress: UploadState::Transferring {
                peer: peer.connection.clone(),
                progress_lock: progress_lock.clone(),
                progress_animation: 0.,
                requested_size: requested_size.clone(),
                snapshot: TransferSnapshot::new(),
            },
        });

        if cfg!(debug_assertions) && !is_nonce_sorted(uploads) {
            tracing::error!("Uploads not sorted by nonce after adding new upload");
            sort_nonce(uploads);
        }

        insert_nonce_for_peer(peer.connection.remote_address(), peers, upload_nonce);

        let file_size = publishing.file_size;
        iced::Task::perform(
            async move {
                let file = match tokio::fs::File::open(path.as_ref()).await {
                    Ok(f) => f,
                    Err(e) => {
                        return UploadResult::Failure(Arc::new(format!(
                            "Failed to open the file: {e}"
                        )))
                    }
                };

                // Try to upload the file to the peer connection.
                let mut streams = peer.bistream.lock().await;

                let (start_index, upload_length) =
                    match crate::core::read_publish_range(&mut streams, file_size).await {
                        Ok(range) => range,
                        Err(e) => {
                            return UploadResult::Failure(Arc::new(format!(
                                "Failed to read peer upload range: {e}"
                            )));
                        }
                    };
                if let Some(l) = NonZeroU64::new(upload_length) {
                    requested_size.write().await.replace(l);
                } else {
                    tracing::info!("The requested upload size is zero, skipping upload");
                    return UploadResult::Success((start_index)..(start_index + upload_length), 0);
                }

                // Prepare a reader for the file to upload.
                let reader = tokio::io::BufReader::new(file);

                tokio::select! {
                    () = cancellation_token.cancelled() => UploadResult::Cancelled,
                    result = Box::pin(crate::core::upload_to_peer(
                        &mut streams,
                        start_index,
                        upload_length,
                        reader,
                        Some(&progress_lock),
                    )) => match result {
                        Ok(()) => UploadResult::Success((start_index)..(start_index + upload_length), 0),
                        Err(e) => UploadResult::Failure(Arc::new(format!("Upload failed: {e}"))),
                    }
                }
            },
            move |r| Message::UploadTransferResulted(upload_nonce, r),
        )
    }

    /// Handle the subscribe button being clicked by prompting to choose a save location.
    #[tracing::instrument(skip(self))]
    fn update_subscribe_started(&mut self) -> iced::Task<Message> {
        // Clear the status message before starting the subscribe attempt.
        self.clear_status_message();

        // Let state know that a modal dialog is open.
        self.modal = true;

        let (hash_hex, extension) =
            if let ConnectionState::Connected(ConnectedState { hash_input, .. }) =
                &self.connection_state
            {
                let Some(p) = HASH_EXT_REGEX.captures(hash_input).and_then(|captures| {
                    let Some(hash) = captures.name("hash").map(|h| h.as_str().to_string()) else {
                        tracing::error!(
                            "Subscribe started but unable to match `hash` capture group"
                        );
                        return None;
                    };
                    let extension = captures.name("ext").map(|e| e.as_str().to_string());
                    Some((hash, extension))
                }) else {
                    tracing::warn!("Subscribe started with invalid hash input");
                    return iced::Task::none();
                };
                p
            } else {
                tracing::warn!("Subscribe started while not in the connected state");
                return iced::Task::none();
            };

        let mut builder = rfd::AsyncFileDialog::new().set_title("Choose a file path to save to");
        if let Some(extension) = extension {
            builder = builder.add_filter(extension.clone(), &[extension]);
        }

        iced::Task::perform(builder.save_file(), move |f| {
            Message::SubscribePathChosen(f.map(PathBuf::from), hash_hex)
        })
    }

    /// Update the state after the publish button was clicked. Begins a subscribe request.
    #[tracing::instrument(skip(self))]
    fn update_subscribe_path_chosen(
        &mut self,
        path: Option<PathBuf>,
        hash_hex: &str,
    ) -> iced::Task<Message> {
        self.modal = false;

        // Ensure a path was chosen, otherwise safely cancel.
        let Some(path) = path else {
            return iced::Task::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            server,
            external_address,
            downloads,
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Subscribe path chosen while not connected");
            return iced::Task::none();
        };

        // Ensure there are no downloads or publishes using this path.
        // TODO: Use `HashSet`s to more efficiently track these file paths.
        if downloads.iter().any(|d| path.eq(d.base.path.as_ref())) {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "Download using this path already exists".to_owned(),
            );
            return iced::Task::none();
        }
        if publishes.iter().any(|p| &path == p.path.as_ref()) {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                PUBLISH_PATH_EXISTS.to_owned(),
            );
            return iced::Task::none();
        }

        // Ensure the hash is valid.
        let mut hash = HashBytes::default();
        if let Err(e) = faster_hex::hex_decode(hash_hex.as_bytes(), &mut hash.bytes) {
            log_status_change::<LogErrorStatus>(
                &mut self.status_manager,
                format!("Failed to decode matched hash: {e}"),
            );
            return iced::Task::none();
        }

        // Ensure the transfer view is set to downloads to see the new item.
        *transfer_view = TransferView::Downloads;

        let server = server.clone();
        let external_address = external_address.0;
        iced::Task::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::subscribe(&server, &mut bb, hash, Some(external_address))
                    .await
                    .map(|publishing_peers| {
                        IncomingSubscribePeers::new(publishing_peers, path, hash)
                    })
                    .map_err(Arc::new)
            },
            Message::SubscribePeersResult,
        )
    }

    /// Update the state after loading a download from the last session.
    #[tracing::instrument(skip(self))]
    fn update_subscribe_recreated(&mut self, saved_download: SavedDownload) -> iced::Task<Message> {
        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("Subscribe recreated while not connected");
            return iced::Task::none();
        };

        // Extract the saved download information.
        let (hash, file_size, path, saved_intervals) = {
            let SavedDownload {
                hash,
                file_size,
                path,
                intervals,
            } = saved_download;

            let intervals = if let Some(intervals) = intervals {
                // Recreate the file intervals from the saved ranges.
                let mut file_intervals = FileIntervals::new(file_size);
                for interval in intervals {
                    if let Err(e) = file_intervals.add_interval(interval) {
                        log_status_change::<LogErrorStatus>(
                            &mut self.status_manager,
                            format!("Failed to recover partial download {hash}: {e}"),
                        );
                        return iced::Task::none();
                    }
                }
                Some(file_intervals)
            } else {
                None
            };

            (hash, file_size, path, intervals)
        };

        // Get a unique nonce for this download.
        let nonce = generate_nonce();

        downloads.push(DownloadTransfer {
            base: TransferBase {
                nonce,
                hash,
                hash_hex: hash.to_string(),
                file_size,
                path: Arc::new(path),
                cancellation_token: CancellationToken::new(),
            },
            progress: DownloadState::Paused(saved_intervals),
            publish_on_success: false,
        });

        if cfg!(debug_assertions) && !is_nonce_sorted(downloads) {
            tracing::error!("Downloads not sorted by nonce after adding new download");
            sort_nonce(downloads);
        }

        iced::Task::done(Message::ResumePausedDownload(nonce))
    }

    /// Update after server has responded to a subscribe request.
    #[tracing::instrument(skip_all)]
    fn update_subscribe_peers_result(
        &mut self,
        result: Result<IncomingSubscribePeers, Arc<SubscribeError>>,
    ) -> iced::Task<Message> {
        match result {
            Ok(IncomingSubscribePeers {
                peers_with_size,
                path,
                hash,
            }) => {
                let ConnectionState::Connected(ConnectedState {
                    endpoint,
                    downloads,
                    ..
                }) = &mut self.connection_state
                else {
                    tracing::warn!("Subscribe peers result while not connected");
                    return iced::Task::none();
                };

                if peers_with_size.is_empty() {
                    // Let the user know why nothing else is happening.
                    log_status_change::<LogWarnStatus>(
                        &mut self.status_manager,
                        format!("No peers available for {hash}"),
                    );
                    return iced::Task::none();
                }
                let hash_hex = faster_hex::hex_string(&hash.bytes);
                let path = Arc::new(path);

                // Group peers by file size.
                let peers_by_size = group_peers_by_size(peers_with_size);

                // Create a new transfer state and connection attempt for each peer.
                let transfers_commands_iter =
                    peers_by_size.into_iter().map(|(file_size, peers)| {
                        // Create a nonce to identify the transfer.
                        let nonce = generate_nonce();
                        let cancellation_token = CancellationToken::new();

                        // New download state for this request.
                        let transfer = DownloadTransfer {
                            base: TransferBase {
                                nonce,
                                hash,
                                hash_hex: hash_hex.clone(),
                                file_size,
                                path: path.clone(),
                                cancellation_token: cancellation_token.clone(),
                            },
                            progress: DownloadState::Connecting,
                            publish_on_success: false,
                        };

                        // New connection attempt for this peer with result command identified by the nonce.
                        let task = {
                            iced::Task::perform(
                                open_download_streams(endpoint, hash, peers, &cancellation_token)
                                    .map(std::iter::Iterator::collect),
                                move |peers| Message::SubscribePeerConnectResulted(nonce, peers),
                            )
                        };

                        // Return the pair to be separated later.
                        (transfer, task)
                    });

                // Create a new transfer for each peer.
                let (mut new_transfers, connect_commands): (
                    Vec<DownloadTransfer>,
                    Vec<iced::Task<Message>>,
                ) = transfers_commands_iter.unzip();

                // Add the new transfers to the list of active transfers.
                downloads.append(&mut new_transfers);

                if cfg!(debug_assertions) && !is_nonce_sorted(downloads) {
                    tracing::error!("Downloads not sorted by nonce after adding new downloads");
                    sort_nonce(downloads);
                }

                iced::Task::batch(connect_commands)
            }
            Err(e) => {
                log_status_change::<LogErrorStatus>(
                    &mut self.status_manager,
                    format!("Error subscribing to the server: {e}"),
                );
                iced::Task::none()
            }
        }
    }

    /// Update the download state after connect attempts resulted with the given peers.
    #[tracing::instrument(skip(self, result))]
    fn update_subscribe_connect_resulted(
        &mut self,
        nonce: Nonce,
        mut result: Vec<PeerRequestStream>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Subscribe connect resulted while not connected");
            return iced::Task::none();
        };

        // Find the transfer with the matching nonce.
        let Some((index, transfer)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "Subscribe connect resulted for unknown item".to_owned(),
            );
            return iced::Task::none();
        };

        // Update the state of the transfer with the result.
        for peer_request in &result {
            insert_nonce_for_peer(peer_request.connection.remote_address(), peers, nonce);
        }

        if let Some(p) = result.pop() {
            // Promise to update with a non-empty list of peers.
            let peers = nonempty::NonEmpty::from((p, result));

            // Update the transfer to await the user's confirmation.
            transfer.progress = DownloadState::Consent(peers);
        } else {
            // Remove this download entry since no connections are available.
            downloads.remove(index);
        }
        iced::Task::none()
    }

    /// Tell the peer to send the file and begin receiving and writing the file.
    #[tracing::instrument(skip(self))]
    fn update_accept_download(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to accept download");
            return iced::Task::none();
        };

        // Get the current transfer status.
        let Some((_, transfer)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogErrorStatus>(
                &mut self.status_manager,
                "No transfer found to accept download".to_owned(),
            );
            return iced::Task::none();
        };

        // Extract the progress and replace with a temporary state of connecting.
        let progress = std::mem::replace(&mut transfer.progress, DownloadState::Connecting);

        // Get necessary info for the download.
        let DownloadState::Consent(peer_streams) = progress else {
            log_status_change::<LogErrorStatus>(
                &mut self.status_manager,
                "Transfer is not in consent state".to_owned(),
            );

            // Revert the progress state back since we cannot proceed.
            transfer.progress = progress;

            return iced::Task::none();
        };
        let hash = transfer.base.hash;
        let file_size = transfer.base.file_size;
        let output_path = transfer.base.path.clone();

        let task = if peer_streams.tail.is_empty() {
            // Single peer download optimization.
            let peer_stream = peer_streams.head;

            // Set the transfer state for a single peer download.
            let byte_progress = Arc::new(RwLock::new(0));
            transfer.progress =
                DownloadState::new_transferring(DownloadStrategy::SinglePeer(DownloadSinglePeer {
                    peer_string: peer_stream.connection.remote_address().to_string(),
                    peer: peer_stream.connection.clone(),
                    progress_lock: byte_progress.clone(),
                }));
            let cancellation_token = transfer.base.cancellation_token.clone();

            // Download the full file from the peer.
            iced::Task::perform(
                full_download(
                    peer_stream,
                    cancellation_token,
                    byte_progress,
                    hash,
                    file_size,
                    output_path.clone(),
                ),
                move |r| Message::DownloadTransferResulted(nonce, r),
            )
        } else {
            // Set the transfer state for a multi-peer download.
            // We add all connections to the transfer state since these connections were already added  to the peers manager.
            let peers: HashMap<_, _> = peer_streams
                .iter()
                .map(|p| (p.connection.stable_id(), p.connection.clone()))
                .collect();
            let peers_string = DownloadMultiPeer::generate_peers_string(&peers);
            transfer.progress =
                DownloadState::new_transferring(DownloadStrategy::MultiPeer(DownloadMultiPeer {
                    peers,
                    peers_string,
                    intervals: FileIntervals::new(file_size),
                }));

            // Start by creating the output file with the necessary size.
            // This is to allow each concurrent chunk to write into the file at the correct position.
            let output_path = output_path.clone();
            iced::Task::perform(
                async move { create_sized_file(file_size, &output_path) },
                move |r| {
                    Message::PrepareMultiPeerDownloadResulted(
                        nonce,
                        r.map(|()| peer_streams).map_err(Arc::new),
                    )
                },
            )
        };

        // Remove all downloads to the same path when accepting this one.
        downloads.retain(|d| {
            if d.base.path == output_path
                && d.base.nonce != nonce
                && matches!(
                    d.progress,
                    DownloadState::Connecting | DownloadState::Consent(_)
                )
            {
                d.base.cancellation_token.cancel();
                false
            } else {
                true
            }
        });

        task
    }

    /// A download was rejected. Remove the transfer from the downloads list.
    #[tracing::instrument(skip(self))]
    fn update_reject_download(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to reject download");
            return iced::Task::none();
        };

        let download = {
            let Some(i) = downloads.iter().position(|d| d.base.nonce == nonce) else {
                tracing::warn!("No download found to reject");
                return iced::Task::none();
            };

            // Remove the download from the downloads list.
            downloads.remove(i)
        };

        // Cancel any ongoing download tasks.
        // There shouldn't be any, but it doesn't hurt and prevents such tasks from being created.
        download.base.cancellation_token.cancel();

        // Remove the nonce from the peer's transactions.
        for connection in download.progress.connections() {
            remove_nonce_for_peer(connection, peers, nonce);
        }

        // Log download rejection based on the current progress state.
        match &download.progress {
            DownloadState::Consent(_) => {}
            DownloadState::Transferring { .. } => {
                tracing::error!("Rejecting download that is transferring, this should not happen");
            }
            _ => tracing::warn!("Rejecting download that is not in expected state"),
        }

        // Attempt a graceful rejection of the download request in the background.
        iced::Task::future(async move {
            let DownloadState::Consent(r) = download.progress else {
                return;
            };

            // Reject the download request on all peer streams.
            let reject_futures = r.into_iter().map(|peer| async move {
                let mut bi_stream = peer.bistream.lock().await;
                if let Err(e) = crate::core::reject_download_request(&mut bi_stream).await {
                    tracing::debug!("Failed to reject download request: {e}");
                }
            });

            let _ = tokio::time::timeout(
                MAX_REJECT_TIMEOUT,
                futures_util::future::join_all(reject_futures),
            )
            .await;
        })
        .discard()
    }

    /// Copy a hash (and file extension) to the clipboard.
    #[tracing::instrument(skip(self))]
    fn update_copy_hash(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to copy hash");
            return iced::Task::none();
        };

        let Some((_, publish_item)) = binary_find_nonce(publishes, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No publish found with nonce to copy hash".to_owned(),
            );
            return iced::Task::none();
        };
        let PublishState::Publishing(Publish { hash_hex, .. }) = &publish_item.state else {
            tracing::warn!("Specified publish item is not in a publishing state");
            return iced::Task::none();
        };

        let copy_string =
            if let Some(extension) = publish_item.path.extension().and_then(OsStr::to_str) {
                format!("{hash_hex}:{extension}")
            } else {
                hash_hex.clone()
            };
        tracing::debug!("Copying hash '{copy_string}' to clipboard");
        iced::clipboard::write(copy_string)
    }

    #[tracing::instrument(skip(self))]
    fn update_rehash_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to rehash publish");
            return iced::Task::none();
        };

        let Some((_, publish)) = binary_find_nonce_mut(publishes, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No publish found with nonce to rehash".to_owned(),
            );
            return iced::Task::none();
        };

        let progress = Arc::new(RwLock::new(0.));
        tracing::debug!("Rehashing publish {}", publish.path.to_string_lossy());
        publish.state = PublishState::Hashing(progress.clone());
        publish.cancellation_token.cancel();
        publish.cancellation_token = CancellationToken::new();

        hash_publish_task(
            publish.nonce,
            publish.path.clone(),
            publish.cancellation_token.clone(),
            progress,
        )
    }

    /// Update the state after a publish was cancelled.
    #[tracing::instrument(skip(self))]
    fn update_cancel_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            if let Some((_, publish)) = binary_find_nonce_mut(publishes, nonce) {
                tracing::info!("Cancelling publish for {}", publish.path.to_string_lossy());
                publish.cancellation_token.cancel();
                publish.state = PublishState::Cancelled(publish.state.hash_and_file_size());
            } else {
                tracing::warn!("No publish found to cancel");
            }
        } else {
            tracing::warn!("No connected state to cancel publish");
        }
        iced::Task::none()
    }

    /// Update the state to retry a publish.
    #[tracing::instrument(skip(self))]
    fn update_retry_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to retry publish");
            return iced::Task::none();
        };
        let Some((_, publish)) = binary_find_nonce_mut(publishes, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No publish found with nonce to retry".to_owned(),
            );
            return iced::Task::none();
        };

        // Cancel the old publish task in case it's still running, somehow.
        publish.cancellation_token.cancel();
        publish.cancellation_token = CancellationToken::new();

        iced::Task::done(
            if let Some((hash, file_size)) = publish.state.hash_and_file_size() {
                Message::PublishFileHashed {
                    publish: CreateOrExistingPublish::Existing(publish.nonce),
                    hash,
                    file_size,
                    new_hash: false,
                }
            } else {
                Message::PublishChosenItem(CreateOrExistingPublish::Existing(publish.nonce))
            },
        )
    }

    /// Update the state to remove a publish.
    #[tracing::instrument(skip(self))]
    fn update_remove_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            if let Some(i) = publishes.iter().position(|p| p.nonce == nonce) {
                tracing::debug!("Removing publish item {i}");
                self.save_on_exit = true;

                // Cancel the publish task and remove.
                publishes[i].cancellation_token.cancel();
                publishes.remove(i);
            } else {
                tracing::warn!("No publish found to remove");
            }
        } else {
            tracing::warn!("No connected state to remove publish");
        }
        iced::Task::none()
    }

    /// Update the state after a transfer was cancelled or paused.
    //  TODO: Separate into dedicated functions for cancelling and pausing transfers. Can't pause uploads.
    #[tracing::instrument(skip(self))]
    fn update_cancel_or_pause(
        &mut self,
        nonce: Nonce,
        transfer_type: FileYeetCommandType,
        cancel_or_pause: CancelOrPause,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers,
            downloads,
            uploads,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to cancel transfer");
            return iced::Task::none();
        };

        match transfer_type {
            FileYeetCommandType::Sub => {
                binary_find_nonce_mut(downloads, nonce).map(|(_, t)| {
                    // Cancel the download's tasks.
                    t.base.cancellation_token.cancel();

                    match cancel_or_pause {
                        CancelOrPause::Cancel => {
                            tracing::debug!("Cancelled download {}", t.base.hash_hex);

                            // Mark the download as cancelled.
                            update_download_result(
                                &mut t.progress,
                                DownloadResult::Cancelled,
                                peers,
                                nonce,
                            );
                        }
                        CancelOrPause::Pause => {
                            tracing::debug!("Paused download {}", t.base.hash_hex);

                            // Default to no saved intervals.
                            let progress =
                                std::mem::replace(&mut t.progress, DownloadState::Paused(None));
                            let intervals = match progress {
                                // Retain existing paused intervals. This shouldn't happen ever.
                                DownloadState::Paused(intervals) => {
                                    tracing::error!("Download is already paused");
                                    intervals
                                }

                                // Get the currently saved intervals for this download.
                                DownloadState::Transferring(DownloadTransferringState {
                                    strategy:
                                        DownloadStrategy::MultiPeer(DownloadMultiPeer {
                                            intervals, ..
                                        }),
                                    ..
                                }) => intervals
                                    .convert_ranges(
                                        |r| {
                                            let start = r.start();
                                            start..start + *r.progress_lock.blocking_read()
                                        },
                                        merge_adjacent_ranges,
                                    )
                                    .map_or_else(
                                        |e| {
                                            tracing::error!(
                                                "Failed to convert multi-peer intervals: {e}"
                                            );
                                            None
                                        },
                                        Some,
                                    ),

                                // Already set the `Paused` intervals to `None`, return.
                                _ => return,
                            };
                            t.progress = DownloadState::Paused(intervals);
                        }
                    }
                })
            }
            FileYeetCommandType::Pub => {
                binary_find_nonce_mut(uploads, nonce).map(|(_, t)| {
                    // Cancel the upload's tasks.
                    t.base.cancellation_token.cancel();

                    match cancel_or_pause {
                        CancelOrPause::Cancel => {
                            tracing::debug!("Cancelled upload {}", t.base.hash_hex);

                            // Mark the upload as cancelled.
                            update_upload_result(
                                &mut t.progress,
                                UploadResult::Cancelled,
                                peers,
                                nonce,
                            );
                        }
                        CancelOrPause::Pause => {
                            tracing::error!(
                                "Unexpected attempt to pause an upload, only cancel is expected"
                            );
                        }
                    }
                })
            }
        }
        .unwrap_or_else(|| {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                format!("No transfer found to {cancel_or_pause:?}"),
            );
        });
        iced::Task::none()
    }

    /// Set the `publish_on_success` toggle for the given download.
    #[tracing::instrument(skip(self))]
    fn update_publish_on_success_toggle(
        &mut self,
        nonce: Nonce,
        publish_on_success: bool,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to update `publish_on_success` toggle");
            return iced::Task::none();
        };

        if let Some((_, download)) = binary_find_nonce_mut(downloads, nonce) {
            tracing::debug!("Setting `publish_on_success` for download to {publish_on_success}");
            download.publish_on_success = publish_on_success;
        } else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No download found to update toggle".to_owned(),
            );
        }
        iced::Task::none()
    }

    /// Update the state to resume a paused transfer.
    #[tracing::instrument(skip(self))]
    fn update_resume_paused(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            server,
            external_address,
            downloads,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to resume download");
            return iced::Task::none();
        };

        let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No download found to resume".to_owned(),
            );
            return iced::Task::none();
        };
        let endpoint = endpoint.clone();
        let server = server.clone();
        let external_address = external_address.0;
        let path = t.base.path.clone();
        let hash = t.base.hash;
        let final_file_size = t.base.file_size;

        let progress_lock = Arc::new(RwLock::new(0.));
        let paused_progress = std::mem::replace(
            &mut t.progress,
            DownloadState::HashingFile {
                progress_animation: 0.,
                progress: progress_lock.clone(),
            },
        );

        t.base.cancellation_token = CancellationToken::new();
        let cancellation_token = t.base.cancellation_token.clone();
        *transfer_view = TransferView::Downloads;

        let intervals = match paused_progress {
            DownloadState::Paused(intervals) => intervals,
            DownloadState::Done(DownloadResult::Failure(_, RecoverableState::Recoverable(i))) => i
                .map(|i| {
                    Arc::try_unwrap(i).unwrap_or_else(|arc| {
                        tracing::warn!("Failed to unwrap Arc for saved intervals");
                        (*arc).clone()
                    })
                }),
            _ => {
                tracing::warn!("Download is not in a paused state");
                None
            }
        };

        if let Some(intervals) = intervals {
            // Convert the saved progress into the download part ranges used during transfers.
            let Ok(intervals) =
                intervals.convert_ranges(DownloadPartRange::new_completed, intervals::never_merge)
            else {
                // This should never happen since the ranges are not changing during conversion.
                tracing::error!("Failed to convert saved intervals to download part ranges");
                return iced::Task::none();
            };

            // Set the download to use multi-peer strategy with the saved intervals.
            // The peers will be added once the connections are made.
            t.progress =
                DownloadState::new_transferring(DownloadStrategy::MultiPeer(DownloadMultiPeer {
                    peers: HashMap::new(),
                    peers_string: String::new(),
                    intervals,
                }));

            // Return a task to prepare the multi-peer download.
            // We don't need to create the file; in fact we get to reuse the existing progress.
            let future = async move {
                // Get the list of peers to resume the download from.
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                let peers =
                    match crate::core::subscribe(&server, &mut bb, hash, Some(external_address))
                        .await
                    {
                        Ok(peers) => peers,
                        Err(e) => {
                            // TODO: Handle no peers available to resume.
                            return Message::SaveFailedMultiPeerDownloadResume(
                                nonce,
                                Arc::new(format!("{e}")),
                            );
                        }
                    };

                let Some(peers) = group_peers_by_size(peers).remove(&final_file_size) else {
                    // TODO: Handle no peers with matching file size to resume.
                    return Message::SaveFailedMultiPeerDownloadResume(
                        nonce,
                        Arc::new("No reachable peers".into()),
                    );
                };

                if let Some(peers) = nonempty::NonEmpty::collect(
                    open_download_streams(&endpoint, hash, peers, &cancellation_token).await,
                ) {
                    Message::PrepareMultiPeerDownloadResulted(nonce, Ok(peers))
                } else {
                    Message::SaveFailedMultiPeerDownloadResume(
                        nonce,
                        Arc::new("No reachable peers".into()),
                    )
                }
            };
            return iced::Task::perform(future, std::convert::identity);
        }

        // Create a future to resume the download.
        let resume_future = async move {
            // Get the file size and digest state of the chosen file to publish.
            let (_, current_file_size, digest) = Box::pin(crate::core::file_size_and_hasher(
                &path,
                Some(&progress_lock),
            ))
            .await
            .map_err(|e| Some(Arc::new(format!("{e}"))))?;

            // Get the list of peers to resume the download from.
            let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
            let peers = crate::core::subscribe(&server, &mut bb, hash, Some(external_address))
                .await
                .map_err(|e| Some(Arc::new(format!("{e}"))))?;

            // Get a request stream to the peer to resume the download.
            // TODO: We should prefer resuming with multiple peers when available.
            let request = first_matching_download(&endpoint, &peers, hash, final_file_size)
                .await
                .ok_or(None)?;

            Ok((digest, current_file_size, request))
        };

        // Resume the transfer.
        iced::Task::perform(
            async move {
                tokio::select! {
                    // Allow cancelling the resume request.
                    () = cancellation_token.cancelled() => {
                        tracing::debug!("Cancelling the resume request");
                        Err(Some(Arc::new("Cancelled".to_owned())))
                    }

                    // Await the resume request to complete.
                    result = resume_future => result,
                }
            },
            move |r| Message::ResumeFromPartialHashFile(nonce, r),
        )
    }

    /// Update the state after a resume partial hash has resulted.
    #[tracing::instrument(skip(self))]
    fn update_resume_partial_hash(
        &mut self,
        nonce: Nonce,
        result: Result<(Hasher, u64, PeerRequestStream), Option<Arc<String>>>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to resume partial hash");
            return iced::Task::none();
        };

        let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No download found to resume partial hash".to_owned(),
            );
            return iced::Task::none();
        };

        match result {
            // Resume the download with the partial hash
            Ok((digest, start_index, request)) => {
                let progress = Arc::new(RwLock::new(start_index));
                let mut download_transferring = DownloadTransferringState::new(
                    DownloadStrategy::SinglePeer(DownloadSinglePeer {
                        peer_string: request.connection.remote_address().to_string(),
                        peer: request.connection.clone(),
                        progress_lock: progress.clone(),
                    }),
                );

                // Resuming from partial file, update progress accordingly.
                download_transferring.progress_animation =
                    start_index as f32 / t.base.file_size as f32;

                t.progress = DownloadState::Transferring(download_transferring);
                let cancellation_token = t.base.cancellation_token.clone();
                let path = t.base.path.clone();
                let hash = t.base.hash;
                let file_size = t.base.file_size;

                // Insert nonce for resumed download. May already exist if resumed from this session.
                insert_nonce_for_peer(request.connection.remote_address(), peers, nonce);

                iced::Task::perform(
                    partial_download(
                        request,
                        cancellation_token,
                        progress,
                        hash,
                        start_index..file_size,
                        path,
                        Some(digest),
                    ),
                    move |r| Message::DownloadTransferResulted(nonce, r),
                )
            }

            // Failed to resume the download.
            Err(e) => {
                let e = if let Some(e) = e {
                    tracing::warn!("Failed to resume partial hash: {e}");
                    Arc::new(e.to_string())
                } else {
                    tracing::info!("Failed to connect to peer to resume partial hash");
                    Arc::new("No reachable peers".into())
                };

                // No file interval needs to be stored for synchronous download type.
                update_download_result(
                    &mut t.progress,
                    DownloadResult::Failure(e, RecoverableState::Recoverable(None)),
                    peers,
                    nonce,
                );

                iced::Task::none()
            }
        }
    }

    /// Update the state after a download transfer has concluded, successfully or not.
    #[tracing::instrument(skip(self, result))]
    fn update_download_resulted(
        &mut self,
        nonce: Nonce,
        result: DownloadResult,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to update transfer result");
            return iced::Task::none();
        };

        // Log a warning if the transfer failed.
        if let DownloadResult::Failure(e, _) = &result {
            tracing::warn!("Transfer failed: {e}");
        }

        if let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) {
            update_download_result(&mut t.progress, result, peers, nonce);

            if t.publish_on_success
                && matches!(t.progress, DownloadState::Done(DownloadResult::Success))
            {
                // Automatically publish the file after a successful download.
                tracing::debug!("Automatically publishing file after successful download");
                return iced::Task::done(Message::PublishFileHashed {
                    publish: CreateOrExistingPublish::Create(t.base.path.clone()),
                    hash: t.base.hash,
                    file_size: t.base.file_size,
                    new_hash: true,
                });
            }
        } else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No download found to update result".to_owned(),
            );
        }
        iced::Task::none()
    }

    /// Update the state after preparation for a multi-peer download has resulted.
    #[tracing::instrument(skip(self, result))]
    fn update_prepare_multi_peer_download_resulted(
        &mut self,
        nonce: Nonce,
        result: Result<nonempty::NonEmpty<PeerRequestStream>, Arc<std::io::Error>>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers: active_peers,
            downloads,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to update multi-peer download");
            return iced::Task::none();
        };

        let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No item found to prepare multi-peer download".to_owned(),
            );
            return iced::Task::none();
        };

        let peer_streams = match result {
            Ok(peer_streams) => peer_streams,

            Err(e) => {
                let err = format!("Failed to prepare output file: {e}");
                tracing::warn!("{err}");
                update_download_result(
                    &mut t.progress,
                    DownloadResult::Failure(Arc::new(err), RecoverableState::NonRecoverable),
                    active_peers,
                    nonce,
                );
                return iced::Task::none();
            }
        };

        // Get the intervals manager for this download.
        let DownloadState::Transferring(DownloadTransferringState {
            strategy:
                DownloadStrategy::MultiPeer(DownloadMultiPeer {
                    peers,
                    peers_string,
                    intervals,
                }),
            ..
        }) = &mut t.progress
        else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "Download not in multi-peer transferring state".to_owned(),
            );
            return iced::Task::none();
        };

        // Register all peers for this download.
        // TODO: Optionally add peers now (and insert nonce for active peers) or consider this already done.
        *peers = peer_streams
            .iter()
            .map(|p| {
                insert_nonce_for_peer(p.connection.remote_address(), active_peers, nonce);
                (p.connection.stable_id(), p.connection.clone())
            })
            .collect();
        *peers_string = DownloadMultiPeer::generate_peers_string(peers);

        let cancellation_token = t.base.cancellation_token.clone();
        let hash = t.base.hash;
        let output_path = t.base.path.clone();

        // * Attempt to split the download chunks among the available peers. This is to maximize
        //   concurrent utilization of all peers. Dividing by two allows faster peers to contribute more chunks.
        //
        // * If this division is smaller than the reasonable minimum, take that minimum instead.
        //   This is to prevent zero-size or extremely small chunks from being requested.
        let peer_share = u64::max(
            (t.base.file_size / peer_streams.len() as u64) / 2,
            DOWNLOAD_CHUNK_INTERVAL_MIN,
        );

        let tasks = peer_streams.into_iter().filter_map(|request| {
            let mut chunk = intervals.next_download_chunk()?;

            // Compare the chunk size to the fair peer share to promote each peer being utilized.
            if chunk.end - chunk.start > peer_share {
                chunk.end = chunk.start + peer_share;
            }

            let interval = DownloadPartRange::new(chunk.clone());
            let progress = interval.progress_lock.clone();
            if let Err(e) = intervals.add_interval(interval) {
                // Should never happen since we just got the chunk from `next_download_chunk`.
                // Log and treat as though no chunk is available.
                tracing::error!("Failed to add download interval: {e}");
                return None;
            }

            // Create a task which will seek to the correct position in the file and download the chunk.
            let stable_id = request.connection.stable_id();
            Some(iced::Task::perform(
                partial_download(
                    request,
                    cancellation_token.clone(),
                    progress,
                    hash,
                    chunk.clone(),
                    output_path.clone(),
                    None,
                ),
                move |r| {
                    Message::MultiPeerDownloadTransferResulted(nonce, chunk, stable_id, r.into())
                },
            ))
        });
        iced::Task::batch(tasks)
    }

    /// Update the state after a multi-peer download transfer chunk has concluded, successfully or not.
    #[tracing::instrument(skip(self, result))]
    fn update_multi_peer_download_transfer_resulted(
        &mut self,
        nonce: Nonce,
        old_range: std::ops::Range<u64>,
        connection_id: usize,
        result: MultiPeerDownloadResult,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers: active_peers,
            downloads,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to update multi-peer download transfer");
            return iced::Task::none();
        };

        let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No item found to update multi-peer download".to_owned(),
            );
            return iced::Task::none();
        };

        let DownloadState::Transferring(DownloadTransferringState {
            strategy:
                DownloadStrategy::MultiPeer(DownloadMultiPeer {
                    peers,
                    peers_string,
                    intervals,
                }),
            ..
        }) = &mut t.progress
        else {
            // Warn only if the download resulted in an unexpected state.
            // Having multiple cancelled tasks is expected.
            if !matches!(
                t.progress,
                DownloadState::Paused(_) | DownloadState::Done(_)
            ) && !matches!(
                result,
                MultiPeerDownloadResult::Cancelled | MultiPeerDownloadResult::Failure(_)
            ) {
                log_status_change::<LogWarnStatus>(
                    &mut self.status_manager,
                    "Download not in multi-peer transferring state".to_owned(),
                );
            }
            return iced::Task::none();
        };

        match result {
            MultiPeerDownloadResult::Success => {
                // Mark the interval as completed.
                if let Some(interval) = intervals.interval_at_mut(old_range.start) {
                    interval.completed = true;
                } else {
                    // TODO: Determine appropriate way to handle this error.
                    tracing::error!("Could not find interval to mark as completed for range");
                }

                if let Some(next_chunk) = intervals.next_download_chunk() {
                    // Use the same peer for the next chunk to naturally balance among peers.
                    let Some(peer) = peers.get(&connection_id).cloned() else {
                        // Should never happen since this peer just succeeded.
                        // Log and do not proceed with this chunk.
                        tracing::error!("Peer is not available for next download chunk");
                        return iced::Task::none();
                    };

                    let interval = DownloadPartRange::new(next_chunk.clone());
                    let progress = interval.progress_lock.clone();
                    if let Err(e) = intervals.add_interval(interval) {
                        // Should never happen since we just got the chunk from `next_download_chunk`.
                        // Log and do not proceed with this chunk.
                        tracing::error!("Failed to add download interval: {e}");
                        return iced::Task::none();
                    }

                    let hash = t.base.hash;
                    let cancellation_token = t.base.cancellation_token.clone();
                    let file_path = t.base.path.clone();
                    let next_chunk_clone = next_chunk.clone();

                    tracing::debug!("Create new task for next multi-peer download chunk: Next chunk {next_chunk:?}");
                    iced::Task::perform(
                        async move {
                            // Create a request stream to the peer.
                            let request = crate::core::peer_connection_into_stream(
                                &peer,
                                hash,
                                FileYeetCommandType::Sub,
                            )
                            .await;

                            let request = match request {
                                Ok(r) => PeerRequestStream::new(peer, r),
                                Err(e) => {
                                    tracing::error!(
                                        "Failed to create download request for multi-peer chunk: {e}"
                                    );
                                    return DownloadResult::Failure(
                                        Arc::new("Failed to create download request".to_owned()),
                                        RecoverableState::Recoverable(None),
                                    );
                                }
                            };

                            // Download the next chunk.
                            partial_download(
                                request,
                                cancellation_token,
                                progress,
                                hash,
                                next_chunk,
                                file_path,
                                None,
                            )
                            .await
                        }
                        .instrument(tracing::info_span!("multi_peer_download_next_chunk")),
                        move |r| {
                            Message::MultiPeerDownloadTransferResulted(
                                nonce,
                                next_chunk_clone,
                                connection_id,
                                r.into(),
                            )
                        },
                    )
                } else {
                    // Check if all intervals are complete.
                    if !intervals.ranges().iter().all(|r| r.completed) {
                        // There are still chunks continuing to download.
                        return iced::Task::none();
                    }
                    tracing::debug!("All multi-peer download chunks completed");

                    // Download is complete, verify the file hash.
                    let file_path = t.base.path.clone();
                    let file_hash = t.base.hash;
                    let file_size = t.base.file_size;
                    let progress = Arc::new(RwLock::new(0.));
                    t.progress = DownloadState::HashingFile {
                        progress_animation: 0.,
                        progress: progress.clone(),
                    };
                    iced::Task::perform(
                        async move {
                            match crate::core::file_size_and_hash(&file_path, Some(&progress)).await
                            {
                                Ok((calc_file_size, calc_file_hash)) => {
                                    if calc_file_hash == file_hash {
                                        if calc_file_size == file_size {
                                            tracing::info!(
                                                "Successful multi-peer download of hash {file_hash}"
                                            );
                                            DownloadResult::Success
                                        } else {
                                            let err = "File size does not match".to_owned();
                                            tracing::warn!("{err}");
                                            DownloadResult::Failure(
                                                Arc::new(err),
                                                RecoverableState::NonRecoverable,
                                            )
                                        }
                                    } else {
                                        let err = "File hash does not match".to_owned();
                                        tracing::warn!("{err}");
                                        DownloadResult::Failure(
                                            Arc::new(err),
                                            RecoverableState::NonRecoverable,
                                        )
                                    }
                                }
                                Err(e) => DownloadResult::Failure(
                                    Arc::new(format!("Failed to hash file: {e}")),
                                    RecoverableState::NonRecoverable,
                                ),
                            }
                        }
                        .instrument(tracing::info_span!("multi_peer_download_verify")),
                        move |r| Message::DownloadTransferResulted(nonce, r),
                    )
                }
            }

            MultiPeerDownloadResult::Failure(e) => {
                tracing::warn!("Multi-peer download chunk failed: {e}");

                // Remove this peer from the download since something has gone wrong.
                if let Some(connection) = peers.remove(&connection_id) {
                    remove_nonce_for_peer(&connection, active_peers, nonce);
                    // Update the peers_string to reflect the removal.
                    *peers_string = DownloadMultiPeer::generate_peers_string(peers);
                } else {
                    tracing::warn!("Failed to remove peer from multi-peer download after failure");
                }

                if peers.is_empty() {
                    // The download has failed when no peers are left to download from.
                    // Set a temporary interval to hold the progress before replacing it below.
                    let intervals =
                        std::mem::replace(intervals, FileIntervals::new(t.base.file_size));

                    // Convert the partial progress of the download.
                    let recovered_intervals = intervals.convert_ranges(
                        |r| {
                            let start = r.start();
                            start..start + *r.progress_lock.blocking_read()
                        },
                        merge_adjacent_ranges,
                    )
                    .map(|i| RecoverableState::Recoverable(Some(Arc::new(i))))
                    .map_err(|e| {
                        tracing::error!("Failed to convert multi-peer download intervals after failure: {e}");
                    })
                    .unwrap_or(RecoverableState::NonRecoverable);

                    // Set the download as failed with recoverable partial state.
                    let err = "No peers remaining to complete the download".to_owned();
                    tracing::warn!("{err}");
                    update_download_result(
                        &mut t.progress,
                        DownloadResult::Failure(err.into(), recovered_intervals),
                        active_peers,
                        nonce,
                    );
                } else {
                    // Remove the failed interval so it can be retried later.
                    if let Some(mut i) = intervals.remove_interval_at(old_range.start) {
                        let bytes_downloaded = *i.progress_lock.blocking_read();
                        if bytes_downloaded > 0 {
                            // Attempt to save the partial progress of the interval.
                            i.range.end = bytes_downloaded + i.start();
                            i.completed = true;
                            if let Err(e) = intervals.add_interval(i) {
                                // This should never happen since we just removed this interval.
                                // Log but do not give up on this download since the interval will be retried.
                                tracing::error!("Failed to re-add failed interval: {e}");
                            } else {
                                tracing::debug!("Retrying failed interval with partial progress");
                            }
                        } else {
                            tracing::debug!("Retrying failed interval with no progress");
                        }
                    } else {
                        tracing::warn!("Failed to remove interval after failure");
                    }
                }
                iced::Task::none()
            }

            // The multi-peer download was cancelled.
            MultiPeerDownloadResult::Cancelled => {
                tracing::info!("Multi-peer download chunk was cancelled");

                // Mark the entire download as cancelled
                // We verified above that the current state is `Transferring`.
                update_download_result(
                    &mut t.progress,
                    DownloadResult::Cancelled,
                    active_peers,
                    nonce,
                );
                iced::Task::none()
            }
        }
    }

    /// Update the state after a multi-peer download resume attempt has failed.
    /// We save progress if possible.
    fn update_save_failed_multi_peer_download_resume(
        &mut self,
        nonce: Nonce,
        error: Arc<String>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to update multi-peer download transfer");
            return iced::Task::none();
        };

        let Some((_, t)) = binary_find_nonce_mut(downloads, nonce) else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No item found to update multi-peer download".to_owned(),
            );
            return iced::Task::none();
        };

        let DownloadState::Transferring(DownloadTransferringState {
            strategy: DownloadStrategy::MultiPeer(DownloadMultiPeer { intervals, .. }),
            ..
        }) = &mut t.progress
        else {
            tracing::warn!("Download not in multi-peer transferring state");
            return iced::Task::none();
        };
        tracing::warn!("Multi-peer download failed: {error}");

        // Convert and save the current progress of the download intervals.
        let recovered_intervals = match std::mem::replace(
            intervals,
            FileIntervals::new(t.base.file_size),
        )
        .convert_ranges(
            |r| {
                let start = r.start();
                start..start + *r.progress_lock.blocking_read()
            },
            merge_adjacent_ranges,
        ) {
            // Saved download intervals.
            Ok(i) => RecoverableState::Recoverable(Some(Arc::new(i))),

            // Failed to convert saved intervals.
            Err(e) => {
                tracing::error!(
                    "Failed to convert multi-peer download intervals after download failure: {e}"
                );
                RecoverableState::NonRecoverable
            }
        };

        update_download_result(
            &mut t.progress,
            DownloadResult::Failure(error, recovered_intervals),
            peers,
            nonce,
        );
        iced::Task::none()
    }

    /// Update the state after an upload transfer has concluded, successfully or not.
    #[tracing::instrument(skip(self, result))]
    fn update_upload_resulted(
        &mut self,
        nonce: Nonce,
        result: UploadResult,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { peers, uploads, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to update transfer result");
            return iced::Task::none();
        };

        match &result {
            // Log a warning if the transfer failed.
            UploadResult::Failure(e) => tracing::warn!("Transfer failed: {e}"),

            // Remove successful uploads of partial-file ranges from the list.
            // TODO: Make a new type like `UploadResultDisplay` to avoid needing an aggregate param
            //       in the tupe here, which is always zero/unused. Other solution is to add the
            //       aggregate to the `UploadState::Done` variant.
            UploadResult::Success(r, _) => {
                let data = if let Some((index, t)) = binary_find_nonce(uploads, nonce) {
                    Some((index, t.base.hash, t.base.file_size, t.peer_string.clone()))
                } else {
                    None
                };
                if let Some((index, hash, file_size, peer_string)) = data {
                    // Look for another successful upload of the same file to this peer and
                    // aggregate the bytes shared.
                    for other_upload in uploads.iter_mut() {
                        let UploadState::Done(UploadResult::Success(_, aggregate)) =
                            &mut other_upload.progress
                        else {
                            continue;
                        };

                        if other_upload.base.hash == hash
                            && other_upload.base.file_size == file_size
                            && other_upload.peer_string == peer_string
                            && other_upload.base.nonce != nonce
                        {
                            // Add our successful range to the aggregate of the other upload.
                            *aggregate += r.end - r.start;

                            // Remove this upload entry.
                            uploads.remove(index);
                            return iced::Task::none();
                        }
                    }
                }
            }

            UploadResult::Cancelled => {}
        }

        if let Some((_, t)) = binary_find_nonce_mut(uploads, nonce) {
            update_upload_result(&mut t.progress, result, peers, nonce);
        } else {
            log_status_change::<LogWarnStatus>(
                &mut self.status_manager,
                "No upload found to update result".to_owned(),
            );
        }
        iced::Task::none()
    }

    /// Update the state after the user has chosen to remove a transfer entry.
    #[tracing::instrument(skip(self))]
    fn update_remove_from_transfers(
        &mut self,
        nonce: Nonce,
        transfer_type: FileYeetCommandType,
    ) -> iced::Task<Message> {
        fn remove_transfer<T: Transfer>(transfers: &mut Vec<T>, nonce: Nonce) {
            if let Some(i) = transfers.iter().position(|t| t.base().nonce == nonce) {
                transfers.remove(i);
            }
        }

        if let ConnectionState::Connected(ConnectedState {
            downloads, uploads, ..
        }) = &mut self.connection_state
        {
            tracing::debug!("Removing transfer");
            match transfer_type {
                FileYeetCommandType::Sub => remove_transfer(downloads, nonce),
                FileYeetCommandType::Pub => remove_transfer(uploads, nonce),
            }
        } else {
            tracing::warn!("No connected state to remove transfer");
        }
        iced::Task::none()
    }

    /// Try to safely close.
    #[tracing::instrument(skip(self))]
    fn safely_close(&mut self, close_type: CloseType) -> iced::Task<Message> {
        tracing::debug!("Safely leaving server");

        // If connected, close the connection and save the current state.
        if let ConnectionState::Connected(ConnectedState {
            endpoint,
            downloads,
            publishes,
            ..
        }) = &mut self.connection_state
        {
            self.options.last_publishes = publishes
                .drain(..)
                .map(|publish_item| {
                    // Ensure all publish tasks are cancelled.
                    publish_item.cancellation_token.cancel();

                    // If the publish is valid or in progress, add it to the list of open publishes.
                    publish_item.into()
                })
                .collect();

            self.options
                .last_downloads
                .extend(downloads.drain(..).filter_map(|d| {
                    // If the download is in progress, cancel it.
                    d.base.cancellation_token.cancel();

                    // Ensure all downloads that were in-progress are saved.
                    let intervals = match d.progress {
                        // States where no save progress is available or needed.
                        DownloadState::Transferring(DownloadTransferringState {
                            strategy: DownloadStrategy::SinglePeer(_),
                            ..
                        })
                        | DownloadState::HashingFile { .. } => None,

                        // States where saved intervals are available.
                        DownloadState::Paused(intervals) => intervals,
                        DownloadState::Done(DownloadResult::Failure(
                            _,
                            RecoverableState::Recoverable(intervals),
                        )) => intervals.map(|i| {
                            Arc::try_unwrap(i).unwrap_or_else(|arc| {
                                tracing::warn!("Failed to unwrap Arc for saved intervals");
                                (*arc).clone()
                            })
                        }),
                        DownloadState::Transferring(DownloadTransferringState {
                            strategy:
                                DownloadStrategy::MultiPeer(DownloadMultiPeer { intervals, .. }),
                            ..
                        }) => intervals
                            .convert_ranges(
                                |r| {
                                    let start = r.start();
                                    start..start + *r.progress_lock.blocking_read()
                                },
                                merge_adjacent_ranges,
                            )
                            .map_or_else(
                                |e| {
                                    tracing::error!("Failed to convert multi-peer intervals: {e}");
                                    None
                                },
                                Some,
                            ),

                        // In other cases, do not save the download.
                        _ => return None,
                    }
                    .map(FileIntervals::into_ranges);
                    Some(SavedDownload {
                        hash: d.base.hash,
                        file_size: d.base.file_size,
                        path: d.base.path.as_ref().clone(),
                        intervals,
                    })
                }));

            endpoint.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

            // Save the app settings if needed.
            if self.save_on_exit || !self.options.last_downloads.is_empty() {
                if let Err(e) = save_settings(&self.options) {
                    tracing::error!("Could not save settings: {e}");
                } else {
                    tracing::info!("Settings saved");
                }
            } else {
                tracing::debug!("No changes to settings, not saving");
            }
        }

        if let Some(port_mapping) = self.port_mapping.take() {
            // Set the state to `Stalling` before waiting for the safe close to complete.
            self.connection_state = ConnectionState::new_stalling();

            self.safely_closing = true;
            let port_mapping_timeout = Duration::from_millis(500);
            iced::Task::perform(
                tokio::time::timeout(port_mapping_timeout, async move {
                    if let Err((e, mapping)) = port_mapping.try_drop().await {
                        tracing::warn!(
                            "Could not safely remove port mapping: {e}: expires at {}",
                            crate::core::instant_to_datetime_string(mapping.expiration()),
                        );
                    } else {
                        tracing::info!("Port mapping safely removed");
                    }
                }),
                // Force the close operation after completing the request or after a timeout.
                move |_| match close_type {
                    CloseType::Application => Message::ForceExit,
                    CloseType::Connections => Message::LeftServer,
                },
            )
        } else {
            match close_type {
                // Immediately exit if there isn't a port mapping to remove.
                CloseType::Application => {
                    tracing::debug!("No work to do before exiting, closing now");
                    iced::exit()
                }

                // Close connections and return to the main screen.
                CloseType::Connections => {
                    tracing::debug!("Exiting connected view to main screen");
                    self.connection_state = ConnectionState::Disconnected;
                    iced::Task::none()
                }
            }
        }
    }

    /// Helper to clear the current status message.
    fn clear_status_message(&mut self) {
        // Save the old status message to history.
        if let Some(old_status) = self.status_manager.message.take() {
            self.status_manager.history.push_back(old_status);
        }
    }
}

/// Helper to use a binary search to find a nonce item in a sorted slice.
/// Returns the index and a reference to the item if found.
fn binary_find_nonce<T: NonceItem>(items: &[T], nonce: Nonce) -> Option<(usize, &T)> {
    items
        .binary_search_by_key(&nonce, T::nonce)
        .ok()
        .and_then(|idx| items.get(idx).map(|item| (idx, item)))
}

/// Helper to use a binary search to find a nonce item in a sorted slice.
/// Returns the index and a mutable reference to the item if found.
fn binary_find_nonce_mut<T: NonceItem>(items: &mut [T], nonce: Nonce) -> Option<(usize, &mut T)> {
    items
        .binary_search_by_key(&nonce, T::nonce)
        .ok()
        .and_then(|idx| items.get_mut(idx).map(|item| (idx, item)))
}

/// Helper to check if a slice of nonce items is sorted by nonce.
fn is_nonce_sorted<T: NonceItem>(items: &[T]) -> bool {
    items.is_sorted_by_key(T::nonce)
}

/// Helper to sort a slice by their nonce.
fn sort_nonce<T: NonceItem>(items: &mut [T]) {
    items.sort_by_key(T::nonce);
}

/// Helper for creating a horizontal line.
fn horizontal_line<'c>() -> iced::Element<'c, Message> {
    widget::rule::horizontal(3).into()
}

/// A trait to log status messages at different levels.
/// This avoids needing to `match` an enum each log status call.
trait LogStatusLevel {
    fn log_status(status: &str);
}
struct LogErrorStatus;
impl LogStatusLevel for LogErrorStatus {
    fn log_status(status: &str) {
        tracing::error!("{status}");
    }
}
struct LogWarnStatus;
impl LogStatusLevel for LogWarnStatus {
    fn log_status(status: &str) {
        tracing::warn!("{status}");
    }
}

/// Helper to log an error that we assign to the status message.
/// This helper assumes that the status string is non-empty.
#[inline]
fn log_status_change<L: LogStatusLevel>(status_manager: &mut StatusManager, status: String) {
    L::log_status(&status);

    // Save the old status message to history.
    if let Some(old_status) = status_manager.message.take() {
        status_manager.history.push_back(old_status);
    }

    status_manager.message = Some(status);
}

/// Helper to get a consistent horizontal scrollbar for text overflow.
fn text_horizontal_scrollbar() -> widget::scrollable::Direction {
    widget::scrollable::Direction::Horizontal(
        widget::scrollable::Scrollbar::new()
            .width(8)
            .scroller_width(8),
    )
}

/// Helper to create a timed tooltip.
fn timed_tooltip<'a, E>(
    element: E,
    tooltip_text: &'a str,
    elapsed: &Duration,
) -> Element<'a, Message>
where
    E: Into<Element<'a, Message>>,
{
    let element = element.into();
    if elapsed.gt(&TOOLTIP_WAIT_DURATION) {
        widget::tooltip(
            element,
            tooltip_text,
            widget::tooltip::Position::FollowCursor,
        )
        .style(widget::container::rounded_box)
        .into()
    } else {
        element
    }
}

/// Helper to group peers by their advertised file sizes.
fn group_peers_by_size<I: IntoIterator<Item = (SocketAddr, u64)>>(
    peers_with_size: I,
) -> HashMap<u64, nonempty::NonEmpty<SocketAddr>> {
    // Group peers by file size.
    let mut peers_by_size = HashMap::new();
    for (peer, size) in peers_with_size {
        peers_by_size
            .entry(size)
            .and_modify(|v: &mut nonempty::NonEmpty<_>| v.push(peer))
            .or_insert_with(|| nonempty::nonempty![peer]);
    }

    peers_by_size
}

/// Helper to connect to multiple peers for a specific hash and collect the successful streams.
#[tracing::instrument(skip(endpoint, peers, cancellation_token))]
fn open_download_streams(
    endpoint: &quinn::Endpoint,
    hash: HashBytes,
    peers: nonempty::NonEmpty<SocketAddr>,
    cancellation_token: &CancellationToken,
) -> impl std::future::Future<Output = impl std::iter::Iterator<Item = PeerRequestStream>> {
    // Create a new connection or open a stream on an existing one.
    let futures = peers.into_iter().map(|peer| {
        let cancellation_token = cancellation_token.clone();
        let endpoint = endpoint.clone();

        // The future to use to create the connection.
        async move {
            let peer = if let Some(c) = ConnectionsManager::instance()
                .get_connection_async(peer)
                .await
            {
                if cfg!(debug_assertions) {
                    tracing::debug!("Reusing connection to peer {peer}");
                } else {
                    tracing::debug!("Reusing connection to peer");
                }
                PeerConnectionOrTarget::Connection(c)
            } else {
                if cfg!(debug_assertions) {
                    tracing::debug!("Creating new connection to peer {peer}");
                } else {
                    tracing::debug!("Creating new connection to peer");
                }
                PeerConnectionOrTarget::Target(endpoint, peer)
            };
            tokio::select! {
                // Allow cancelling the connection attempt.
                () = cancellation_token.cancelled() => None,

                r = try_peer_connection(peer, hash, FileYeetCommandType::Sub) => r,
            }
        }
    });

    // Join all the connection attempts for this hash/size into a single future.
    futures_util::future::join_all(futures).then(async |results| results.into_iter().flatten())
}

/// Helper to connect to peer publishing a known hash and file size.
#[tracing::instrument(skip(endpoint, peers_with_size))]
async fn first_matching_download(
    endpoint: &quinn::Endpoint,
    peers_with_size: &[(SocketAddr, u64)],
    hash: HashBytes,
    expected_size: u64,
) -> Option<PeerRequestStream> {
    // Filter the peers to find those with the expected file size.
    let filtered_peers = peers_with_size
        .iter()
        .filter_map(|(peer, file_size)| file_size.eq(&expected_size).then_some(*peer));

    for peer in filtered_peers {
        // Create a new connection or open a stream on an existing one.
        let peer = if let Some(c) = ConnectionsManager::instance()
            .get_connection_async(peer)
            .await
        {
            if cfg!(debug_assertions) {
                tracing::debug!("Reusing connection to peer {peer}");
            } else {
                tracing::debug!("Reusing connection to peer");
            }
            PeerConnectionOrTarget::Connection(c)
        } else {
            if cfg!(debug_assertions) {
                tracing::debug!("Creating new connection to peer {peer}");
            } else {
                tracing::debug!("Creating new connection to peer");
            }
            PeerConnectionOrTarget::Target(endpoint.clone(), peer)
        };

        // Attempt to connect to the peer.
        let r = try_peer_connection(peer, hash, FileYeetCommandType::Sub).await;

        // Return the first successful connection.
        if r.is_some() {
            return r;
        }
    }

    // No matching peer found.
    None
}

/// Either an existing peer connection or a local endpoint and peer address to connect to.
enum PeerConnectionOrTarget {
    /// An existing peer connection.
    Connection(quinn::Connection),

    /// A local endpoint and peer address to connect to.
    Target(quinn::Endpoint, SocketAddr),
}

/// Helper to get a `Task` to hash a file and return the file size and hash.
#[tracing::instrument(skip(cancellation, progress))]
fn hash_publish_task(
    nonce: Nonce,
    path: Arc<PathBuf>,
    cancellation: CancellationToken,
    progress: Arc<RwLock<f32>>,
) -> iced::Task<Message> {
    iced::Task::perform(
        async move {
            tracing::info!("Determine the file size and hash for publish");
            tokio::select! {
                // Allow cancelling the publish request thread.
                () = cancellation.cancelled() => Err(PublishRequestResult::Cancelled),

                // Get the file size and hash of the chosen file to publish.
                r = crate::core::file_size_and_hash(&path, Some(&progress)) => r.map_err(|e| {
                    PublishRequestResult::Failure(Arc::new(e.into()))
                })
            }
        },
        move |r| match r {
            Err(r) => Message::PublishRequestResulted(nonce, r),
            Ok((file_size, hash)) => Message::PublishFileHashed {
                publish: CreateOrExistingPublish::Existing(nonce),
                hash,
                file_size,
                new_hash: true, // Indicate that this hash was freshly calculated.
            },
        },
    )
}

/// Try to establish a peer connection for a command type.
/// Either starts from an existing connection or attempts to holepunch.
#[tracing::instrument(skip(peer))]
async fn try_peer_connection(
    peer: PeerConnectionOrTarget,
    hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Option<PeerRequestStream> {
    use PeerConnectionOrTarget::{Connection, Target};
    tokio::time::timeout(PEER_CONNECT_TIMEOUT, async move {
        match peer {
            Connection(c) => match peer_connection_into_stream(&c, hash, cmd).await {
                Ok(s) => Some((c, s)),
                Err(e) => {
                    tracing::error!("Failed to open stream on existing connection: {e}");
                    None
                }
            },

            Target(e, peer) => udp_holepunch(cmd, hash, e, peer).await,
        }
        .map(PeerRequestStream::from)
    })
    .await
    .ok()
    .flatten()
}

/// Helper to perform a synchronous download of an entire file from a single peer.
/// The file at `output_path` will be created (or truncated) before downloading.
#[tracing::instrument(skip(peer_stream, cancellation_token, byte_progress, output_path))]
async fn full_download(
    peer_stream: PeerRequestStream,
    cancellation_token: CancellationToken,
    byte_progress: Arc<RwLock<u64>>,
    hash: HashBytes,
    file_size: u64,
    output_path: Arc<PathBuf>,
) -> DownloadResult {
    let mut peer_stream_lock = peer_stream.bistream.lock().await;

    tokio::select! {
        // Let the transfer be cancelled. This is not an error if cancelled.
        () = cancellation_token.cancelled() => DownloadResult::Cancelled,

        // Await the file to be downloaded.
        result = crate::core::download_from_peer(
            hash,
            &mut peer_stream_lock,
            file_size,
            &output_path,
            Some(&byte_progress),
        ) => {
            match result {
                Ok(()) => DownloadResult::Success,
                Err(e) => {
                    let recoverable = if e.is_recoverable() {
                        // No file interval needs to be stored for synchronous download type.
                        RecoverableState::Recoverable(None)
                    } else {
                        RecoverableState::NonRecoverable
                    };
                    DownloadResult::Failure(Arc::new(format!("Download failed: {e}")), recoverable)
                }
            }
        }
    }
}

/// Helper to create an output file with the desired size.
/// The work is synchronous, but is not guaranteed to be fast.
#[tracing::instrument()]
fn create_sized_file(file_size: u64, output_path: &std::path::Path) -> Result<(), std::io::Error> {
    let file = std::fs::File::create(output_path)?;
    file.set_len(file_size)?;
    tracing::debug!("Created output file with size");
    Ok(())
}

/// Helper to perform a partial download from a single peer.
/// The `output_path` must already exist and be writable.
#[tracing::instrument(skip(peer_stream, cancellation_token, byte_progress, output_path))]
async fn partial_download(
    peer_stream: PeerRequestStream,
    cancellation_token: CancellationToken,
    byte_progress: Arc<RwLock<u64>>,
    hash: HashBytes,
    file_range: std::ops::Range<u64>,
    output_path: Arc<PathBuf>,
    hasher: Option<Hasher>,
) -> DownloadResult {
    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .open(output_path.as_ref())
        .await
    {
        Ok(f) => f,
        Err(e) => {
            return DownloadResult::Failure(
                Arc::new(format!("Failed to open the file: {e}")),
                RecoverableState::Recoverable(None),
            )
        }
    };

    // Try to upload the file to the peer connection.
    let mut request = peer_stream.bistream.lock().await;
    tokio::select! {
        () = cancellation_token.cancelled() => DownloadResult::Cancelled,

        result = Box::pin(crate::core::download_partial_from_peer(
            hash,
            &mut request,
            &mut file,
            crate::core::DownloadOffsetState::new(file_range, hasher),
            Some(&byte_progress),
        )) => match result {
            Ok(()) => DownloadResult::Success,
            Err(e) => {
                let recoverable = if e.is_recoverable() {
                    // No file interval needs to be stored for synchronous download type.
                    RecoverableState::Recoverable(None)
                } else {
                    RecoverableState::NonRecoverable
                };
                DownloadResult::Failure(Arc::new(format!("Download failed: {e}")), recoverable)
            },
        }
    }
}

/// Add the nonce of a transaction to a peer's set of known transactions.
fn insert_nonce_for_peer(
    peer_address: SocketAddr,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    match peers.entry(peer_address) {
        hash_map::Entry::Vacant(e) => {
            // Add the peer into our map of known peer addresses.
            e.insert(HashSet::from([nonce]));
        }
        hash_map::Entry::Occupied(mut e) => {
            // Add the transfer nonce to the peer's set of known transfer nonces.
            e.get_mut().insert(nonce);
        }
    }
}

/// Remove the nonce of a transaction from a peer's set of known transactions.
#[tracing::instrument(skip(peer, peers))]
fn remove_nonce_for_peer(
    peer: &quinn::Connection,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    let peer_address = peer.remote_address();
    if let hash_map::Entry::Occupied(mut e) = peers.entry(peer_address) {
        let nonces = e.get_mut();
        if !nonces.remove(&nonce) {
            if cfg!(debug_assertions) {
                tracing::warn!("Nonce was not found for peer {peer_address}");
            } else {
                tracing::warn!("Nonce was not found for peer");
            }
        } else if cfg!(debug_assertions) {
            tracing::debug!("Removed nonce for peer {peer_address}");
        } else {
            tracing::debug!("Removed nonce for peer");
        }

        // If there are no more streams to the peer, close the connection.
        if nonces.is_empty() {
            let connection = peer.stable_id();
            if cfg!(debug_assertions) {
                tracing::debug!("Closing peer {peer_address} connection {connection}");
            } else {
                tracing::debug!("Closing peer connection {connection}");
            }

            // Locally close the connection. The request loop for this connection will handle any cleanup.
            peer.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

            // Remove the peer from our map of known peer addresses.
            e.remove();
        }
    } else if cfg!(debug_assertions) {
        tracing::warn!("Peer {peer_address} not found in peers map");
    } else {
        tracing::warn!("Peer not found in peers map");
    }
}

/// Either close all connections or the entire application.
#[derive(Clone, Copy, Debug)]
enum CloseType {
    Connections,
    Application,
}

const INVALID_PORT_FORWARD: &str = "Invalid port forward. Defaults to no port mappings";
const PUBLISH_PATH_EXISTS: &str = "Publish using this path already exists";
