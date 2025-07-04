use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    net::SocketAddr,
    num::NonZeroU16,
    ops::Div as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::{
    BiStream, ExpectedSocketError, HashBytes, DEFAULT_PORT, GOODBYE_CODE, GOODBYE_MESSAGE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use iced::{widget, window, Element};
use tokio::{io::AsyncWriteExt as _, sync::RwLock};
use tokio_util::sync::CancellationToken;

use crate::{
    core::{
        humanize_bytes, peer_connection_into_stream, udp_holepunch, ConnectionsManager,
        FileAccessError, FileYeetCommandType, PortMappingConfig, PrepareConnectionError,
        PreparedConnection, ReadSubscribingPeerError, SubscribeError, HASH_EXT_REGEX,
        MAX_PEER_COMMUNICATION_SIZE, PEER_CONNECT_TIMEOUT, SERVER_CONNECTION_TIMEOUT,
    },
    settings::{
        load_settings, save_settings, AppSettings, PortMappingSetting, SavedDownload, SavedPublish,
    },
};

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

/// The maximum time to wait before forcing the application to exit.
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The red used to display errors to the user.
const ERROR_RED_COLOR: iced::Color = iced::Color::from_rgb(1., 0.35, 0.45);

/// Font capable of rendering emojis.
pub static EMOJI_FONT: &[u8] = include_bytes!("../NotoEmoji-Regular.ttf");

/// The rate at which transfer speed text is updated.
const TRANSFER_SPEED_UPDATE_INTERVAL: Duration = Duration::from_millis(400);

/// The delay of mouse inactivity before showing tooltips.
const TOOLTIP_WAIT_DURATION: Duration = Duration::from_millis(400);

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

/// The result of a file transfer with a peer.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TransferResult {
    /// The transfer succeeded.
    #[error("Transfer succeeded")]
    Success,

    /// The transfer failed: {0}.
    #[error("{0}")]
    Failure(Arc<String>),

    /// The transfer was cancelled.
    #[error("Transfer cancelled")]
    Cancelled,
}

/// The progress of a file transfer at a moment in time.
#[derive(Clone, Debug)]
struct TransferSnapshot {
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

/// The state of a file transfer with a peer.
//  TODO: Separate progress enum for uploads and downloads. Consider using a trait if there is a
//        use case for sharing certain aspects.
#[derive(Debug)]
enum TransferState {
    /// The transfer is awaiting a connection attempt. Only used for downloads.
    Connecting,

    /// The transfer is awaiting user confirmation. Only used for downloads.
    Consent(PeerRequestStream),

    /// The transfer is in progress.
    Transferring {
        peer: quinn::Connection,
        progress_lock: Arc<RwLock<u64>>,
        progress_animation: f32,
        snapshot: TransferSnapshot,
    },

    /// The transfer has been paused. Only used for downloads.
    Paused(Option<SocketAddr>),

    /// Resuming a download by hashing the partial file. Only used for downloads.
    ResumingHash(Arc<RwLock<f32>>),

    /// The transfer has completed.
    Done(TransferResult),
}
impl TransferState {
    /// If the progress state contains a peer connection, return it.
    /// Otherwise, return `None`.
    pub fn connection(&self) -> Option<&quinn::Connection> {
        match self {
            // Connection in these states.
            TransferState::Consent(PeerRequestStream { connection, .. })
            | TransferState::Transferring {
                peer: connection, ..
            } => Some(connection),

            // No connection in remaining states.
            _ => None,
        }
    }
}

/// A file transfer with a peer in any state.
#[derive(Debug)]
struct Transfer {
    pub nonce: Nonce,
    pub hash: HashBytes,
    pub hash_hex: String,
    pub file_size: u64,
    pub peer_string: String,
    pub path: PathBuf,
    pub progress: TransferState,
    pub cancellation_token: CancellationToken,
}

/// The result of a file publish request.
#[derive(Debug, thiserror::Error)]
pub enum PublishFileFailure {
    #[error("{0}")]
    FileAccess(#[from] FileAccessError),

    #[error("{0}")]
    Publish(#[from] crate::core::PublishError),
}

#[derive(Clone, Debug)]
pub enum PublishRequestResult {
    Success(IncomingPublishSession),
    Failure(Arc<PublishFileFailure>),
    Cancelled,
}

/// A file actively being published to the server.
#[derive(Clone, Debug)]
struct Publish {
    pub server_streams: Arc<tokio::sync::Mutex<BiStream>>,
    pub hash: HashBytes,
    pub hash_hex: String,
    pub file_size: u64,
}

/// The information to create a new publish item, or the nonce of an existing one.
#[derive(Clone, Debug)]
pub enum NewOrExistingPublish {
    New(PathBuf),
    Existing(Nonce),
}

/// The state of a file publish request.
#[derive(Clone, Debug)]
enum PublishState {
    /// The file is being hashed, with progress given in the range [0., 1.].
    Hashing(Arc<RwLock<f32>>),

    /// The publish request is active.
    Publishing(Publish),

    /// The publish request has encountered an unrecoverable error.
    Failure(Arc<PublishFileFailure>),

    /// The publish request was cancelled by the user.
    Cancelled,
}

/// An item in the list of publishing requests.
#[derive(Clone, Debug)]
struct PublishItem {
    pub nonce: Nonce,
    pub path: PathBuf,
    pub cancellation_token: CancellationToken,
    pub state: PublishState,
}
impl PublishItem {
    /// Make a new publish item in the hashing state.
    pub fn new(path: PathBuf) -> Self {
        Self {
            nonce: rand::random(),
            path,
            cancellation_token: CancellationToken::new(),
            state: PublishState::Hashing(Arc::new(RwLock::new(0.))),
        }
    }

    /// Upgrade a hashing state to publishing.
    pub fn upgrade_hashing(
        &mut self,
        server_streams: Arc<tokio::sync::Mutex<BiStream>>,
        hash: HashBytes,
        file_size: u64,
    ) {
        self.state = PublishState::Publishing(Publish {
            server_streams,
            hash,
            hash_hex: hash.to_string(),
            file_size,
        });
    }
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
    downloads: Vec<Transfer>,

    /// List of file uploads to peers.
    uploads: Vec<Transfer>,

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

/// The state of the application for interacting with the GUI.
#[derive(Default)]
pub struct AppState {
    connection_state: ConnectionState,
    options: AppSettings,
    status_message: Option<String>,
    modal: bool,
    safely_closing: bool,
    port_mapping: Option<crab_nat::PortMapping>,
    main_window: Option<window::Id>,
    last_mouse_move: Option<Instant>,
}

/// The messages that can be sent to the update loop of the application.
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

    /// A connection to a peer has been disconnected.
    PeerDisconnected(SocketAddr),

    /// The transfer view radio buttons were changed.
    TransferViewChanged(TransferView),

    /// The hash input field was changed.
    HashInputChanged(String),

    /// The publish button was clicked.
    PublishClicked,

    /// The path to a file to publish was chosen or cancelled.
    PublishPathChosen(Option<PathBuf>),

    /// Hashing a file has completed.
    PublishFileHashed(NewOrExistingPublish, HashBytes, u64),

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
    SubscribePeerConnectResulted(Nonce, Option<PeerRequestStream>),

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

    /// Cancel or pause a transfer that is in-progress.
    CancelOrPauseTransfer(Nonce, FileYeetCommandType, CancelOrPause),

    /// The resume button was pressed for a paused download.
    ResumePausedDownload(Nonce, Option<SocketAddr>),

    /// A resume attempt to get a partial file hash completed.
    ResumeFromPartialHashFile(
        Nonce,
        Result<(sha2::Sha256, u64, PeerRequestStream), Option<Arc<anyhow::Error>>>,
    ),

    /// The result of a download attempt.
    TransferResulted(Nonce, TransferResult, FileYeetCommandType),

    /// Open the file containing using system defaults.
    OpenFile(PathBuf),

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
    pub fn new(args: crate::Cli) -> (Self, iced::Task<Message>) {
        let mut status_message = None;

        // Get base settings from the settings file, or default.
        // If there is an error, show the error message and use default settings.
        let mut settings = load_settings().unwrap_or_else(|e| {
            status_message = Some(format!("Failed to load settings: {e}"));
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
            if let Some(server_address) = server_address.filter(|s| !s.is_empty()) {
                settings.server_address = server_address;
                used_cli = true;
            }
            if let Some(gateway) = gateway.filter(|g| !g.is_empty()) {
                settings.gateway_address = Some(gateway);
                used_cli = true;
            }
            if let Some(port) = internal_port {
                settings.internal_port_text = port.to_string();
                used_cli = true;
            }
            if let Some(port) = external_port_override {
                settings.port_forwarding_text = port.to_string();
                settings.port_mapping = PortMappingSetting::PortForwarding(Some(port));
            } else if (!used_cli && matches!(settings.port_mapping, PortMappingSetting::None))
                || nat_map
            {
                // Default to enabling NAT-PMP/PCP if no port forwarding is set.
                // Average users may not know that this is usually the best option for them.
                settings.port_mapping = PortMappingSetting::TryPcpNatPmp;
            }
        }

        // Create the initial state with the settings.
        let mut initial_state = Self {
            options: settings,
            status_message,
            ..Self::default()
        };

        // Get the ID of the main window.
        let window_task = window::get_oldest().map(Message::MainWindowId);

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

    /// Get the application title text.
    pub const fn title() -> &'static str {
        crate::core::APP_TITLE
    }

    /// Update the application state based on a message.
    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            // Set the ID of the main window.
            Message::MainWindowId(id) => {
                self.main_window = id;
                iced::Task::none()
            }

            // Handle the server address being changed.
            Message::ServerAddressChanged(address) => {
                self.options.server_address = address;
                iced::Task::none()
            }

            Message::InternalPortTextChanged(text) => {
                self.options.internal_port_text = text;
                iced::Task::none()
            }
            Message::PortMappingRadioChanged(selection) => {
                self.update_port_radio_changed(selection)
            }
            Message::PortForwardTextChanged(text) => self.update_port_forward_text(text),
            Message::GatewayTextChanged(text) => self.update_gateway_text(text),
            Message::ConnectClicked => self.update_connect_clicked(),
            Message::AnimationTick => self.update_animation_tick(),
            Message::ConnectResulted(r) => self.update_connect_resulted(r),
            Message::PortMappingUpdated(mapping) => self.update_port_mapping(mapping),

            // Copy the connected server address to the clipboard.
            Message::CopyServer => iced::clipboard::write(self.options.server_address.clone()),

            Message::SafelyLeaveServer => self.safely_close(CloseType::Connections),

            // All async actions to leave a server have completed.
            Message::LeftServer => {
                self.safely_closing = false;
                self.connection_state = ConnectionState::Disconnected;
                iced::Task::none()
            }

            // A peer has requested a new transfer from an existing connection.
            Message::PeerRequestedTransfer((hash, peer_request)) => {
                self.update_peer_requested_transfer(hash, peer_request)
            }

            // A peer has disconnected from the endpoint. Remove them from our map.
            Message::PeerDisconnected(peer_addr) => {
                if let ConnectionState::Connected(ConnectedState { peers, .. }) =
                    &mut self.connection_state
                {
                    peers.remove(&peer_addr);
                    ConnectionsManager::instance().blocking_remove_peer(&peer_addr);
                }
                iced::Task::none()
            }

            // The transfer view radio buttons were changed.
            Message::TransferViewChanged(view) => {
                if let ConnectionState::Connected(connected_state) = &mut self.connection_state {
                    connected_state.transfer_view = view;
                }
                iced::Task::none()
            }

            // Handle the hash input being changed.
            Message::HashInputChanged(hash) => {
                if let ConnectionState::Connected(ConnectedState { hash_input, .. }) =
                    &mut self.connection_state
                {
                    *hash_input = hash;
                }
                iced::Task::none()
            }

            // Handle the publish button being clicked by picking a file to publish.
            Message::PublishClicked => {
                // Clear the status message before starting the publish attempt.
                self.status_message = None;

                // Let state know that a modal dialog is open.
                self.modal = true;

                iced::Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file to publish")
                        .pick_file(),
                    |f| Message::PublishPathChosen(f.map(PathBuf::from)),
                )
            }

            Message::PublishPathChosen(path) => self.update_publish_path_chosen(path),
            Message::PublishFileHashed(publish, hash, file_size) => {
                self.update_publish_file_hashed(publish, hash, file_size)
            }
            Message::PublishRequestResulted(nonce, r) => {
                self.update_publish_request_resulted(nonce, r)
            }
            Message::PublishPeerReceived(nonce, r) => self.update_publish_peer_received(nonce, r),
            Message::PublishPeerConnectResulted(pub_nonce, peer) => {
                self.update_publish_peer_connect_resulted(pub_nonce, peer)
            }
            Message::SubscribeStarted => self.update_subscribe_started(),
            Message::SubscribePathChosen(path, hash_hex) => {
                self.update_subscribe_path_chosen(path, hash_hex)
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
            Message::CancelOrPauseTransfer(nonce, transfer_type, cancel_or_pause) => {
                self.update_cancel_or_pause(nonce, transfer_type, cancel_or_pause)
            }
            Message::ResumePausedDownload(nonce, peer) => self.update_resume_paused(nonce, peer),
            Message::ResumeFromPartialHashFile(nonce, result) => {
                self.update_resume_partial_hash(nonce, result)
            }
            Message::TransferResulted(nonce, r, transfer_type) => {
                self.update_transfer_resulted(nonce, r, transfer_type)
            }

            // Handle a file being opened.
            Message::OpenFile(path) => {
                open::that(path).unwrap_or_else(|e| {
                    let e = format!("Failed to open file: {e}");
                    tracing::error!("{e}");
                    self.status_message = Some(e);
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

                    if self
                        .main_window
                        .expect("Main window not available at unhandled event")
                        != window
                        || self.safely_closing
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
            Message::ForceExit => iced::window::close(
                self.main_window
                    .expect("Main window not available at force exit"),
            ),
        }
    }

    /// Listen for events that should be translated into messages.
    #[tracing::instrument(skip(self))]
    pub fn subscription(&self) -> iced::Subscription<Message> {
        // Listen for runtime events that iced did not handle internally. Used for safe exit handling.
        fn unhandled_events() -> iced::Subscription<Message> {
            iced::event::listen_with(|event, status, window| match status {
                iced::event::Status::Ignored => Some(Message::UnhandledEvent(window, event)),
                iced::event::Status::Captured => None,
            })
        }

        // Listen for timing intervals to update animations.
        fn animation() -> iced::Subscription<Message> {
            iced::time::every(Duration::from_millis(35)).map(|_| Message::AnimationTick)
        }

        match &self.connection_state {
            // Listen for close events and animation ticks when connecting/stalling.
            ConnectionState::Stalling { .. } => {
                iced::Subscription::batch([unhandled_events(), animation()])
            }

            ConnectionState::Connected(ConnectedState {
                endpoint,
                external_address,
                publishes,
                ..
            }) => {
                let external_address = external_address.0;

                // Create a task to listen for incoming connections to our QUIC endpoint.
                let incoming_connections = {
                    let endpoint = endpoint.clone();
                    iced::Subscription::run_with_id(
                        0,
                        iced::stream::channel(4, move |_output| {
                            ConnectionsManager::manage_incoming_loop(endpoint)
                        }),
                    )
                };

                // Create a task to renew the port mapping in a loop.
                let port_mapping = self.port_mapping.clone().into_iter().map(|mut mapping| {
                    iced::Subscription::run_with_id(
                        1,
                        iced::stream::channel(2, move |mut output| async move {
                            let mut last_lifetime = mapping.lifetime() as u64;
                            let mut interval =
                                crate::core::new_renewal_interval(last_lifetime).await;
                            loop {
                                interval.tick().await;
                                match crate::core::renew_port_mapping(&mut mapping).await {
                                    Ok(changed) if changed => {
                                        if let Err(e) = output.try_send(
                                            Message::PortMappingUpdated(Some(mapping.clone())),
                                        ) {
                                            let e = e.into_send_error();
                                            tracing::error!(
                                                "Failed to send port mapping update: {e}"
                                            );
                                        }
                                        let lifetime = mapping.lifetime() as u64;
                                        if lifetime != last_lifetime {
                                            last_lifetime = lifetime;
                                            interval =
                                                crate::core::new_renewal_interval(lifetime).await;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to renew port mapping: {e}");
                                    }
                                    _ => {}
                                }
                            }
                        }),
                    )
                });

                // For each publish we listen to the server for new peers requesting the file.
                let pubs = publishes.iter().filter_map(|publish| {
                    // If the publish is still hashing, skip for now.
                    let PublishItem {
                        nonce,
                        cancellation_token,
                        state: PublishState::Publishing(publish),
                        ..
                    } = &publish
                    else {
                        return None;
                    };
                    let nonce = *nonce;
                    let cancellation_token = cancellation_token.clone();
                    let publish = publish.clone();

                    // Subscribe to the server for new peers to upload to.
                    Some(iced::Subscription::run_with_id(
                        nonce,
                        iced::stream::channel(8, move |output| {
                            peers_requesting_publish_loop(
                                publish,
                                nonce,
                                cancellation_token,
                                external_address,
                                output,
                            )
                        }),
                    ))
                });

                // Create a listener for each peer that may want a new request stream.
                let peer_requests =
                    ConnectionsManager::instance().filter_map(|(peer_addr, connection)| {
                        let crate::core::IncomingPeerState::Connected(connection) = connection
                        else {
                            return None;
                        };

                        let peer_addr = *peer_addr;
                        let connection = connection.clone();
                        Some(iced::Subscription::run_with_id(
                            peer_addr,
                            iced::stream::channel(8, move |output| {
                                connected_peer_request_loop(connection, peer_addr, output)
                            }),
                        ))
                    });

                // Batch all the listeners together.
                iced::Subscription::batch(
                    [unhandled_events(), animation(), incoming_connections]
                        .into_iter()
                        .chain(port_mapping)
                        .chain(pubs)
                        .chain(peer_requests),
                )
            }

            // Listen for application close events when disconnected.
            ConnectionState::Disconnected => unhandled_events(),
        }
    }

    /// Draw the application GUI.
    pub fn view(&self) -> Element<Message> {
        // Get the time since the last mouse movement.
        let mouse_move_elapsed = self
            .last_mouse_move
            .as_ref()
            .map(Instant::elapsed)
            .unwrap_or_default();

        // Create a different top-level page based on the connection state.
        let page: Element<Message> = match &self.connection_state {
            // Display a prompt for the server address when disconnected.
            ConnectionState::Disconnected => self.view_disconnected_page(),

            // Display a spinner while connecting/stalling.
            &ConnectionState::Stalling { start, tick } => {
                if self.safely_closing {
                    widget::column!(
                        Self::view_connecting_page(start, tick, MAX_SHUTDOWN_WAIT),
                        widget::text("Closing... Pressing close a second time will cancel safety operations.").size(24),
                        widget::vertical_space(),
                    ).align_x(iced::Alignment::Center).into()
                } else {
                    Self::view_connecting_page(start, tick, SERVER_CONNECTION_TIMEOUT)
                }
            }

            // Display the main application controls when connected.
            ConnectionState::Connected(connected_state) => {
                self.view_connected_page(connected_state, &mouse_move_elapsed)
            }
        };

        // Always display the status bar at the bottom.
        let status_bar = widget::container(if let Some(status_message) = &self.status_message {
            Element::from(
                widget::text(status_message)
                    .color(ERROR_RED_COLOR)
                    .width(iced::Length::Fill)
                    .height(iced::Length::Shrink),
            )
        } else {
            widget::horizontal_space().into()
        });
        widget::column!(page, status_bar).padding(6).into()
    }

    /// Prefer a dark theme.
    #[allow(clippy::unused_self)]
    pub fn theme(&self) -> iced::Theme {
        iced::Theme::Dark
    }

    /// Draw the disconnected page with a server address input and connect button.
    fn view_disconnected_page(&self) -> iced::Element<Message> {
        let mut server_address = widget::text_input(
            "Server address. E.g., localhost:7828",
            &self.options.server_address,
        );

        let mut connect_button = widget::button("Connect");
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
            connect_button = connect_button.on_press(Message::ConnectClicked);

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
            widget::row!(widget::text("Internal Port to Bind"), internal_port_text).spacing(12),
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
            widget::text("Gateway address:"),
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
                widget::vertical_space(),
                server_address,
                connect_button,
                widget::vertical_space().height(iced::Length::FillPortion(2)),
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
        // TODO: Update progress value on a timer. This is necessary because of how `iced` does
        // differencing on the state for redraws.
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
    fn draw_transfers<'a, I>(
        transfers: I,
        transfer_type: FileYeetCommandType,
        mouse_move_elapsed: &Duration,
    ) -> iced::Element<'a, Message>
    where
        I: IntoIterator<Item = &'a Transfer>,
    {
        widget::column(transfers.into_iter().map(|t| {
            // Try to get a transfer rate string or None.
            let rate = match &t.progress {
                TransferState::Transferring { snapshot, .. } => {
                    Some(snapshot.human_readable.clone())
                }
                _ => None,
            };

            let progress = match &t.progress {
                TransferState::Connecting => Element::from(widget::text("Connecting...")),

                TransferState::Consent(_) => widget::row!(
                    widget::text(format!(
                        "Accept download of size {}",
                        humanize_bytes(t.file_size)
                    ))
                    .width(iced::Length::Fill),
                    widget::button(widget::text("Accept").size(12))
                        .on_press(Message::AcceptDownload(t.nonce)),
                    widget::button(widget::text("Reject").size(12))
                        .on_press(Message::RejectDownload(t.nonce)),
                )
                .spacing(12)
                .into(),

                TransferState::Transferring {
                    progress_animation: p,
                    ..
                } => {
                    let widgets = [
                        widget::text("Transferring...").into(),
                        widget::progress_bar(0.0..=1., *p).height(24).into(),
                    ]
                    .into_iter()
                    .chain((transfer_type == FileYeetCommandType::Sub).then(|| {
                        widget::button(widget::text("Pause").size(12))
                            .on_press(Message::CancelOrPauseTransfer(
                                t.nonce,
                                transfer_type,
                                CancelOrPause::Pause,
                            ))
                            .into()
                    }))
                    .chain([widget::button(widget::text("Cancel").size(12))
                        .on_press(Message::CancelOrPauseTransfer(
                            t.nonce,
                            transfer_type,
                            CancelOrPause::Cancel,
                        ))
                        .into()]);
                    widget::row(widgets)
                        .spacing(6)
                        .align_y(iced::Alignment::Center)
                        .into()
                }

                TransferState::Paused(peer) => {
                    let cancel = widget::button(widget::text("Cancel").size(12)).on_press(
                        Message::CancelOrPauseTransfer(
                            t.nonce,
                            transfer_type,
                            CancelOrPause::Cancel,
                        ),
                    );
                    widget::row!(
                        "Transfer is paused",
                        widget::horizontal_space(),
                        widget::button(widget::text("Resume").size(12))
                            .on_press(Message::ResumePausedDownload(t.nonce, *peer)),
                        cancel,
                    )
                    .spacing(6)
                    .into()
                }

                TransferState::ResumingHash(progress_lock) => widget::row!(
                    widget::text("Resuming with partial hash..."),
                    widget::progress_bar(0.0..=1., *progress_lock.blocking_read()).height(24),
                    widget::button(widget::text("Cancel").size(12)).on_press(
                        Message::CancelOrPauseTransfer(
                            t.nonce,
                            transfer_type,
                            CancelOrPause::Cancel,
                        )
                    ),
                )
                .spacing(6)
                .into(),

                TransferState::Done(r) => {
                    let remove = timed_tooltip(
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::RemoveFromTransfers(t.nonce, transfer_type)),
                        "Remove from list, file is untouched",
                        mouse_move_elapsed,
                    );
                    let result_text = widget::text(r.to_string())
                        .width(iced::Length::Fill)
                        .color_maybe(match r {
                            TransferResult::Failure(_) => Some(ERROR_RED_COLOR),
                            _ => None,
                        });
                    widget::row!(
                        result_text,
                        if transfer_type == FileYeetCommandType::Sub
                            && matches!(r, TransferResult::Success)
                        {
                            Element::<Message>::from(
                                widget::row!(
                                    widget::button(widget::text("Open").size(12))
                                        .on_press(Message::OpenFile(t.path.clone())),
                                    remove
                                )
                                .spacing(12),
                            )
                        } else {
                            remove
                        },
                    )
                    .into()
                }
            };

            widget::container(widget::column!(
                progress,
                widget::row!(
                    widget::text(&t.hash_hex).size(12),
                    widget::horizontal_space(),
                    rate.map_or_else(
                        || widget::horizontal_space().into(),
                        |r| Element::from(widget::text(r).size(12)),
                    ),
                ),
                widget::row!(
                    widget::text(&t.peer_string).size(12),
                    widget::scrollable(
                        widget::text(t.path.to_string_lossy())
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
        }))
        .spacing(6)
        .into()
    }

    /// Draw the publishes view for the main connected page.
    fn draw_pubs<'a>(
        publishes: &'a [PublishItem],
        mouse_move_elapsed: &Duration,
    ) -> iced::Element<'a, Message> {
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
                                widget::progress_bar(0.0..=1., *progress.blocking_read())
                                    .height(12),
                            )
                            .spacing(6),
                            file_path_scrollable,
                        ),
                        widget::button(widget::text("Cancel").size(14))
                            .on_press(Message::CancelPublish(pi.nonce)),
                    ),

                    // Display a publish in the publishing state.
                    PublishState::Publishing(p) => widget::row!(
                        widget::column!(widget::text(&p.hash_hex).size(12), file_path_scrollable,),
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
                        timed_tooltip(
                            widget::button(widget::text("Rehash").size(14))
                                .on_press(Message::RehashPublish(pi.nonce)),
                            "Rehash the file, necessary if the file has changed",
                            mouse_move_elapsed,
                        ),
                        timed_tooltip(
                            widget::button(widget::text("Cancel").size(14))
                                .on_press(Message::CancelPublish(pi.nonce)),
                            "Stop accepting new uploads",
                            mouse_move_elapsed,
                        ),
                    ),

                    // Display a publish in the failure state.
                    PublishState::Failure(e) => widget::row!(
                        widget::column!(
                            widget::text(format!("Failed to publish: {e}")).color(ERROR_RED_COLOR),
                            file_path_scrollable,
                        )
                        .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),

                    // Display a publish that was intentionally cancelled.
                    PublishState::Cancelled => widget::row!(
                        widget::column!(widget::text("Cancelled"), file_path_scrollable,)
                            .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
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

    /// Draw the main application controls when connected to a server.
    fn view_connected_page<'a, 'b: 'a>(
        &'b self,
        connected_state: &'a ConnectedState,
        mouse_move_elapsed: &Duration,
    ) -> iced::Element<'a, Message> {
        /// Helper for creating a horizontal line.
        fn horizontal_line<'c>() -> iced::Element<'c, Message> {
            widget::horizontal_rule(3).into()
        }

        // Define the elements that we want to be modal aware first.
        let mut publish_button = widget::button("Publish");
        let mut download_button = widget::button("Download");
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
            "Download file with specified hash",
            mouse_move_elapsed,
        );
        let leave_server_button = timed_tooltip(
            leave_server_button,
            "Leave the server, cancels ongoing transfers",
            mouse_move_elapsed,
        );

        // Define a header exposing the server address we are connected to
        // and how the server sees us (our external IP address).
        let header = widget::row!(
            widget::text("Server address:"),
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
            widget::horizontal_space(),
            widget::text("Our External Address:"),
            widget::text(&connected_state.external_address.1),
        )
        .align_y(iced::alignment::Alignment::Center)
        .spacing(6);

        // Hash input and download button.
        let download_input = widget::row!(hash_text_input, download_button).spacing(6);

        // Radio buttons for choosing the transfer view.
        let transfer_view_choice = widget::row(
            std::iter::once(widget::text("View: ").into()).chain(TRANSFER_VIEWS.iter().map(|l| {
                widget::radio(
                    l.to_str(),
                    *l,
                    Some(connected_state.transfer_view),
                    Message::TransferViewChanged,
                )
                .size(18)
                .spacing(8)
                .into()
            })),
        )
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
                    (true, true) => iced::widget::Space::new(0, 0).into(),

                    // Only uploads are empty, show publishes.
                    (false, true) => {
                        Self::draw_pubs(&connected_state.publishes, mouse_move_elapsed)
                    }

                    // Only publishes are empty, show uploads.
                    (true, false) => Self::draw_transfers(
                        &connected_state.uploads,
                        FileYeetCommandType::Pub,
                        mouse_move_elapsed,
                    ),

                    // Show both publishes and uploads. Separate them with a line.
                    (false, false) => widget::column!(
                        Self::draw_pubs(&connected_state.publishes, mouse_move_elapsed),
                        horizontal_line(),
                        Self::draw_transfers(
                            &connected_state.uploads,
                            FileYeetCommandType::Pub,
                            mouse_move_elapsed
                        ),
                    )
                    .spacing(12)
                    .into(),
                }
            }

            // Create a list of download attempts.
            TransferView::Downloads => Self::draw_transfers(
                &connected_state.downloads,
                FileYeetCommandType::Sub,
                mouse_move_elapsed,
            ),
        };

        widget::container(
            widget::column!(
                header,
                horizontal_line(),
                widget::row!(
                    publish_button,
                    widget::Space::with_width(iced::Length::Fixed(10.)),
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
        .padding(12)
        .into()
    }

    /// Handle the port mapping radio button being changed.
    fn update_port_radio_changed(&mut self, selection: PortMappingSetting) -> iced::Task<Message> {
        self.options.port_mapping = match selection {
            PortMappingSetting::None => {
                self.status_message = None;
                PortMappingSetting::None
            }
            PortMappingSetting::PortForwarding(_) => PortMappingSetting::PortForwarding({
                let o = self
                    .options
                    .port_forwarding_text
                    .trim()
                    .parse::<NonZeroU16>()
                    .ok();
                if o.is_none() {
                    self.status_message = Some(INVALID_PORT_FORWARD.to_owned());
                }
                o
            }),
            PortMappingSetting::TryPcpNatPmp => {
                self.status_message = None;
                PortMappingSetting::TryPcpNatPmp
            }
        };
        iced::Task::none()
    }

    /// Update the state after the port forward text field was changed.
    fn update_port_forward_text(&mut self, text: String) -> iced::Task<Message> {
        self.options.port_forwarding_text = text;
        if let PortMappingSetting::PortForwarding(port) = &mut self.options.port_mapping {
            if let Ok(p) = self
                .options
                .port_forwarding_text
                .trim()
                .parse::<NonZeroU16>()
            {
                *port = Some(p);
                self.status_message = None;
            } else {
                *port = None;
                self.status_message = Some(INVALID_PORT_FORWARD.to_owned());
            }
        }
        iced::Task::none()
    }

    /// Update the state after the gateway text field was changed.
    fn update_gateway_text(&mut self, text: String) -> iced::Task<Message> {
        if text.trim().is_empty() {
            self.options.gateway_address = None;
        } else {
            self.options.gateway_address = Some(text);
        }
        iced::Task::none()
    }

    /// Update the state after the connect button was clicked.
    fn update_connect_clicked(&mut self) -> iced::Task<Message> {
        // Clear the status message before starting the connection attempt.
        self.status_message = None;

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
            self.status_message = Some("Invalid server address".to_owned());
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
                self.status_message = Some("Invalid internal port".to_owned());
                return iced::Task::none();
            }
        };

        tracing::info!("Trying connection to server {server_address}:{port}");

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
    fn update_animation_tick(&mut self) -> iced::Task<Message> {
        match &mut self.connection_state {
            // Update the spinner when connecting/stalling.
            ConnectionState::Stalling { tick, .. } => *tick = Instant::now(),

            // Update the progress of transfers when connected.
            ConnectionState::Connected(ConnectedState {
                downloads, uploads, ..
            }) => {
                for t in downloads.iter_mut().chain(uploads.iter_mut()) {
                    if let TransferState::Transferring {
                        progress_lock,
                        progress_animation,
                        snapshot,
                        ..
                    } = &mut t.progress
                    {
                        // Update the progress bar with the most recent value.
                        let bytes_transferred = *progress_lock.blocking_read();
                        *progress_animation = bytes_transferred as f32 / t.file_size as f32;

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
            }

            // Do nothing in other states.
            ConnectionState::Disconnected => {}
        }
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
                    let tasks = self
                        .options
                        .last_publishes
                        .drain(..)
                        .map(|mut p| {
                            let message = if let Some(hfs) = p.hash_and_file_size.take() {
                                Message::PublishFileHashed(
                                    NewOrExistingPublish::New(p.path),
                                    hfs.0,
                                    hfs.1,
                                )
                            } else {
                                Message::PublishPathChosen(Some(p.path))
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
                self.status_message = Some(format!("Error connecting: {e}"));
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

        self.update_publish_peer_connect_resulted(nonce, Some(peer_request))
    }

    /// Update the state after the publish button was clicked.
    /// Begins a publish request if a file was chosen.
    #[tracing::instrument(skip(self))]
    fn update_publish_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Task<Message> {
        self.modal = false;

        // Ensure a path was chosen, otherwise safely cancel.
        let Some(path) = path else {
            return iced::Task::none();
        };

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

        let publish = PublishItem::new(path.clone());
        let progress = if let PublishState::Hashing(p) = &publish.state {
            p.clone()
        } else {
            tracing::error!("Publish path chosen while not hashing");
            Arc::new(RwLock::new(0.))
        };
        let cancellation_token = publish.cancellation_token.clone();
        let nonce = publish.nonce;

        publishes.push(publish);
        iced::Task::perform(
            async move {
                tokio::select! {
                    // Allow cancelling the publish request thread.
                    () = cancellation_token.cancelled() => Err(PublishRequestResult::Cancelled),

                    // Get the file size and hash of the chosen file to publish.
                    r = crate::core::file_size_and_hash(&path, Some(&progress)) => match r {
                        Ok(p) => Ok(p),
                        Err(e) => {
                            Err(PublishRequestResult::Failure(Arc::new(e.into())))
                        }
                    }
                }
            },
            move |r| match r {
                Err(r) => Message::PublishRequestResulted(nonce, r),
                Ok((file_size, hash)) => Message::PublishFileHashed(
                    NewOrExistingPublish::Existing(nonce),
                    hash,
                    file_size,
                ),
            },
        )
    }

    /// Take a file and hash info and create a new publish request.
    #[tracing::instrument(skip(self, publish))]
    fn update_publish_file_hashed(
        &mut self,
        publish: NewOrExistingPublish,
        hash: HashBytes,
        file_size: u64,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            server, publishes, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Publish file hashed while not connected");
            return iced::Task::none();
        };

        let (nonce, cancellation_token) = match publish {
            NewOrExistingPublish::New(path) => {
                let publish = PublishItem::new(path.clone());
                let nonce = publish.nonce;
                let cancellation_token = publish.cancellation_token.clone();
                publishes.push(publish);
                (nonce, cancellation_token)
            }
            NewOrExistingPublish::Existing(nonce) => {
                let publish = publishes.iter_mut().find(|p| p.nonce == nonce);
                if let Some(publish) = publish {
                    (nonce, publish.cancellation_token.clone())
                } else {
                    tracing::warn!("Publish file hashed for unknown nonce {nonce}");
                    return iced::Task::none();
                }
            }
        };
        tracing::debug!("Attempting to publish file with known hash");

        let server = server.clone();
        iced::Task::perform(
            async move {
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
            },
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
            match (result, publishes.iter_mut().find(|p| p.nonce == nonce)) {
                (
                    PublishRequestResult::Success(IncomingPublishSession {
                        server_streams,
                        hash,
                        file_size,
                    }),
                    Some(publish),
                ) => {
                    tracing::debug!("Publish request succeeded");
                    publish.upgrade_hashing(server_streams, hash, file_size);
                }
                (PublishRequestResult::Failure(e), Some(publish)) => {
                    publish.state = PublishState::Failure(e);
                }
                (PublishRequestResult::Cancelled, Some(publish)) => {
                    publish.state = PublishState::Cancelled;
                }
                (_, None) => {
                    tracing::warn!("Publish request resulted with an unknown nonce");
                }
            }
        }
        iced::Task::none()
    }

    /// Update after the server has sent a peer to publish to, or there was an error.
    #[tracing::instrument(skip(self))]
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

        let publish = publishes.iter().find_map(|p| {
            if let PublishState::Publishing(publishing) = &p.state {
                if p.nonce == nonce {
                    Some(publishing.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        match (result, publish) {
            // Attempt a new request stream from an existing or new peer connection.
            (Ok(peer), Some(publish)) => {
                tracing::debug!("Received peer {peer} for publish {}", &publish.hash,);
                let data =
                    if let Some(c) = ConnectionsManager::instance().get_connection_sync(&peer) {
                        tracing::debug!("Reusing connection to peer {peer}");
                        PeerConnectionOrTarget::Connection(c)
                    } else {
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
    #[tracing::instrument(skip(self))]
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
            // Silently fail if the peer connection was not successful when publishing.
            return iced::Task::none();
        };

        let Some((publishing, path)) = publishes.iter().find_map(|pi| {
            if let PublishState::Publishing(p) = &pi.state {
                if pi.nonce == pub_nonce {
                    Some((p, pi.path.clone()))
                } else {
                    None
                }
            } else {
                None
            }
        }) else {
            tracing::warn!("Peer connected for unknown publish nonce {pub_nonce}");
            return iced::Task::none();
        };

        let upload_nonce = rand::random();
        let progress_lock = Arc::new(RwLock::new(0));
        let cancellation_token = CancellationToken::new();
        uploads.push(Transfer {
            nonce: upload_nonce,
            hash: publishing.hash,
            hash_hex: publishing.hash.to_string(),
            file_size: publishing.file_size,
            peer_string: peer.connection.remote_address().to_string(),
            path: path.clone(),
            progress: TransferState::Transferring {
                peer: peer.connection.clone(),
                progress_lock: progress_lock.clone(),
                progress_animation: 0.,
                snapshot: TransferSnapshot::new(),
            },
            cancellation_token: cancellation_token.clone(),
        });

        insert_nonce_for_peer(peer.connection.remote_address(), peers, upload_nonce);

        let file_size = publishing.file_size;
        iced::Task::perform(
            async move {
                let file = match tokio::fs::File::open(path).await {
                    Ok(f) => f,
                    Err(e) => {
                        return TransferResult::Failure(Arc::new(format!(
                            "Failed to open the file: {e}"
                        )))
                    }
                };

                // Prepare a reader for the file to upload.
                let reader = tokio::io::BufReader::new(file);

                // Try to upload the file to the peer connection.
                let mut streams = peer.bistream.lock().await;

                tokio::select! {
                    () = cancellation_token.cancelled() => TransferResult::Cancelled,
                    result = Box::pin(crate::core::upload_to_peer(
                        &mut streams,
                        file_size,
                        reader,
                        Some(&progress_lock),
                    )) => match result {
                        Ok(()) => TransferResult::Success,
                        Err(e) => TransferResult::Failure(Arc::new(format!("Upload failed: {e}"))),
                    }
                }
            },
            move |r| Message::TransferResulted(upload_nonce, r, FileYeetCommandType::Pub),
        )
    }

    /// Handle the subscribe button being clicked by prompting to choose a save location.
    #[tracing::instrument(skip(self))]
    fn update_subscribe_started(&mut self) -> iced::Task<Message> {
        // Clear the status message before starting the subscribe attempt.
        self.status_message = None;

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
            // TODO: https://github.com/iced-rs/iced/pull/2827 resolves need for `.clone()` here.
            Message::SubscribePathChosen(f.map(PathBuf::from), hash_hex.clone())
        })
    }

    /// Update the state after the publish button was clicked. Begins a subscribe request.
    #[tracing::instrument(skip(self))]
    fn update_subscribe_path_chosen(
        &mut self,
        path: Option<PathBuf>,
        hash_hex: String,
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
            uploads,
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Subscribe path chosen while not connected");
            return iced::Task::none();
        };

        // Ensure there are no active transfers using this path.
        // TODO: Use a `HashSet` to more efficiently track active file paths.
        if downloads
            .iter()
            .chain(uploads.iter())
            .any(|t| t.path == path && !matches!(t.progress, TransferState::Done(_)))
        {
            self.status_message = Some("Active transfer using this path already exists".to_owned());
            return iced::Task::none();
        }
        if publishes.iter().any(|p| {
            p.path == path && !matches!(p.state, PublishState::Failure(_) | PublishState::Cancelled)
        }) {
            self.status_message = Some("Active publish using this path already exists".to_owned());
            return iced::Task::none();
        }

        // Ensure the hash is valid.
        let mut hash = HashBytes::default();
        if let Err(e) = faster_hex::hex_decode(hash_hex.as_bytes(), &mut hash.bytes) {
            let error = format!("Failed to decode matched hash: {e}");
            tracing::error!("{error}");
            self.status_message = Some(error);
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
                    .map(|peers| IncomingSubscribePeers::new(peers, path, hash))
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

        let SavedDownload {
            hash,
            file_size,
            peer_socket,
            path,
        } = saved_download;
        let nonce = rand::random();
        downloads.push(Transfer {
            nonce,
            hash,
            hash_hex: saved_download.hash.to_string(),
            file_size,
            peer_string: String::new(),
            path: path.clone(),
            progress: TransferState::Paused(peer_socket),
            cancellation_token: CancellationToken::new(),
        });

        iced::Task::done(Message::ResumePausedDownload(nonce, peer_socket))
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
                    self.status_message = Some("No peers available".to_owned());
                    return iced::Task::none();
                }
                let hash_hex = faster_hex::hex_string(&hash.bytes);

                // Create a new transfer state and connection attempt for each peer.
                let transfers_commands_iter =
                    peers_with_size.into_iter().map(|(peer, file_size)| {
                        // Create a nonce to identify the transfer.
                        let nonce = rand::random();
                        let cancellation_token = CancellationToken::new();

                        // New transfer state for this request.
                        let transfer = Transfer {
                            nonce,
                            hash,
                            hash_hex: hash_hex.clone(),
                            file_size,
                            peer_string: peer.to_string(),
                            path: path.clone(),
                            progress: TransferState::Connecting,
                            cancellation_token: cancellation_token.clone(),
                        };

                        // New connection attempt for this peer with result command identified by the nonce.
                        let task = {
                            // Create a new connection or open a stream on an existing one.
                            let peer = if let Some(c) =
                                ConnectionsManager::instance().get_connection_sync(&peer)
                            {
                                tracing::debug!("Reusing connection to peer {peer}");
                                PeerConnectionOrTarget::Connection(c)
                            } else {
                                tracing::debug!("Creating new connection to peer {peer}");
                                PeerConnectionOrTarget::Target(endpoint.clone(), peer)
                            };

                            // The future to use to create the connection.
                            let future = async move {
                                tokio::select! {
                                    // Allow cancelling the connection attempt.
                                    () = cancellation_token.cancelled() => None,

                                    r = try_peer_connection(peer, hash, FileYeetCommandType::Sub) => r,
                                }
                            };
                            iced::Task::perform(future, move |r| {
                                Message::SubscribePeerConnectResulted(nonce, r)
                            })
                        };

                        // Return the pair to be separated later.
                        (transfer, task)
                    });

                // Create a new transfer for each peer.
                let (mut new_transfers, connect_commands): (
                    Vec<Transfer>,
                    Vec<iced::Task<Message>>,
                ) = transfers_commands_iter.unzip();

                // Add the new transfers to the list of active transfers.
                downloads.append(&mut new_transfers);
                iced::Task::batch(connect_commands)
            }
            Err(e) => {
                self.status_message = Some(format!("Error subscribing to the server: {e}"));
                iced::Task::none()
            }
        }
    }

    /// Update the state after a subscribe connection attempt to a peer completed.
    #[tracing::instrument(skip(self, result))]
    fn update_subscribe_connect_resulted(
        &mut self,
        nonce: Nonce,
        result: Option<PeerRequestStream>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("Subscribe connect resulted while not connected");
            return iced::Task::none();
        };

        // Find the transfer with the matching nonce.
        let Some((index, transfer)) = downloads
            .iter_mut()
            .enumerate()
            .find(|(_, t)| t.nonce == nonce)
        else {
            tracing::warn!("Subscribe connect resulted for unknown nonce");
            return iced::Task::none();
        };

        // Update the state of the transfer with the result.
        if let Some(peer_request) = result {
            insert_nonce_for_peer(peer_request.connection.remote_address(), peers, nonce);
            transfer.progress = TransferState::Consent(peer_request);
        } else {
            // Remove unreachable peers from view.
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
        let Some(transfer) = downloads.iter_mut().find(|t| t.nonce == nonce) else {
            tracing::warn!("No transfer found to accept download");
            return iced::Task::none();
        };
        let hash = transfer.hash;
        let file_size = transfer.file_size;
        let peer_streams = if let TransferState::Consent(p) = &mut transfer.progress {
            p.clone()
        } else {
            tracing::warn!("Transfer is not in consent state");
            return iced::Task::none();
        };

        // Begin the transfer.
        let byte_progress = Arc::new(RwLock::new(0));
        transfer.progress = TransferState::Transferring {
            peer: peer_streams.connection.clone(),
            progress_lock: byte_progress.clone(),
            progress_animation: 0.,
            snapshot: TransferSnapshot::new(),
        };
        let output_path = transfer.path.clone();
        let cancellation_token = transfer.cancellation_token.clone();
        let path = transfer.path.clone();

        // Remove all downloads to the same path when accepting this one.
        downloads.retain(|d| {
            if d.path != path
                || !matches!(
                    d.progress,
                    TransferState::Consent(_) | TransferState::Connecting
                )
                || d.nonce == nonce
            {
                true
            } else {
                d.cancellation_token.cancel();
                false
            }
        });

        iced::Task::perform(
            async move {
                let mut peer_streams_lock = peer_streams.bistream.lock().await;

                tokio::select! {
                    // Let the transfer be cancelled. This is not an error if cancelled.
                    () = cancellation_token.cancelled() => TransferResult::Cancelled,

                    // Await the file to be downloaded.
                    result = crate::core::download_from_peer(
                        hash,
                        &mut peer_streams_lock,
                        file_size,
                        &output_path,
                        Some(&byte_progress),
                    ) => {
                        match result {
                            Ok(()) => TransferResult::Success,
                            Err(e) => TransferResult::Failure(Arc::new(format!("Download failed: {e}"))),
                        }
                    }
                }
            },
            move |r| Message::TransferResulted(nonce, r, FileYeetCommandType::Sub),
        )
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
            let Some(i) = downloads.iter().position(|d| d.nonce == nonce) else {
                tracing::warn!("No download found to reject");
                return iced::Task::none();
            };

            // Remove the download from the downloads list.
            downloads.remove(i)
        };

        // Cancel any ongoing download tasks.
        // There shouldn't be any, but it doesn't hurt and prevents such tasks from being created.
        download.cancellation_token.cancel();

        // Remove the nonce from the peer's transactions.
        if let Some(connection) = download.progress.connection() {
            remove_nonce_for_peer(connection, peers, nonce);
        }

        // Log download rejection based on the current progress state.
        match &download.progress {
            TransferState::Consent(_) => {}
            TransferState::Transferring { .. } => {
                tracing::error!("Rejecting download that is transferring, this should not happen");
            }
            _ => tracing::warn!("Rejecting download that is not in expected state"),
        }

        // Attempt a graceful rejection of the download request in the background.
        iced::Task::future(async move {
            let TransferState::Consent(r) = download.progress else {
                return;
            };
            let mut bi_stream_lock = r.bistream.lock().await;
            let _ = crate::core::reject_download_request(&mut bi_stream_lock).await;
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

        let Some(publish_item) = publishes.iter().find(|p| p.nonce == nonce) else {
            tracing::warn!("No publish found with input nonce");
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

        if let Some(publish) = publishes.iter_mut().find(|p| p.nonce == nonce) {
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
        } else {
            tracing::warn!("No publish found to rehash");
            iced::Task::none()
        }
    }

    /// Update the state after a publish was cancelled.
    #[tracing::instrument(skip(self))]
    fn update_cancel_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            if let Some(i) = publishes.iter().position(|p| p.nonce == nonce) {
                // Cancel the publish task.
                publishes[i].cancellation_token.cancel();

                // Currently running hashing task, remove the publish from list.
                if !matches!(&publishes[i].state, PublishState::Hashing(_)) {
                    publishes.remove(i);
                }
            }
        } else {
            tracing::warn!("No connected state to cancel publish");
        }
        iced::Task::none()
    }

    /// Update the state after a transfer was cancelled or paused.
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

        let transfers = match transfer_type {
            FileYeetCommandType::Sub => downloads,
            FileYeetCommandType::Pub => uploads,
        };
        let Some(t) = transfers.iter_mut().find(|t| t.nonce == nonce) else {
            tracing::warn!("No transfer found to cancel or pause for nonce");
            return iced::Task::none();
        };
        // Cancel the transfer tasks.
        t.cancellation_token.cancel();

        match cancel_or_pause {
            CancelOrPause::Cancel => {
                tracing::debug!("Cancelled transfer {}", t.hash_hex);

                // If the transfer was connected to a peer, remove the nonce from transactions
                if let Some(connection) = t.progress.connection() {
                    remove_nonce_for_peer(connection, peers, nonce);
                }

                // Mark the transfer as cancelled.
                t.progress = TransferState::Done(TransferResult::Cancelled);
            }
            CancelOrPause::Pause => {
                tracing::debug!("Paused transfer {}", t.hash_hex);
                let peer = t
                    .progress
                    .connection()
                    .map(quinn::Connection::remote_address);
                t.progress = TransferState::Paused(peer);
            }
        }
        iced::Task::none()
    }

    /// Update the state to resume a paused transfer.
    #[tracing::instrument(skip(self))]
    fn update_resume_paused(
        &mut self,
        nonce: Nonce,
        peer: Option<SocketAddr>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            server,
            external_address,
            downloads,
            ..
        }) = &mut self.connection_state
        else {
            tracing::warn!("No connected state to resume download");
            return iced::Task::none();
        };

        let Some(t) = downloads.iter_mut().find(|t| t.nonce == nonce) else {
            tracing::warn!("No download found to resume for nonce");
            return iced::Task::none();
        };
        let endpoint = endpoint.clone();
        let server = server.clone();
        let external_address = external_address.0;
        let path = t.path.clone();
        let hash = t.hash;
        let final_file_size = t.file_size;

        let progress_lock = Arc::new(RwLock::new(0.));
        t.progress = TransferState::ResumingHash(progress_lock.clone());
        t.cancellation_token = CancellationToken::new();
        let cancellation_token = t.cancellation_token.clone();

        // Create a future to resume the download.
        let resume_future = async move {
            // Get the file size and digest state of the chosen file to publish.
            let (_, file_size, digest) = Box::pin(crate::core::file_size_and_hasher(
                &path,
                Some(&progress_lock),
            ))
            .await
            .map_err(|e| Some(Arc::new(e.into())))?;

            // Get the list of peers to resume the download from.
            let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
            let mut peers = crate::core::subscribe(&server, &mut bb, hash, Some(external_address))
                .await
                .map_err(|e| Some(Arc::new(e.into())))?;

            // Try to connect to the previous peer first if one was provided.
            if let Some(peer) = peer {
                if let Some(i) = peers
                    .iter()
                    .position(|(p, f)| peer.eq(p) && *f == file_size)
                {
                    // No need for introduction if the peer is already in the list.
                    // Ensure the peer is at the front of the list.
                    if i != 0 {
                        peers.swap(0, i);
                    }
                } else if let Some(e) = crate::core::introduction(&server, &mut bb, hash, peer)
                    .await
                    .err()
                {
                    tracing::warn!("Failed to receive introduction with peer {peer}: {e}");
                } else {
                    // Attempt to connect to the original peer first.
                    let i = peers.len();
                    peers.push((peer, file_size));
                    if i != 0 {
                        peers.swap(0, i);
                    }
                }
            }

            // Get a request stream to the peer to resume the download.
            let request = first_matching_download(&endpoint, &peers, hash, final_file_size)
                .await
                .ok_or(None)?;

            Ok((digest, file_size, request))
        };

        // Resume the transfer.
        iced::Task::perform(
            async move {
                tokio::select! {
                    // Allow cancelling the resume request.
                    () = cancellation_token.cancelled() => {
                        tracing::debug!("Cancelling the resume request");
                        Err(Some(Arc::new(anyhow::anyhow!("Cancelled"))))
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
        result: Result<(sha2::Sha256, u64, PeerRequestStream), Option<Arc<anyhow::Error>>>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            tracing::warn!("No connected state to resume partial hash");
            return iced::Task::none();
        };

        let Some(t) = downloads.iter_mut().find(|t| t.nonce == nonce) else {
            tracing::warn!("No download found to resume partial hash for nonce");
            return iced::Task::none();
        };

        match result {
            // Resume the download with the partial hash
            Ok((digest, start_index, request)) => {
                let progress = Arc::new(RwLock::new(start_index));
                let progress_animation = start_index as f32 / t.file_size as f32;
                t.progress = TransferState::Transferring {
                    peer: request.connection.clone(),
                    progress_lock: progress.clone(),
                    progress_animation,
                    snapshot: TransferSnapshot::new(),
                };
                let cancellation_token = t.cancellation_token.clone();
                let path = t.path.clone();
                let hash = t.hash;
                let file_size = t.file_size;

                iced::Task::perform(
                    async move {
                        let mut file = match tokio::fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .open(&path)
                            .await
                        {
                            Ok(f) => f,
                            Err(e) => {
                                return TransferResult::Failure(Arc::new(format!(
                                    "Failed to open the file: {e}"
                                )))
                            }
                        };

                        // Try to upload the file to the peer connection.
                        let mut request = request.bistream.lock().await;
                        tokio::select! {
                            () = cancellation_token.cancelled() => TransferResult::Cancelled,

                            result = Box::pin(crate::core::download_partial_from_peer(
                                hash,
                                &mut request,
                                &mut file,
                                crate::core::DownloadOffsetState::new(start_index..file_size, Some(digest)),
                                Some(&progress),
                            )) => match result {
                                Ok(()) => TransferResult::Success,
                                Err(e) => TransferResult::Failure(Arc::new(format!("Upload failed: {e}"))),
                            }
                        }
                    },
                    move |r| Message::TransferResulted(nonce, r, FileYeetCommandType::Sub),
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
                t.progress = TransferState::Done(TransferResult::Failure(e));

                self.options.last_downloads.push(SavedDownload {
                    path: t.path.clone(),
                    hash: t.hash,
                    file_size: t.file_size,
                    peer_socket: t.peer_string.parse().ok(),
                });

                iced::Task::none()
            }
        }
    }

    /// Update the state after a transfer has concluded, successfully or not.
    #[tracing::instrument(skip(self))]
    fn update_transfer_resulted(
        &mut self,
        nonce: Nonce,
        result: TransferResult,
        transfer_type: FileYeetCommandType,
    ) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState {
            peers,
            downloads,
            uploads,
            ..
        }) = &mut self.connection_state
        {
            // Log a warning if the transfer failed.
            if let TransferResult::Failure(e) = &result {
                tracing::warn!("Transfer failed: {e}");
            }

            let mut transfers = match transfer_type {
                FileYeetCommandType::Sub => downloads.iter_mut(),
                FileYeetCommandType::Pub => uploads.iter_mut(),
            };

            if let Some(t) = transfers.find(|t| t.nonce == nonce) {
                // Handle a paused transfer.
                if let TransferState::Paused(_) = &t.progress {
                    // If the transfer result is cancelled, ignore it.
                    // This is expected if the transfer was paused.
                    if matches!(result, TransferResult::Cancelled) {
                        tracing::debug!(
                            "Transfer was paused and then cancelled, expected race condition"
                        );
                        return iced::Task::none();
                    }
                }

                // Handle a transfer that is already done.
                if let TransferState::Done(done) = &t.progress {
                    // If we are cancelling twice, ignore the second cancellation.
                    // Otherwise, this is an unexpected double-result.
                    if !matches!(result, TransferResult::Cancelled)
                        || !matches!(done, TransferResult::Cancelled)
                    {
                        tracing::warn!("Transfer already marked as done {done}");
                    }
                    return iced::Task::none();
                }

                // If the transfer was connected to a peer, remove the nonce from transactions.
                if let Some(connection) = t.progress.connection() {
                    remove_nonce_for_peer(connection, peers, nonce);
                }

                // Mark the transfer as done.
                t.progress = TransferState::Done(result);
            }
        } else {
            tracing::warn!("No connected state to update transfer result");
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
        if let ConnectionState::Connected(ConnectedState {
            downloads, uploads, ..
        }) = &mut self.connection_state
        {
            let transfers = match transfer_type {
                FileYeetCommandType::Sub => downloads,
                FileYeetCommandType::Pub => uploads,
            };
            if let Some(i) = transfers.iter().position(|t| t.nonce == nonce) {
                transfers.remove(i);
            }
        } else {
            tracing::warn!("No connected state to remove transfer");
        }
        iced::Task::none()
    }

    /// Try to safely close.
    #[tracing::instrument(skip(self))]
    fn safely_close(&mut self, close_type: CloseType) -> iced::Task<Message> {
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
                .filter_map(|publish_item| {
                    // Ensure all publish tasks are cancelled.
                    publish_item.cancellation_token.cancel();

                    // If the publish is valid or in progress, add it to the list of open publishes.
                    match publish_item.state {
                        PublishState::Publishing(p) => Some(SavedPublish {
                            path: publish_item.path,
                            hash_and_file_size: Some((p.hash, p.file_size)),
                        }),
                        PublishState::Hashing(_) => Some(SavedPublish {
                            path: publish_item.path,
                            hash_and_file_size: None,
                        }),
                        _ => None,
                    }
                })
                .collect();

            self.options
                .last_downloads
                .extend(downloads.drain(..).filter_map(|d| {
                    // If the download is in progress, cancel it.
                    d.cancellation_token.cancel();

                    // Ensure all downloads that were in-progress are saved.
                    let peer_socket = match d.progress {
                        TransferState::Transferring { peer, .. } => Some(peer.remote_address()),
                        TransferState::Paused(peer) => peer,

                        // In most cases, do not save the download.
                        _ => return None,
                    };
                    Some(SavedDownload {
                        hash: d.hash,
                        file_size: d.file_size,
                        peer_socket,
                        path: d.path,
                    })
                }));

            endpoint.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

            // Save the app settings when closing our connections.
            if let Err(e) = save_settings(&self.options) {
                tracing::warn!("Could not save settings: {e}");
            } else {
                tracing::info!("Settings saved");
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
}

/// Helper to get a consistent horizontal scrollbar for text overflow.
fn text_horizontal_scrollbar() -> widget::scrollable::Direction {
    widget::scrollable::Direction::Horizontal(
        widget::scrollable::Scrollbar::new()
            .width(8)
            .scroller_width(8),
    )
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
            .get_connection_async(&peer)
            .await
        {
            tracing::debug!("Reusing connection to peer {peer}");
            PeerConnectionOrTarget::Connection(c)
        } else {
            tracing::debug!("Creating new connection to peer {peer}");
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

/// A loop to await the server to send peers requesting the specified publish.
/// An asynchronous loop to await new requests from a peer connection.
#[tracing::instrument(skip(connection, output))]
async fn connected_peer_request_loop(
    connection: quinn::Connection,
    peer_address: SocketAddr,
    mut output: futures_channel::mpsc::Sender<Message>,
) {
    loop {
        // Wait for a new bi-directional stream request from the peer.
        match connection.accept_bi().await.map(BiStream::from) {
            Ok(mut streams) => {
                // Get the file hash desired by the peer.
                let mut hash = HashBytes::default();
                if let Err(e) = streams.recv.read_exact(&mut hash.bytes).await {
                    tracing::warn!("Failed to read hash from peer: {e}");
                    continue;
                }

                tracing::debug!("Peer requested transfer: {hash}");

                if let Err(e) = output.try_send(Message::PeerRequestedTransfer((
                    hash,
                    PeerRequestStream::new(connection.clone(), streams),
                ))) {
                    tracing::error!(
                        "Failed to perform internal message passing for peer requested stream: {e}"
                    );
                }
            }

            Err(e) => {
                tracing::debug!("Peer connection closed: {peer_address} {e:?}");

                // The peer has disconnected or the connection deteriorated.
                if let Err(e) = output.try_send(Message::PeerDisconnected(peer_address)) {
                    tracing::error!(
                        "Failed to perform internal message passing for failed peer stream: {e}"
                    );
                }
                return;
            }
        }
    }
}

/// Helper to get a task to hash a file and return the file size and hash.
fn hash_publish_task(
    nonce: Nonce,
    path: PathBuf,
    cancellation: CancellationToken,
    progress: Arc<RwLock<f32>>,
) -> iced::Task<Message> {
    iced::Task::perform(
        async move {
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
            Ok((file_size, hash)) => {
                Message::PublishFileHashed(NewOrExistingPublish::Existing(nonce), hash, file_size)
            }
        },
    )
}

/// For the given publish, await peers desiring to receive the file.
#[tracing::instrument(skip(publish, cancellation_token, output))]
async fn peers_requesting_publish_loop(
    publish: Publish,
    nonce: Nonce,
    cancellation_token: CancellationToken,
    our_external_address: SocketAddr,
    mut output: futures_channel::mpsc::Sender<Message>,
) {
    loop {
        let mut request = publish.server_streams.lock().await;

        tokio::select! {
            // Let the task be cancelled.
            () = cancellation_token.cancelled() => {
                // Send data back to the server to tell them we are done with this task.
                if let Err(e) = request.send.write_u8(0).await {
                    let kind = e.kind();
                    if let Ok(e) = e.downcast() {
                        if matches!(e, crate::core::LOCALLY_CLOSED_WRITE) {
                            // This error is expected in quick closes, don't warn.
                            tracing::debug!("Closed endpoint before explicit publish cancel");
                        } else {
                            tracing::warn!("Failed to tell server to cancel publish: {e:?}");
                        }
                    } else {
                        tracing::warn!("Failed to tell server to cancel publish of IO kind: {kind:?}");
                    }
                }

                return;
            }

            // Await the server to send a peer connection.
            result = crate::core::read_subscribing_peer(
                &mut request.recv,
                Some(our_external_address),
            ) => {
                // Handle errors appropriately based on the error type.
                if let Err(e) = &result {
                    match &e {
                        // Our address was sent as a peer, expected while testing.
                        ReadSubscribingPeerError::SelfAddress => {
                            tracing::debug!("Expected failure to read peer introduction: {e}");
                            continue;
                        }

                        // Unexpected error, log and continue.
                        ReadSubscribingPeerError::ReadSocket(e) => {
                            if matches!(e, ExpectedSocketError::ReadIp(
                                quinn::ReadExactError::ReadError(crate::core::LOCALLY_CLOSED_READ)
                            )) {
                                // Locally closed connection, expected.
                                tracing::debug!("Expected failure to read peer introduction: Locally closed connection");
                                return;
                            }
                            tracing::warn!("Failed to read peer introduction: {e}");

                            if matches!(
                                e,
                                ExpectedSocketError::ReadPort(_)
                                | ExpectedSocketError::ReadIp(
                                    quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(
                                        quinn::ConnectionError::ConnectionClosed(_)
                                        | quinn::ConnectionError::ApplicationClosed(_))))
                            ) {
                                // The server connection has closed, but not by our intention.
                                tracing::warn!("Server connection closed unexpectedly");

                                // Try to tell the client to cancel the publish task.
                                if let Err(e) = output.try_send(Message::CancelPublish(nonce)) {
                                    tracing::error!("Failed to perform internal message passing for subscription peer: {e}");
                                }
                                return;
                            }
                        }
                    }
                }

                // Send the result back to the main loop.
                if let Err(e) = output.try_send(Message::PublishPeerReceived(
                        nonce,
                        result.map_err(Arc::new),
                    ))
                {
                    tracing::error!("Failed to perform internal message passing for subscription peer: {e}");
                }
            }
        }
    }
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

/// Try to establish a peer connection for a command type.
/// Either starts from an existing connection or attempts to holepunch.
//  TODO: Consider returning a `Result` instead of an `Option` to handle errors.
async fn try_peer_connection(
    peer: PeerConnectionOrTarget,
    hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Option<PeerRequestStream> {
    use PeerConnectionOrTarget::{Connection, Target};
    tokio::time::timeout(PEER_CONNECT_TIMEOUT, async move {
        match peer {
            Connection(c) => peer_connection_into_stream(&c, hash, cmd)
                .await
                .map(|s| (c, s)),

            Target(e, peer) => udp_holepunch(cmd, hash, e, peer).await,
        }
        .map(PeerRequestStream::from)
    })
    .await
    .ok()
    .flatten()
}

/// Add the nonce of a transaction to a peer's set of known transactions.
fn insert_nonce_for_peer(
    peer_address: SocketAddr,
    peers: &mut HashMap<SocketAddr, HashSet<Nonce>>,
    nonce: Nonce,
) {
    match peers.entry(peer_address) {
        std::collections::hash_map::Entry::Vacant(e) => {
            // Add the peer into our map of known peer addresses.
            e.insert(HashSet::from([nonce]));
        }
        std::collections::hash_map::Entry::Occupied(mut e) => {
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
    if let std::collections::hash_map::Entry::Occupied(mut e) = peers.entry(peer_address) {
        let nonces = e.get_mut();
        if !nonces.remove(&nonce) {
            tracing::warn!("Nonce was not found for peer {peer_address}");
        }

        // If there are no more streams to the peer, close the connection.
        if nonces.is_empty() {
            tracing::debug!("Closing peer {peer_address} connection");

            // Close the connection.
            // Peer cleanup will happen when `connected_peer_request_loop(..)` sees the connection is dropped.
            peer.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());
        }
    } else {
        tracing::debug!("Peer {peer_address} not found in peers map");
    }
}

/// Either close all connections or the entire application.
#[derive(Clone, Copy, Debug)]
enum CloseType {
    Connections,
    Application,
}

const INVALID_PORT_FORWARD: &str = "Invalid port forward. Defaults to no port mappings.";
