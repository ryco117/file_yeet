use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU16,
    ops::Div as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::{
    local_now_fmt, BiStream, HashBytes, DEFAULT_PORT, GOODBYE_CODE, GOODBYE_MESSAGE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use iced::{
    widget::{self, horizontal_space},
    window, Element,
};
use tokio::io::AsyncWriteExt as _;
use tokio_util::sync::CancellationToken;

use crate::core::{
    humanize_bytes, FileYeetCommandType, PortMappingConfig, PreparedConnection,
    MAX_PEER_COMMUNICATION_SIZE, PEER_CONNECT_TIMEOUT, SERVER_CONNECTION_TIMEOUT,
};

/// Lazily initialized regex for parsing server addresses.
/// Produces match groups `host` and `port` for the server address and optional port.
static SERVER_ADDRESS_REGEX: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^\s*(?P<host>([^:]|::)+)(?::(?P<port>\d+))?\s*$").unwrap()
    });

/// The maximum time to wait before forcing the application to exit.
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The red used to display errors to the user.
const ERROR_RED_COLOR: iced::Color = iced::Color::from_rgb(1., 0.4, 0.5);

/// The state of the port mapping options in the GUI.
#[derive(
    Clone,
    Copy,
    std::cmp::PartialEq,
    std::cmp::Eq,
    Debug,
    Default,
    serde::Deserialize,
    serde::Serialize,
)]
pub enum PortMappingGuiOptions {
    #[default]
    None,
    PortForwarding(Option<NonZeroU16>),
    TryPcpNatPmp,
}
impl PortMappingGuiOptions {
    /// Get the port mapping option as a human-readable string.
    fn to_label(self) -> &'static str {
        match self {
            PortMappingGuiOptions::None => "None",
            PortMappingGuiOptions::PortForwarding(_) => "Port Forward",
            PortMappingGuiOptions::TryPcpNatPmp => "NAT-PMP / PCP",
        }
    }
}
impl std::fmt::Display for PortMappingGuiOptions {
    /// Display the port mapping option as a human-readable string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = self.to_label();
        write!(f, "{label}")
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

/// Nonce used to identifying items locally.
type Nonce = u64;

/// The result of a file transfer with a peer.
#[derive(Clone, Debug, displaydoc::Display)]
pub enum TransferResult {
    /// The transfer succeeded.
    Success,

    /// The transfer failed: {0}.
    Failure(Arc<anyhow::Error>),

    /// The transfer was cancelled.
    Cancelled,
}

/// The state of a file transfer with a peer.
#[derive(Debug)]
enum TransferProgress {
    Connecting,
    Consent(PeerRequestStream),
    Transferring(PeerRequestStream, Arc<std::sync::RwLock<f32>>, f32),
    Done(TransferResult),
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
    pub progress: TransferProgress,
    pub cancellation_token: CancellationToken,
}

/// The fundamental elements of a file transfer.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TransferBase {
    pub hash: HashBytes,
    pub file_size: u64,
    pub peer_socket: SocketAddr,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub enum PublishRequestResult {
    Success(IncomingPublishSession),
    Failure(Arc<anyhow::Error>),
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

/// The state of a file publish request.
#[derive(Clone, Debug)]
enum PublishState {
    Hashing(Arc<std::sync::RwLock<f32>>),
    Publishing(Publish),
    Failure(Arc<anyhow::Error>),
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
    pub fn new(
        nonce: Nonce,
        path: PathBuf,
        cancellation_token: CancellationToken,
        hash_progress: Arc<std::sync::RwLock<f32>>,
    ) -> Self {
        Self {
            nonce,
            path,
            cancellation_token,
            state: PublishState::Hashing(hash_progress),
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
            hash_hex: faster_hex::hex_string(&hash),
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
    external_address: String,

    /// The hash input field for creating new subscribe requests.
    hash_input: String,

    /// Map of peer socket addresses to QUIC connections.
    peers: HashMap<SocketAddr, (quinn::Connection, HashSet<Nonce>)>,

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
    fn new(endpoint: quinn::Endpoint, server: quinn::Connection, external_address: String) -> Self {
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

/// The current settings for the app.
#[derive(Default, serde::Deserialize, serde::Serialize)]
struct AppSettings {
    pub server_address: String,
    pub gateway_address: Option<String>,
    pub port_forwarding_text: String,
    pub internal_port_text: String,
    pub port_mapping: PortMappingGuiOptions,
    pub last_publish_paths: Vec<PathBuf>,
    pub last_downloads: Vec<TransferBase>,
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
    PortMappingRadioChanged(PortMappingGuiOptions),

    /// The port forward text field was changed.
    PortForwardTextChanged(String),

    /// The gateway text field was changed.
    GatewayTextChanged(String),

    /// The connect button was clicked.
    ConnectClicked,

    /// A moment in time has passed, update the animations.
    AnimationTick,

    /// The result of a server connection attempt.
    ConnectResulted(Result<crate::core::PreparedConnection, Arc<anyhow::Error>>),

    /// Copy the server address to the clipboard.
    CopyServer,

    /// Leave the server and disconnect.
    SafelyLeaveServer,

    /// All async actions to leave a server have completed.
    LeftServer,

    /// A peer has connected to our endpoint directly.
    PeerConnected(quinn::Connection),

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

    /// The result of a publish request.
    PublishRequestResulted(Nonce, PathBuf, PublishRequestResult),

    /// The result of trying to receive a peer to publish to from the server.
    PublishPeerReceived(Nonce, Result<SocketAddr, Arc<anyhow::Error>>),

    /// The result of trying to connect to a peer to publish to.
    PublishPeerConnectResulted(Nonce, Option<PeerRequestStream>),

    /// The subscribe button was clicked or the hash field was submitted.
    SubscribeStarted,

    /// The path to save a file to was chosen or cancelled.
    SubscribePathChosen(Option<PathBuf>),

    /// A download is being recreated from the open transfers at last close.
    SubscribeRecreated(TransferBase),

    /// A subscribe request was completed.
    SubscribePeersResult(Result<IncomingSubscribePeers, Arc<anyhow::Error>>),

    /// A subscribe connection attempt was completed.
    SubscribePeerConnectResulted(Nonce, Option<PeerRequestStream>),

    // A download was accepted, initiate the download.
    AcceptDownload(Nonce),

    /// Copy a hash to the clipboard.
    CopyHash(String),

    /// Cancel publishing a file.
    CancelPublish(Nonce),

    /// Cancel a transfer that is in-progress.
    CancelTransfer(Nonce, FileYeetCommandType),

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

/// Try to get the path to the app settings file.
fn settings_path() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|mut p| {
        p.push("file_yeet_client/settings.json");
        p
    })
}

/// The application state and logic.
impl AppState {
    /// Create a new application state.
    pub fn new(args: crate::Cli) -> (Self, iced::Task<Message>) {
        // Get base settings from the settings file, or default.
        let mut settings = settings_path()
            .and_then(|p| {
                // Ensure the settings file and directory exist.
                if p.exists() {
                    // Try to read the settings for the app.
                    let settings = std::fs::read_to_string(p).ok()?;
                    serde_json::from_str::<AppSettings>(&settings).ok()
                } else {
                    // Create the settings file and directory.
                    std::fs::create_dir_all(p.parent()?).ok()?;
                    std::fs::write(p, "").ok()?;
                    None
                }
            })
            .unwrap_or_default();

        // The CLI arguments take final precedence on start.
        let crate::Cli {
            server_address,
            external_port_override,
            internal_port,
            gateway,
            nat_map,
            ..
        } = args;
        if let Some(server_address) = server_address {
            settings.server_address = server_address;
        }
        if let Some(gateway) = gateway {
            settings.gateway_address = Some(gateway);
        }
        if let Some(port) = internal_port {
            settings.internal_port_text = port.to_string();
        }
        if let Some(port) = external_port_override {
            settings.port_forwarding_text = port.to_string();
            settings.port_mapping = PortMappingGuiOptions::PortForwarding(Some(port));
        } else if nat_map {
            settings.port_mapping = PortMappingGuiOptions::TryPcpNatPmp;
        }

        // Create the initial state with the settings.
        let mut initial_state = Self {
            options: settings,
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
        "file_yeet_client"
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

            // Copy the connected server address to the clipboard.
            Message::CopyServer => iced::clipboard::write(self.options.server_address.clone()),

            Message::SafelyLeaveServer => self.safely_close(CloseType::Connections),

            // All async actions to leave a server have completed.
            Message::LeftServer => {
                self.safely_closing = false;
                self.connection_state = ConnectionState::Disconnected;
                iced::Task::none()
            }

            Message::PeerConnected(connection) => self.update_peer_connected(connection),

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
            Message::PublishRequestResulted(nonce, path, r) => {
                self.update_publish_request_resulted(nonce, &path, r)
            }
            Message::PublishPeerReceived(nonce, r) => self.update_publish_peer_received(nonce, r),
            Message::PublishPeerConnectResulted(pub_nonce, peer) => {
                self.update_publish_peer_connect_resulted(pub_nonce, peer)
            }

            // Handle the subscribe button being clicked by choosing a save location.
            Message::SubscribeStarted => {
                // Clear the status message before starting the subscribe attempt.
                self.status_message = None;

                // Let state know that a modal dialog is open.
                self.modal = true;

                iced::Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file path to save to")
                        .save_file(),
                    |f| Message::SubscribePathChosen(f.map(PathBuf::from)),
                )
            }

            Message::SubscribePathChosen(path) => self.update_subscribe_path_chosen(path),
            Message::SubscribeRecreated(transfer_base) => {
                self.update_subscribe_recreated(transfer_base)
            }
            Message::SubscribePeersResult(r) => self.update_subscribe_peers_result(r),
            Message::SubscribePeerConnectResulted(nonce, r) => {
                self.update_subscribe_connect_resulted(nonce, r)
            }
            Message::AcceptDownload(nonce) => self.update_accept_download(nonce),

            // Copy a hash to the clipboard.
            Message::CopyHash(hash) => iced::clipboard::write(hash),

            Message::CancelPublish(nonce) => self.update_cancel_publish(nonce),
            Message::CancelTransfer(nonce, transfer_type) => {
                self.update_cancel_transfer(nonce, transfer_type)
            }
            Message::TransferResulted(nonce, r, transfer_type) => {
                self.update_transfer_resulted(nonce, r, transfer_type)
            }

            // Handle a file being opened.
            Message::OpenFile(path) => {
                open::that(path).unwrap_or_else(|e| {
                    eprintln!("{} Failed to open file: {e}", local_now_fmt());
                });
                iced::Task::none()
            }

            Message::RemoveFromTransfers(nonce, transfer_type) => {
                self.update_remove_from_transfers(nonce, transfer_type)
            }

            // Handle an event that iced did not handle itself.
            // This is used to allow for custom exit handling in this instance.
            Message::UnhandledEvent(window, event) => match event {
                iced::Event::Window(window::Event::CloseRequested) => {
                    if self.safely_closing
                        || self
                            .main_window
                            .expect("Main window not available at unhandled event")
                            == window
                    {
                        // Allow force closing if the safe exit is taking too long for the user.
                        iced::window::close(window)
                    } else {
                        self.safely_close(CloseType::Application)
                    }
                }
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
                peers,
                publishes,
                ..
            }) => {
                // For publish we listen to the server for new peers requesting them.
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
                                output,
                            )
                        }),
                    ))
                });

                // Create a task to listen for incoming connections to our QUIC endpoint.
                let incoming_connections = {
                    let endpoint = endpoint.clone();
                    iced::stream::channel(4, move |output| {
                        incoming_peer_connection_loop(endpoint, output)
                    })
                };

                // Create a listener for each peer that may want a new request stream.
                let peer_requests = peers.iter().map(|(peer_addr, (connection, _))| {
                    let peer_addr = *peer_addr;
                    let connection = connection.clone();
                    iced::Subscription::run_with_id(
                        peer_addr,
                        iced::stream::channel(8, move |output| {
                            connected_peer_request_loop(connection, peer_addr, output)
                        }),
                    )
                });

                // Batch all the listeners together.
                iced::Subscription::batch(
                    [
                        unhandled_events(),
                        animation(),
                        iced::Subscription::run_with_id(0, incoming_connections),
                    ]
                    .into_iter()
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
                self.view_connected_page(connected_state)
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
            if let PortMappingGuiOptions::PortForwarding(_) = &self.options.port_mapping {
                port_forward_text = port_forward_text.on_input(Message::PortForwardTextChanged);
            }
        }

        // Ignore the data field in the radio selection status.
        let selected_mapping = match self.options.port_mapping {
            PortMappingGuiOptions::PortForwarding(_) => PortMappingGuiOptions::PortForwarding(None),
            other => other,
        };

        // Create a bottom section for choosing port forwarding/mapping options.
        let choose_port_mapping = widget::column!(
            widget::row!(widget::text("Internal Port to Bind"), internal_port_text).spacing(12),
            widget::radio(
                PortMappingGuiOptions::None.to_label(),
                PortMappingGuiOptions::None,
                Some(selected_mapping),
                Message::PortMappingRadioChanged,
            ),
            widget::row!(
                widget::radio(
                    PortMappingGuiOptions::PortForwarding(None).to_label(),
                    PortMappingGuiOptions::PortForwarding(None),
                    Some(selected_mapping),
                    Message::PortMappingRadioChanged,
                ),
                port_forward_text,
            )
            .spacing(32),
            widget::radio(
                PortMappingGuiOptions::TryPcpNatPmp.to_label(),
                PortMappingGuiOptions::TryPcpNatPmp,
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

    fn draw_transfers<'a, I>(
        transfers: I,
        transfer_type: FileYeetCommandType,
    ) -> iced::Element<'a, Message>
    where
        I: Iterator<Item = &'a Transfer>,
    {
        widget::column(transfers.map(|t| {
            let progress = match &t.progress {
                TransferProgress::Connecting => Element::from(widget::text("Connecting...")),

                TransferProgress::Consent(_) => widget::row!(
                    widget::text(format!(
                        "Accept download of size {}",
                        humanize_bytes(t.file_size)
                    ))
                    .width(iced::Length::Fill),
                    widget::button(widget::text("Accept").size(12))
                        .on_press(Message::AcceptDownload(t.nonce)),
                    widget::button(widget::text("Cancel").size(12))
                        .on_press(Message::CancelTransfer(t.nonce, transfer_type))
                )
                .spacing(12)
                .into(),
                TransferProgress::Transferring(_, _, p) => widget::row!(
                    widget::text("Transferring..."),
                    widget::progress_bar(0.0..=1., *p),
                    widget::button(widget::text("Cancel").size(12))
                        .on_press(Message::CancelTransfer(t.nonce, transfer_type))
                        .width(iced::Length::Shrink)
                )
                .spacing(6)
                .into(),

                TransferProgress::Done(r) => {
                    let remove = widget::button(widget::text("Remove").size(12))
                        .on_press(Message::RemoveFromTransfers(t.nonce, transfer_type));
                    widget::row!(
                        // TODO: If the transfer failed, color error text red.
                        widget::text(r.to_string()).width(iced::Length::Fill),
                        if matches!(transfer_type, FileYeetCommandType::Sub)
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
                            remove.into()
                        },
                    )
                    .into()
                }
            };

            widget::container(widget::column!(
                progress,
                widget::text(&t.hash_hex).size(12),
                widget::row!(
                    widget::text(&t.peer_string).size(12),
                    widget::horizontal_space(),
                    widget::text(t.path.to_string_lossy()).size(12),
                )
                .spacing(6),
            ))
            .style(widget::container::bordered_box)
            .width(iced::Length::Fill)
            .padding([6, 12]) // Extra padding on the right because of optional scrollbar.
            .into()
        }))
        .spacing(6)
        .into()
    }

    fn draw_pubs(publishes: &[PublishItem]) -> iced::Element<Message> {
        let publish_views = publishes.iter().map(|pi| {
            widget::container(
                match &pi.state {
                    PublishState::Hashing(progress) => widget::row!(
                        widget::column!(
                            widget::row!(
                                widget::text("Hashing..."),
                                widget::progress_bar(0.0..=1., *progress.read().unwrap()),
                            )
                            .spacing(6),
                            widget::text(pi.path.to_string_lossy()).size(12),
                        )
                        .spacing(6),
                        widget::button("Cancel").on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Publishing(p) => widget::row!(
                        widget::column!(
                            widget::text(&p.hash_hex).size(12),
                            widget::text(pi.path.to_string_lossy()).size(12)
                        ),
                        widget::horizontal_space(),
                        widget::button(widget::text("Copy Hash").size(12))
                            .on_press(Message::CopyHash(p.hash_hex.clone())),
                        widget::button(widget::text("Cancel").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Failure(e) => widget::row!(
                        widget::column!(
                            widget::text(format!("Failed to publish: {e}")).color(ERROR_RED_COLOR),
                            widget::text(pi.path.to_string_lossy()).size(12),
                        )
                        .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Cancelled => widget::row!(
                        widget::column!(
                            widget::text("Cancelled"),
                            widget::text(pi.path.to_string_lossy()).size(12),
                        )
                        .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                }
                .align_y(iced::Alignment::Center)
                .spacing(12),
            )
            .width(iced::Length::Fill)
            .padding([6, 12]) // Extra padding on the right because of optional scrollbar.
            .into()
        });

        widget::column(publish_views).spacing(6).into()
    }

    /// Draw the main application controls when connected to a server.
    fn view_connected_page<'a, 'b: 'a>(
        &'b self,
        connected_state: &'a ConnectedState,
    ) -> iced::Element<'a, Message> {
        /// Helper for creating a horizontal line.
        fn horizontal_line<'b>() -> widget::Container<'b, Message> {
            widget::container(horizontal_space()).height(3)
        }

        // Define the elements that we want to be modal aware first.
        let mut publish_button = widget::button("Publish");
        let mut download_button = widget::button("Download");
        let mut hash_text_input = widget::text_input("Hash", &connected_state.hash_input);
        let mut leave_server_button = widget::button(widget::text("Leave").size(12));

        // Disable the inputs while a modal is open.
        if !self.modal {
            publish_button = publish_button.on_press(Message::PublishClicked);
            hash_text_input = hash_text_input.on_input(Message::HashInputChanged);
            leave_server_button = leave_server_button.on_press(Message::SafelyLeaveServer);

            // Enable the download button if the hash is valid.
            if connected_state.hash_input.len() == file_yeet_shared::HASH_BYTE_COUNT << 1
                && faster_hex::hex_check(connected_state.hash_input.as_bytes())
            {
                download_button = download_button.on_press(Message::SubscribeStarted);
                hash_text_input = hash_text_input.on_submit(Message::SubscribeStarted);
            }
        }

        // Define a header exposing the server address and how the server sees us (our IP address).
        let header = widget::row!(
            widget::text("Server address:"),
            widget::text(&self.options.server_address),
            widget::button(widget::text("Copy").size(12)).on_press(Message::CopyServer),
            leave_server_button,
            widget::horizontal_space(),
            widget::text("Our External Address:"),
            widget::text(&connected_state.external_address),
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
                    (false, true) => Self::draw_pubs(&connected_state.publishes),

                    // Only publishes are empty, show uploads.
                    (true, false) => Self::draw_transfers(
                        connected_state.uploads.iter(),
                        FileYeetCommandType::Pub,
                    ),

                    // Show both publishes and uploads. Separate them with a line.
                    (false, false) => widget::column!(
                        Self::draw_pubs(&connected_state.publishes),
                        horizontal_line(),
                        Self::draw_transfers(
                            connected_state.uploads.iter(),
                            FileYeetCommandType::Pub,
                        ),
                    )
                    .spacing(12)
                    .into(),
                }
            }

            // Create a list of download attempts.
            TransferView::Downloads => {
                Self::draw_transfers(connected_state.downloads.iter(), FileYeetCommandType::Sub)
            }
        };

        widget::container(
            widget::column!(
                header,
                horizontal_line(),
                widget::row!(publish_button, download_input).spacing(6),
                transfer_view_choice,
                widget::scrollable(transfer_content),
            )
            .spacing(12),
        )
        .width(iced::Length::Fill)
        .height(iced::Length::Fill)
        .padding(12)
        .into()
    }

    /// Handle the port mapping radio button being changed.
    fn update_port_radio_changed(
        &mut self,
        selection: PortMappingGuiOptions,
    ) -> iced::Task<Message> {
        self.options.port_mapping = match selection {
            PortMappingGuiOptions::None => {
                self.status_message = None;
                PortMappingGuiOptions::None
            }
            PortMappingGuiOptions::PortForwarding(_) => PortMappingGuiOptions::PortForwarding({
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
            PortMappingGuiOptions::TryPcpNatPmp => {
                self.status_message = None;
                PortMappingGuiOptions::TryPcpNatPmp
            }
        };
        iced::Task::none()
    }

    /// Update the state after the port forward text field was changed.
    fn update_port_forward_text(&mut self, text: String) -> iced::Task<Message> {
        self.options.port_forwarding_text = text;
        if let PortMappingGuiOptions::PortForwarding(port) = &mut self.options.port_mapping {
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
            Some((Some(self.options.server_address.clone()), DEFAULT_PORT))
        } else {
            // Otherwise, parse the server address and optional port.
            SERVER_ADDRESS_REGEX
                .captures(&self.options.server_address)
                .and_then(|captures| {
                    let host = captures.name("host").unwrap().as_str();

                    // If there is no port, use the default port. Otherwise, the input must be valid.
                    let port = captures.name("port").map_or(Some(DEFAULT_PORT), |p| {
                        p.as_str().parse::<NonZeroU16>().ok()
                    })?;
                    Some((Some(host.to_owned()), port))
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

        // Set the state to `Stalling` before starting the connection attempt.
        self.connection_state = ConnectionState::new_stalling();

        // Try to get the user's intent from the GUI options.
        let port_mapping = match self.options.port_mapping {
            PortMappingGuiOptions::None | PortMappingGuiOptions::PortForwarding(None) => {
                PortMappingConfig::None
            }
            PortMappingGuiOptions::PortForwarding(Some(port)) => {
                PortMappingConfig::PortForwarding(port)
            }
            PortMappingGuiOptions::TryPcpNatPmp => {
                PortMappingConfig::PcpNatPmp(self.port_mapping.take())
            }
        };
        let gateway = self.options.gateway_address.clone();

        // Try to connect to the server in a new task.
        iced::Task::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::prepare_server_connection(
                    server_address.as_deref(),
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
            ConnectionState::Stalling { tick, .. } => *tick = Instant::now(),
            ConnectionState::Connected(ConnectedState {
                downloads, uploads, ..
            }) => {
                for t in downloads.iter_mut().chain(uploads.iter_mut()) {
                    if let TransferProgress::Transferring(_, lock, progress) = &mut t.progress {
                        let Ok(p) = lock.read() else {
                            // Note that this transfer has had its lock poisoned and continue.
                            t.progress = TransferProgress::Done(TransferResult::Failure(Arc::new(
                                anyhow::anyhow!("Lock poisoned"),
                            )));
                            continue;
                        };

                        // Update the progress bar with the most recent value.
                        *progress = *p;
                    }
                }
            }
            ConnectionState::Disconnected => {}
        }
        iced::Task::none()
    }

    /// Update the state after a connection attempt to the server completed.
    fn update_connect_resulted(
        &mut self,
        result: Result<PreparedConnection, Arc<anyhow::Error>>,
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

                // Attempt to recreate previous publish tasks.
                if !self.options.last_publish_paths.is_empty()
                    || !self.options.last_downloads.is_empty()
                {
                    return iced::Task::batch(
                        self.options
                            .last_publish_paths
                            .drain(..)
                            .map(|p| {
                                iced::Task::perform(
                                    std::future::ready(Some(p)),
                                    Message::PublishPathChosen,
                                )
                            })
                            .chain(self.options.last_downloads.drain(..).map(|d| {
                                iced::Task::perform(
                                    std::future::ready(d),
                                    Message::SubscribeRecreated,
                                )
                            })),
                    );
                }
            }
            Err(e) => {
                self.status_message = Some(format!("Error connecting: {e}"));
                self.connection_state = ConnectionState::Disconnected;
            }
        }
        iced::Task::none()
    }

    /// Update the state after a peer connected to the endpoint.
    fn update_peer_connected(&mut self, connection: quinn::Connection) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { peers, .. }) = &mut self.connection_state
        {
            peers.insert(connection.remote_address(), (connection, HashSet::new()));
        }
        iced::Task::none()
    }

    /// Update after an existing peer requested a new file transfer.
    fn update_peer_requested_transfer(
        &mut self,
        hash: HashBytes,
        peer_request: PeerRequestStream,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        else {
            eprintln!(
                "{} Peer requested transfer while not connected",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        // Find the publish-nonce corresponding to the hash.
        let Some(nonce) = publishes.iter_mut().find_map(|pi| match &pi.state {
            PublishState::Publishing(p) if p.hash == hash => Some(pi.nonce),
            _ => None,
        }) else {
            eprintln!(
                "{} Peer requested transfer for unknown hash",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        self.update_publish_peer_connect_resulted(nonce, Some(peer_request))
    }

    /// Update the state after the publish button was clicked. Begins a publish request if a file was chosen.
    fn update_publish_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Task<Message> {
        self.modal = false;

        // Ensure a path was chosen, otherwise safely cancel.
        let Some(path) = path else {
            return iced::Task::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            server,
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Task::none();
        };

        // Ensure the transfer view is set to publishing to see the new item.
        *transfer_view = TransferView::Publishes;

        let server = server.clone();
        let progress = Arc::new(std::sync::RwLock::new(0.));
        let nonce = rand::random();
        let cancellation_token = CancellationToken::new();
        let cancellation_path = path.clone();

        publishes.push(PublishItem::new(
            nonce,
            path.clone(),
            cancellation_token.clone(),
            progress.clone(),
        ));
        iced::Task::perform(
            async move {
                tokio::select! {
                    // Allow cancelling the publish request thread.
                    () = cancellation_token.cancelled() => (PublishRequestResult::Cancelled, cancellation_path),

                    r = async move {
                        // Get the file size and hash of the chosen file to publish.
                        let (file_size, hash) =
                            match crate::core::file_size_and_hash(&path, Some(&progress)).await {
                                Ok(p) => p,
                                Err(e) => {
                                    return (
                                        PublishRequestResult::Failure(Arc::new(anyhow::anyhow!(
                                            "Error getting file size and hash: {e}"
                                        ))),
                                        path,
                                    );
                                }
                            };

                        // Create a memory buffer with sufficient capacity for the publish request.
                        let bb = bytes::BytesMut::with_capacity(MAX_SERVER_COMMUNICATION_SIZE);

                        // Create a bi-directional stream to the server for this publish request.
                        (
                            match crate::core::publish(&server, bb, hash, file_size).await {
                                Ok(b) => PublishRequestResult::Success(IncomingPublishSession::new(b, hash, file_size)),
                                Err(e) => PublishRequestResult::Failure(Arc::new(e)),
                            },
                            path,
                        )
                    } => r
                }
            },
            move |(r, p)| Message::PublishRequestResulted(nonce, p, r),
        )
    }

    /// Update after the server has accepted a publish request, or there was an error.
    fn update_publish_request_resulted(
        &mut self,
        nonce: Nonce,
        path: &Path,
        result: PublishRequestResult,
    ) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            match (result, publishes.iter().position(|p| p.nonce == nonce)) {
                (
                    PublishRequestResult::Success(IncomingPublishSession {
                        server_streams,
                        hash,
                        file_size,
                    }),
                    Some(i),
                ) => {
                    publishes[i].upgrade_hashing(server_streams, hash, file_size);
                }
                (PublishRequestResult::Failure(e), Some(i)) => {
                    publishes[i].state = PublishState::Failure(e);
                }
                (PublishRequestResult::Cancelled, Some(i)) => {
                    publishes[i].state = PublishState::Cancelled;
                }
                (e, None) => {
                    self.status_message =
                        Some(format!("Error publishing {}: {e:?}", path.display()));
                }
            }
        }
        iced::Task::none()
    }

    /// Update after the server has sent a peer to publish to, or there was an error.
    fn update_publish_peer_received(
        &mut self,
        nonce: Nonce,
        result: Result<SocketAddr, Arc<anyhow::Error>>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            peers,
            publishes,
            ..
        }) = &mut self.connection_state
        else {
            eprintln!("{} Peer received while not connected", local_now_fmt());
            return iced::Task::none();
        };

        let publish = publishes
            .iter()
            .find_map(|p| {
                if let PublishState::Publishing(publishing) = &p.state {
                    if p.nonce == nonce {
                        Some(publishing)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .cloned();
        match (result, publish) {
            (Ok(peer), Some(publish)) => {
                let data = if let Some((c, _)) = peers.get(&peer) {
                    PeerConnectionOrTarget::Connection(c.clone())
                } else {
                    PeerConnectionOrTarget::Target(endpoint.clone(), peer)
                };
                let hash = publish.hash;
                iced::Task::perform(
                    try_peer_connection(data, hash, FileYeetCommandType::Pub),
                    move |r| {
                        Message::PublishPeerConnectResulted(
                            nonce,
                            r.map(Into::<PeerRequestStream>::into),
                        )
                    },
                )
            }
            (Err(e), _) => {
                self.status_message = Some(format!("Error receiving peer: {e}"));
                iced::Task::none()
            }
            (_, None) => iced::Task::none(),
        }
    }

    /// Update after a connection attempt to a peer for publishing has completed.
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
            eprintln!(
                "{} Publish peer connect resulted while not connected",
                local_now_fmt()
            );
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
            eprintln!(
                "{} Peer connected for unknown publish nonce {pub_nonce}",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        let upload_nonce = rand::random();
        let progress_lock = Arc::new(std::sync::RwLock::new(0.));
        let cancellation_token = CancellationToken::new();
        uploads.push(Transfer {
            nonce: upload_nonce,
            hash: publishing.hash,
            hash_hex: faster_hex::hex_string(&publishing.hash),
            file_size: publishing.file_size,
            peer_string: peer.connection.remote_address().to_string(),
            path: path.clone(),
            progress: TransferProgress::Transferring(peer.clone(), progress_lock.clone(), 0.),
            cancellation_token: cancellation_token.clone(),
        });

        insert_nonce_for_peer(&peer, peers, peer.connection.remote_address(), upload_nonce);

        let file_size = publishing.file_size;
        iced::Task::perform(
            async move {
                let file = match tokio::fs::File::open(path).await {
                    Ok(f) => f,
                    Err(e) => {
                        return TransferResult::Failure(Arc::new(anyhow::anyhow!(
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
                        Err(e) => TransferResult::Failure(Arc::new(e)),
                    }
                }
            },
            move |r| Message::TransferResulted(upload_nonce, r, FileYeetCommandType::Pub),
        )
    }

    /// Update the state after the publish button was clicked. Begins a subscribe request.
    fn update_subscribe_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Task<Message> {
        self.modal = false;

        // Ensure a path was chosen, otherwise safely cancel.
        let Some(path) = path else {
            return iced::Task::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            server,
            hash_input,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            eprintln!(
                "{} Subscribe path chosen while not connected",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        // Ensure the hash is valid.
        let mut hash = HashBytes::default();
        if let Err(e) = faster_hex::hex_decode(hash_input.as_bytes(), &mut hash) {
            let error = format!("Invalid hash: {e}");
            eprintln!("{} {error}", local_now_fmt());
            self.status_message = Some(error);
            return iced::Task::none();
        }

        // Ensure the transfer view is set to downloads to see the new item.
        *transfer_view = TransferView::Downloads;

        let server = server.clone();
        iced::Task::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::subscribe(&server, &mut bb, hash)
                    .await
                    .map(|peers| IncomingSubscribePeers::new(peers, path, hash))
                    .map_err(Arc::new)
            },
            Message::SubscribePeersResult,
        )
    }

    /// Update the state after loading a download from the last session.
    fn update_subscribe_recreated(&mut self, transfer_base: TransferBase) -> iced::Task<Message> {
        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            downloads,
            ..
        }) = &mut self.connection_state
        else {
            eprintln!(
                "{} Subscribe recreated while not connected",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        let TransferBase {
            hash,
            file_size,
            peer_socket,
            path,
        } = transfer_base;
        let nonce = rand::random();
        downloads.push(Transfer {
            nonce,
            hash,
            hash_hex: faster_hex::hex_string(&transfer_base.hash),
            file_size,
            peer_string: peer_socket.to_string(),
            path,
            progress: TransferProgress::Connecting,
            cancellation_token: CancellationToken::new(),
        });

        iced::Task::perform(
            try_peer_connection(
                PeerConnectionOrTarget::Target(endpoint.clone(), peer_socket),
                hash,
                FileYeetCommandType::Sub,
            ),
            move |c| Message::SubscribePeerConnectResulted(nonce, c),
        )
    }

    /// Update after server has responded to a subscribe request.
    fn update_subscribe_peers_result(
        &mut self,
        result: Result<IncomingSubscribePeers, Arc<anyhow::Error>>,
    ) -> iced::Task<Message> {
        match result {
            Ok(IncomingSubscribePeers {
                peers_with_size,
                path,
                hash,
            }) => {
                if let ConnectionState::Connected(ConnectedState {
                    endpoint,
                    hash_input,
                    peers,
                    downloads,
                    ..
                }) = &mut self.connection_state
                {
                    // Let the user know why nothing else is happening.
                    if peers_with_size.is_empty() {
                        self.status_message = Some("No peers available".to_owned());
                        return iced::Task::none();
                    }

                    // Create a new transfer state and connection attempt for each peer.
                    let transfers_commands_iter =
                        peers_with_size.into_iter().map(|(peer, file_size)| {
                            // Create a nonce to identify the transfer.
                            let nonce = rand::random();

                            // New transfer state for this request.
                            let transfer = Transfer {
                                nonce,
                                hash,
                                hash_hex: hash_input.clone(),
                                file_size,
                                peer_string: peer.to_string(),
                                path: path.clone(),
                                progress: TransferProgress::Connecting,
                                cancellation_token: CancellationToken::new(),
                            };

                            // New connection attempt for this peer with result command identified by the nonce.
                            let command = {
                                // Create a new connection or open a stream on an existing one.
                                let peer = if let Some((c, _)) = peers.get(&peer) {
                                    PeerConnectionOrTarget::Connection(c.clone())
                                } else {
                                    PeerConnectionOrTarget::Target(endpoint.clone(), peer)
                                };
                                // The future to use to create the connection.
                                let future =
                                    try_peer_connection(peer, hash, FileYeetCommandType::Sub);
                                iced::Task::perform(future, move |r| {
                                    Message::SubscribePeerConnectResulted(nonce, r)
                                })
                            };

                            // Return the pair to be separated later.
                            (transfer, command)
                        });

                    // Create a new transfer for each peer.
                    let (mut new_transfers, connect_commands): (
                        Vec<Transfer>,
                        Vec<iced::Task<Message>>,
                    ) = transfers_commands_iter.unzip();

                    // Add the new transfers to the list of active transfers.
                    downloads.append(&mut new_transfers);
                    iced::Task::batch(connect_commands)
                } else {
                    eprintln!(
                        "{} Subscribe peers result while not connected",
                        local_now_fmt()
                    );
                    iced::Task::none()
                }
            }
            Err(e) => {
                self.status_message = Some(format!("Error subscribing to the server: {e}"));
                iced::Task::none()
            }
        }
    }

    /// Update the state after a subscribe connection attempt to a peer completed.
    fn update_subscribe_connect_resulted(
        &mut self,
        nonce: Nonce,
        result: Option<PeerRequestStream>,
    ) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            eprintln!(
                "{} Subscribe connect resulted while not connected",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        // Find the transfer with the matching nonce.
        let Some((index, transfer)) = downloads
            .iter_mut()
            .enumerate()
            .find(|(_, t)| t.nonce == nonce)
        else {
            eprintln!(
                "{} Subscribe connect resulted for unknown nonce",
                local_now_fmt()
            );
            return iced::Task::none();
        };

        // Update the state of the transfer with the result.
        if let Some(connection) = result {
            let peer_address = connection.connection.remote_address();
            insert_nonce_for_peer(&connection, peers, peer_address, nonce);

            transfer.progress = TransferProgress::Consent(connection);
        } else {
            // Remove unreachable peers from view.
            downloads.remove(index);
        }
        iced::Task::none()
    }

    /// Tell the peer to send the file and begin receiving and writing the file.
    fn update_accept_download(&mut self, nonce: Nonce) -> iced::Task<Message> {
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            eprintln!("{} No connected state to accept download", local_now_fmt());
            return iced::Task::none();
        };

        // Get the current transfer status.
        let Some(transfer) = downloads.iter_mut().find(|t| t.nonce == nonce) else {
            eprintln!("{} No transfer found to accept download", local_now_fmt());
            return iced::Task::none();
        };
        let hash = transfer.hash;
        let file_size = transfer.file_size;
        let peer_streams = if let TransferProgress::Consent(p) = &mut transfer.progress {
            p.clone()
        } else {
            eprintln!("{} Transfer is not in consent state", local_now_fmt());
            return iced::Task::none();
        };

        // Begin the transfer.
        let byte_progress = Arc::new(std::sync::RwLock::new(0.));
        transfer.progress =
            TransferProgress::Transferring(peer_streams.clone(), byte_progress.clone(), 0.);
        let output_path = transfer.path.clone();
        let cancellation_token = transfer.cancellation_token.clone();

        iced::Task::perform(
            async move {
                let mut peer_streams_lock = peer_streams.bistream.lock().await;

                // Create a buffer for the file transfer range. Need to send a `u64` start index and `u64` length.
                let mut bb = bytes::BytesMut::with_capacity(16);
                tokio::select! {
                    // Let the transfer be cancelled. This is not an error if cancelled.
                    () = cancellation_token.cancelled() => TransferResult::Cancelled,

                    // Await the file to be downloaded.
                    result = Box::pin(crate::core::download_from_peer(
                        hash,
                        &mut peer_streams_lock,
                        file_size,
                        &output_path,
                        &mut bb,
                        Some(&byte_progress),
                    )) => {
                        match result {
                            Ok(()) => TransferResult::Success,
                            Err(e) => TransferResult::Failure(Arc::new(anyhow::anyhow!("Download failed: {e}"))),
                        }
                    }
                }
            },
            move |r| Message::TransferResulted(nonce, r, FileYeetCommandType::Sub),
        )
    }

    /// Update the state after a publish was cancelled.
    fn update_cancel_publish(&mut self, nonce: Nonce) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState { publishes, .. }) =
            &mut self.connection_state
        {
            if let Some(i) = publishes.iter().position(|p| p.nonce == nonce) {
                // Cancel the publish task.
                publishes[i].cancellation_token.cancel();

                // If we have finished hashing, remove the publish from the list.
                if !matches!(&publishes[i].state, PublishState::Hashing(_)) {
                    publishes.remove(i);
                }
            }
        } else {
            eprintln!("{} No connected state to cancel publish", local_now_fmt());
        }
        iced::Task::none()
    }

    /// Update the state after a transfer was cancelled.
    fn update_cancel_transfer(
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
            if let Some(t) = transfers.iter_mut().find(|t| t.nonce == nonce) {
                // Cancel the download task.
                t.cancellation_token.cancel();

                // If waiting for user interaction, mark the transfer as cancelled.
                if matches!(t.progress, TransferProgress::Consent(_)) {
                    t.progress = TransferProgress::Done(TransferResult::Cancelled);
                }
            }
        } else {
            eprintln!("{} No connected state to cancel transfer", local_now_fmt());
        }
        iced::Task::none()
    }

    /// Update the state after a transfer has concluded, successfully or not.
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
            let mut transfers = match transfer_type {
                FileYeetCommandType::Sub => downloads.iter_mut(),
                FileYeetCommandType::Pub => uploads.iter_mut(),
            };

            if let Some(t) = transfers.find(|t| t.nonce == nonce) {
                // If the transfer was connected to a peer, remove the peer from the list of known peers.
                if let TransferProgress::Transferring(p, _, _) | TransferProgress::Consent(p) =
                    &t.progress
                {
                    let connection = &p.connection;
                    let peer_address = connection.remote_address();
                    if let std::collections::hash_map::Entry::Occupied(mut e) =
                        peers.entry(peer_address)
                    {
                        let nonces = &mut e.get_mut().1;
                        nonces.remove(&nonce);

                        // If there are no more streams to the peer, close the connection.
                        if nonces.is_empty() {
                            connection.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());
                            peers.remove(&peer_address);
                        }
                    }
                }

                t.progress = TransferProgress::Done(result);
            }
        } else {
            eprintln!(
                "{} No connected state to update transfer result",
                local_now_fmt()
            );
        }
        iced::Task::none()
    }

    /// Update the state after the user has chosen to remove a transfer entry.
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
            eprintln!("{} No connected state to remove transfer", local_now_fmt());
        }
        iced::Task::none()
    }

    /// Try to safely close.
    fn safely_close(&mut self, close_type: CloseType) -> iced::Task<Message> {
        if let ConnectionState::Connected(ConnectedState {
            endpoint,
            downloads,
            publishes,
            ..
        }) = &mut self.connection_state
        {
            self.options.last_publish_paths = publishes
                .drain(..)
                .filter_map(|p| {
                    // Ensure all publish tasks are cancelled.
                    p.cancellation_token.cancel();

                    // If the publish is valid or in progress, add it to the list of open publishes.
                    if matches!(
                        p.state,
                        PublishState::Publishing(_) | PublishState::Hashing(_)
                    ) {
                        Some(p.path)
                    } else {
                        None
                    }
                })
                .collect();

            self.options.last_downloads = downloads
                .drain(..)
                .filter_map(|d| {
                    // If the download is in progress, cancel it.
                    d.cancellation_token.cancel();

                    // Ensure all downloads that were in-progress are saved.
                    if let TransferProgress::Transferring(p, _, _) = d.progress {
                        Some(TransferBase {
                            hash: d.hash,
                            file_size: d.file_size,
                            peer_socket: p.connection.remote_address(),
                            path: d.path,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            endpoint.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());

            // Save the app settings when closing our connections.
            if let Err(e) = settings_path()
                .ok_or_else(|| {
                    anyhow::anyhow!("Could not determine a settings path for this environment.")
                })
                .and_then(|p| Ok(std::fs::File::create(p)?))
                .and_then(|f| Ok(serde_json::to_writer_pretty(f, &self.options)?))
            {
                eprintln!("{} Could not save settings: {e}", local_now_fmt());
            }
        };

        if let Some(port_mapping) = self.port_mapping.take() {
            // Set the state to `Stalling` before waiting for the safe close to complete.
            self.connection_state = ConnectionState::new_stalling();

            self.safely_closing = true;
            let port_mapping_timeout = Duration::from_millis(500);
            iced::Task::perform(
                tokio::time::timeout(port_mapping_timeout, async move {
                    if let Err((e, _)) = port_mapping.try_drop().await {
                        eprintln!(
                            "{} Could not safely remove port mapping: {e}",
                            local_now_fmt()
                        );
                    } else {
                        println!("{} Port mapping safely removed", local_now_fmt());
                    }
                }),
                // Force exit after completing the request or after a timeout.
                move |_| match close_type {
                    CloseType::Application => Message::ForceExit,
                    CloseType::Connections => Message::LeftServer,
                },
            )
        } else {
            match close_type {
                // Immediately exit if there isn't a port mapping to remove.
                CloseType::Application => {
                    iced::window::close(self.main_window.expect("Main window ID not found"))
                }

                // Close connections and return to the main screen.
                CloseType::Connections => {
                    self.connection_state = ConnectionState::Disconnected;
                    iced::Task::none()
                }
            }
        }
    }
}

/// Either an existing peer connection or a local endpoint and peer address to connect to.
enum PeerConnectionOrTarget {
    Connection(quinn::Connection),
    Target(quinn::Endpoint, SocketAddr),
}

/// A loop to await the server to send peers requesting the specified publish.
async fn peers_requesting_publish_loop(
    publish: Publish,
    nonce: Nonce,
    cancellation_token: CancellationToken,
    mut output: futures_channel::mpsc::Sender<Message>,
) {
    loop {
        let mut server = publish.server_streams.lock().await;

        tokio::select! {
            // Let the task be cancelled.
            () = cancellation_token.cancelled() => {
                if let Err(e) = server.send.write_u8(0).await {
                    eprintln!("{} Failed to cancel publish: {e}", local_now_fmt());
                }

                return;
            }

            // Await the server to send a peer connection.
            result = crate::core::read_subscribing_peer(&mut server.recv) => {
                if let Err(e) = output.try_send(Message::PublishPeerReceived(
                        nonce,
                        result.map_err(Arc::new),
                    ))
                {
                    eprintln!("{} Failed to perform internal message passing for subscription peer: {e}", local_now_fmt());
                }
            }
        }
    }
}

/// An asynchronous loop to await new peer connections.
async fn incoming_peer_connection_loop(
    endpoint: quinn::Endpoint,
    mut output: futures_channel::mpsc::Sender<Message>,
) {
    while let Some(connection) = endpoint.accept().await {
        if let Ok(connection) = connection.await {
            if let Err(e) = output.try_send(Message::PeerConnected(connection)) {
                eprintln!(
                    "{} Failed to perform internal message passing for peer connected: {e}",
                    local_now_fmt()
                );
            }
        }
    }

    // The endpoint has been closed.
}

/// An asynchronous loop to await new requests from a peer connection.
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
                if let Err(e) = streams.recv.read_exact(&mut hash).await {
                    eprintln!("{} Failed to read hash from peer: {e}", local_now_fmt());
                    continue;
                }

                if let Err(e) = output.try_send(Message::PeerRequestedTransfer((
                    hash,
                    PeerRequestStream::new(connection.clone(), streams),
                ))) {
                    eprintln!(
                        "{} Failed to perform internal message passing for peer requested stream: {e}",
                        local_now_fmt()
                    );
                }
            }

            Err(e) => {
                println!(
                    "{} Peer connection closed: {peer_address} {e}",
                    local_now_fmt()
                );

                // The peer has disconnected or the connection deteriorated.
                if let Err(e) = output.try_send(Message::PeerDisconnected(peer_address)) {
                    eprintln!(
                        "{} Failed to perform internal message passing for failed peer stream: {e}",
                        local_now_fmt()
                    );
                }
                return;
            }
        }
    }
}

/// Try to establish a peer connection for a command type.
/// Either starts from an existing connection or attempts to holepunch.
async fn try_peer_connection(
    peer: PeerConnectionOrTarget,
    hash: HashBytes,
    cmd: FileYeetCommandType,
) -> Option<PeerRequestStream> {
    use PeerConnectionOrTarget::{Connection, Target};
    tokio::time::timeout(PEER_CONNECT_TIMEOUT, async move {
        match peer {
            Connection(c) => crate::core::peer_connection_into_stream(&c, hash, cmd)
                .await
                .map(|s| (c, s)),

            Target(e, peer) => crate::core::udp_holepunch(cmd, hash, e, peer).await,
        }
        .map(PeerRequestStream::from)
    })
    .await
    .ok()
    .flatten()
}

/// Add the nonce of a transaction to a peer's set of known transactions.
fn insert_nonce_for_peer(
    connection: &PeerRequestStream,
    peers: &mut HashMap<SocketAddr, (quinn::Connection, HashSet<Nonce>)>,
    peer_address: SocketAddr,
    nonce: Nonce,
) {
    match peers.entry(peer_address) {
        std::collections::hash_map::Entry::Vacant(e) => {
            // Add the peer into our map of known peer addresses.
            e.insert((connection.connection.clone(), HashSet::from([nonce])));
        }
        std::collections::hash_map::Entry::Occupied(mut e) => {
            // Add the transfer nonce to the peer's set of known transfer nonces.
            e.get_mut().1.insert(nonce);
        }
    }
}

/// Either close all connections or the entire application.
#[derive(Clone, Copy, Debug)]
enum CloseType {
    Connections,
    Application,
}

const INVALID_PORT_FORWARD: &str = "Invalid port forward. Defaults to no port mappings.";
