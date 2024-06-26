use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU16,
    ops::Div as _,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use file_yeet_shared::{
    local_now_fmt, BiStream, HashBytes, DEFAULT_PORT, GOODBYE_CODE, GOODBYE_MESSAGE,
    MAX_SERVER_COMMUNICATION_SIZE,
};
use futures_util::SinkExt;
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

/// Lazyily initialized regex for parsing server addresses.
/// Produces match groups `host` and `port` for the server address and optional port.
static SERVER_ADDRESS_REGEX: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^\s*(?P<host>([^:]|::)+)(?::(?P<port>\d+))?\s*$").unwrap()
    });

/// The maximum time to wait before forcing the application to exit.
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The red used to display errors to the user.
const ERROR_RED_COLOR: iced::Color = iced::Color::from_rgb(1., 0.4, 0.5);

/// The labels for the port mapping radio buttons.
const PORT_MAPPING_OPTION_LABELS: [&str; 3] = ["None", "Port forward", "NAT-PMP / PCP"];

/// The state of the port mapping options in the GUI.
#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
enum PortMappingGuiOptions {
    #[default]
    None,
    PortForwarding(Option<NonZeroU16>),
    TryPcpNatPmp,
}

/// A peer connection in QUIC for requesting or serving a file to a peer.
#[derive(Clone, Debug)]
pub struct PeerConnection {
    pub connection: quinn::Connection,
    pub streams: Arc<tokio::sync::Mutex<BiStream>>,
}
impl PeerConnection {
    /// Make a new `PeerConnection` from a QUIC connection and a bi-directional stream.
    #[must_use]
    pub fn new(connection: quinn::Connection, streams: BiStream) -> Self {
        Self {
            connection,
            streams: Arc::new(tokio::sync::Mutex::new(streams)),
        }
    }
}
impl From<(quinn::Connection, BiStream)> for PeerConnection {
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
    Consent(PeerConnection),
    Transferring(PeerConnection, Arc<RwLock<f32>>, f32),
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
    Hashing(Arc<RwLock<f32>>),
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
        hash_progress: Arc<RwLock<f32>>,
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
    pub port_mapping: PortMappingGuiOptions,
    pub last_publish_paths: Vec<PathBuf>,
    pub last_downloads: Vec<(PathBuf, HashBytes)>,
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
}

/// The messages that can be sent to the update loop of the application.
#[derive(Clone, Debug)]
pub enum Message {
    /// The server text field was changed.
    ServerAddressChanged(String),

    /// The port mapping radio button was changed.
    PortMappingRadioChanged(&'static str),

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

    /// The result of trying to recieve a peer to publish to from the server.
    PublishPeerReceived(Nonce, Result<SocketAddr, Arc<anyhow::Error>>),

    /// The result of trying to connect to a peer to publish to.
    PublishPeerConnectResulted(Nonce, Option<PeerConnection>),

    /// The subscribe button was clicked or the hash field was submitted.
    SubscribeStarted,

    /// The path to save a file to was chosen or cancelled.
    SubscribePathChosen(Option<PathBuf>),

    /// A subscribe request was completed.
    SubscribePeersResult(Result<IncomingSubscribePeers, Arc<anyhow::Error>>),

    /// A subscribe connection attempt was completed.
    SubscribePeerConnectResulted(Nonce, Option<PeerConnection>),

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
    UnhandledEvent(iced::Event),

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
impl iced::Application for AppState {
    type Message = Message;
    type Theme = iced::Theme;
    type Executor = iced::executor::Default;
    type Flags = Option<crate::Cli>;

    /// Create a new application state.
    fn new(args: Self::Flags) -> (AppState, iced::Command<Message>) {
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
        if let Some(crate::Cli {
            server_address,
            port_override,
            gateway,
            nat_map,
            ..
        }) = args
        {
            if let Some(server_address) = server_address {
                settings.server_address = server_address;
            }
            if let Some(gateway) = gateway {
                settings.gateway_address = Some(gateway);
            }
            if let Some(port) = port_override {
                settings.port_forwarding_text = port.to_string();
                settings.port_mapping = PortMappingGuiOptions::PortForwarding(Some(port));
            } else if nat_map {
                settings.port_mapping = PortMappingGuiOptions::TryPcpNatPmp;
            }
        }
        let server_address_is_empty = settings.server_address.is_empty();

        // Create the initial state with the settings.
        let mut initial_state = Self {
            options: settings,
            ..Self::default()
        };

        // Try connecting immediately if the server address is already set.
        let command = if server_address_is_empty {
            iced::Command::none()
        } else {
            initial_state.update_connect_clicked()
        };
        (initial_state, command)
    }

    /// Get the application title text.
    fn title(&self) -> String {
        String::from("file_yeet_client")
    }

    /// Update the application state based on a message.
    fn update(&mut self, message: Message) -> iced::Command<Message> {
        match message {
            // Handle the server address being changed.
            Message::ServerAddressChanged(address) => {
                self.options.server_address = address;
                iced::Command::none()
            }

            // Handle the port mapping radio button being changed.
            Message::PortMappingRadioChanged(label) => self.update_port_radio_changed(label),

            // Handle the port forward text field being changed.
            Message::PortForwardTextChanged(text) => self.update_port_forward_text(text),

            // Handle the gateway text field being changed.
            Message::GatewayTextChanged(text) => self.update_gateway_text(text),

            // Handle the publish button being clicked by picking a file to publish.
            Message::ConnectClicked => self.update_connect_clicked(),

            // The animation tick doesn't need anything special besides updating the tick state.
            Message::AnimationTick => self.update_animation_tick(),

            // Handle the result of a connection attempt.
            Message::ConnectResulted(r) => self.update_connect_resulted(r),

            // Copy the connected server address to the clipboard.
            Message::CopyServer => iced::clipboard::write(self.options.server_address.clone()),

            // Leave the server and disconnect.
            Message::SafelyLeaveServer => self.safely_close(CloseType::Connections),

            // All async actions to leave a server have completed.
            Message::LeftServer => {
                self.safely_closing = false;
                self.connection_state = ConnectionState::Disconnected;
                iced::Command::none()
            }

            // The transfer view radio buttons were changed.
            Message::TransferViewChanged(view) => {
                if let ConnectionState::Connected(connected_state) = &mut self.connection_state {
                    connected_state.transfer_view = view;
                }
                iced::Command::none()
            }

            // Handle the hash input being changed.
            Message::HashInputChanged(hash) => {
                if let ConnectionState::Connected(ConnectedState { hash_input, .. }) =
                    &mut self.connection_state
                {
                    *hash_input = hash;
                }
                iced::Command::none()
            }

            // Handle the publish button being clicked by picking a file to publish.
            Message::PublishClicked => {
                // Clear the status message before starting the publish attempt.
                self.status_message = None;

                // Let state know that a modal dialog is open.
                self.modal = true;

                iced::Command::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file to publish")
                        .pick_file(),
                    |f| Message::PublishPathChosen(f.map(PathBuf::from)),
                )
            }

            // Begin the process of publishing a file to the server.
            Message::PublishPathChosen(path) => self.update_publish_path_chosen(path),

            // Handle the result of a publish request.
            Message::PublishRequestResulted(nonce, path, r) => {
                self.update_publish_request_resulted(nonce, &path, r)
            }

            // Handle a peer connection being received for a publish request.
            Message::PublishPeerReceived(nonce, r) => self.update_publish_peer_received(nonce, r),

            // Handle the result of a peer connection attempt for a publish request.
            Message::PublishPeerConnectResulted(pub_nonce, peer) => {
                self.update_publish_peer_connect_resulted(pub_nonce, peer)
            }

            // Handle the subscribe button being clicked by choosing a save location.
            Message::SubscribeStarted => {
                // Clear the status message before starting the subscribe attempt.
                self.status_message = None;

                // Let state know that a modal dialog is open.
                self.modal = true;

                iced::Command::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file path to save to")
                        .save_file(),
                    |f| Message::SubscribePathChosen(f.map(PathBuf::from)),
                )
            }

            // Begin the process of subscribing to a file from the server.
            Message::SubscribePathChosen(path) => self.update_subscribe_path_chosen(path),

            // Handle the result of a subscribe request.
            Message::SubscribePeersResult(r) => self.update_subscribe_peers_result(r),

            // Handle the result of a subscribe connection attempt to a peer.
            Message::SubscribePeerConnectResulted(nonce, r) => {
                self.update_subscribe_connect_resulted(nonce, r)
            }

            // Handle the download being accepted, initiate the download.
            Message::AcceptDownload(nonce) => self.update_accept_download(nonce),

            // Copy a hash to the clipboard.
            Message::CopyHash(hash) => iced::clipboard::write(hash),

            // Set the cancellation token to notify the publishing thread to cancel.
            Message::CancelPublish(nonce) => self.update_cancel_publish(nonce),

            // Handle a transfer being cancelled.
            Message::CancelTransfer(nonce, transfer_type) => {
                self.update_cancel_transfer(nonce, transfer_type)
            }

            // Handle the conclusive result of a transfer.
            Message::TransferResulted(nonce, r, transfer_type) => {
                self.update_transfer_resulted(nonce, r, transfer_type)
            }

            // Handle a file being opened.
            Message::OpenFile(path) => {
                open::that(path).unwrap_or_else(|e| {
                    eprintln!("{} Failed to open file: {e}", local_now_fmt());
                });
                iced::Command::none()
            }

            // Handle a transfer being removed from the downloads list.
            Message::RemoveFromTransfers(nonce, transfer_type) => {
                self.update_remove_from_transfers(nonce, transfer_type)
            }

            // Handle an event that iced did not handle itself.
            // This is used to allow for custom exit handling in this instance.
            Message::UnhandledEvent(event) => match event {
                iced::Event::Window(id, window::Event::CloseRequested) => {
                    if id == window::Id::MAIN && !self.safely_closing {
                        self.safely_close(CloseType::Application)
                    } else {
                        // Non-main windows (if ever implemented) can be closed immediately.
                        // This is also used to cancel the safe-close operation.
                        window::close(id)
                    }
                }
                _ => iced::Command::none(),
            },

            // Exit the application immediately.
            Message::ForceExit => window::close(window::Id::MAIN),
        }
    }

    /// Listen for events that should be translated into messages.
    fn subscription(&self) -> iced::Subscription<Message> {
        // Listen for runtime events that iced did not handle internally. Used for safe exit handling.
        let close_event = || iced::event::listen().map(Message::UnhandledEvent);

        // Listen for timing intervals to update animations.
        let animation =
            || iced::time::every(Duration::from_millis(33)).map(|_| Message::AnimationTick);

        match &self.connection_state {
            // Listen for close events and animation ticks when connecting/stalling.
            ConnectionState::Stalling { .. } => {
                iced::Subscription::batch([close_event(), animation()])
            }

            ConnectionState::Connected(ConnectedState { publishes, .. }) => {
                let pubs = publishes.iter().filter_map(|publish| {
                    // If the publish is still hashing, nothing to loop yet.
                    let PublishItem { nonce, cancellation_token, state: PublishState::Publishing(publish), .. } = &publish else { return None; };
                    let nonce = *nonce;
                    let cancellation_token = cancellation_token.clone();
                    let publish = publish.clone();

                    // Subscribe to the server for new peers to upload to.
                    Some(iced::subscription::channel(nonce, 10, move |mut output| async move {
                        loop {
                            let mut server = publish.server_streams.lock().await;

                            tokio::select! {
                                // Let the task be cancelled.
                                () = cancellation_token.cancelled() => {
                                    if let Err(e) = server.send.write_u8(0).await {
                                        eprintln!("{} Failed to cancel publish: {e}", local_now_fmt());
                                    }

                                    // Provide a brief wait for the task to be cancelled.
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                    println!("{} Dead publish task is still running...", local_now_fmt());
                                }

                                // Await the server to send a peer connection.
                                result = crate::core::read_subscribing_peer(&mut server.recv) => {
                                    if let Err(e) = output
                                        .send(Message::PublishPeerReceived(
                                            nonce,
                                            result.map_err(Arc::new),
                                        ))
                                        .await
                                    {
                                        eprintln!("{} Failed to perform internal message passing: {e}", local_now_fmt());
                                    }
                                }
                            }
                        }
                    }))
                });

                iced::Subscription::batch([close_event(), animation()].into_iter().chain(pubs))
            }

            // Listen for close events alone when disconnected.
            ConnectionState::Disconnected => close_event(),
        }
    }

    /// Draw the application GUI.
    fn view(&self) -> iced::Element<Message> {
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
                    ).align_items(iced::Alignment::Center).into()
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
                    .style(iced::theme::Text::Color(ERROR_RED_COLOR))
                    .width(iced::Length::Fill)
                    .height(iced::Length::Shrink),
            )
        } else {
            widget::horizontal_space().into()
        });
        widget::column!(page, status_bar).padding(6).into()
    }

    /// Prefer a dark theme.
    fn theme(&self) -> iced::Theme {
        iced::Theme::Dark
    }
}

impl AppState {
    /// Draw the disconnected page with a server address input and connect button.
    fn view_disconnected_page(&self) -> iced::Element<Message> {
        let mut server_address = widget::text_input(
            "Server address. E.g., localhost:7828",
            &self.options.server_address,
        );

        let mut connect_button = widget::button("Connect");
        let mut port_forward_text = widget::text_input(
            "External port forward. E.g., 8888",
            &self.options.port_forwarding_text,
        );

        if !self.modal {
            server_address = server_address
                .on_input(Message::ServerAddressChanged)
                .on_submit(Message::ConnectClicked);
            connect_button = connect_button.on_press(Message::ConnectClicked);

            if let PortMappingGuiOptions::PortForwarding(_) = &self.options.port_mapping {
                port_forward_text = port_forward_text.on_input(Message::PortForwardTextChanged);
            }
        }

        let selected = match self.options.port_mapping {
            PortMappingGuiOptions::None => PORT_MAPPING_OPTION_LABELS[0],
            PortMappingGuiOptions::PortForwarding(_) => PORT_MAPPING_OPTION_LABELS[1],
            PortMappingGuiOptions::TryPcpNatPmp => PORT_MAPPING_OPTION_LABELS[2],
        };

        // Create a bottom section for choosing port forwaring/mapping options.
        let choose_port_mapping = widget::column!(
            widget::radio(
                PORT_MAPPING_OPTION_LABELS[0],
                PORT_MAPPING_OPTION_LABELS[0],
                Some(selected),
                Message::PortMappingRadioChanged,
            ),
            widget::row!(
                widget::radio(
                    PORT_MAPPING_OPTION_LABELS[1],
                    PORT_MAPPING_OPTION_LABELS[1],
                    Some(selected),
                    Message::PortMappingRadioChanged,
                ),
                port_forward_text,
            )
            .spacing(32),
            widget::radio(
                PORT_MAPPING_OPTION_LABELS[2],
                PORT_MAPPING_OPTION_LABELS[2],
                Some(selected),
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
        .align_items(iced::Alignment::Center);

        widget::container(
            widget::column!(
                widget::vertical_space(),
                server_address,
                connect_button,
                widget::vertical_space().height(iced::Length::FillPortion(2)),
                choose_port_mapping,
                gateway,
            )
            .align_items(iced::Alignment::Center)
            .spacing(6),
        )
        .width(iced::Length::Fill)
        .height(iced::Length::Fill)
        .center_x()
        .center_y()
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
                .width(iced::Length::Fill)
                .height(iced::Length::Fill)
                .padding(24)
                .center_x()
                .center_y();

        Element::<'a>::from(spinner)
    }

    fn draw_transfers<'a, 'b, I>(
        transfers: I,
        transfer_type: FileYeetCommandType,
    ) -> iced::Element<'b, Message>
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
                    widget::text("Transfering..."),
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
                        widget::text(r).width(iced::Length::Fill),
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
                    widget::text(&t.path.to_string_lossy()).size(12),
                )
                .spacing(6),
            ))
            .style(iced::theme::Container::Box)
            .width(iced::Length::Fill)
            .padding([6, 12, 6, 6]) // Extra padding on the right because of optional scrollbar.
            .into()
        }))
        .spacing(6)
        .into()
    }

    fn draw_pubs<'a>(publishes: &[PublishItem]) -> iced::Element<'a, Message> {
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
                            widget::text(&pi.path.to_string_lossy()).size(12),
                        )
                        .spacing(6),
                        widget::button("Cancel").on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Publishing(p) => widget::row!(
                        widget::column!(
                            widget::text(&p.hash_hex).size(12),
                            widget::text(&pi.path.to_string_lossy()).size(12)
                        ),
                        widget::horizontal_space(),
                        widget::button(widget::text("Copy Hash").size(12))
                            .on_press(Message::CopyHash(p.hash_hex.clone())),
                        widget::button(widget::text("Cancel").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Failure(e) => widget::row!(
                        widget::column!(
                            widget::text(format!("Failed to publish: {e}"))
                                .style(iced::theme::Text::Color(ERROR_RED_COLOR)),
                            widget::text(&pi.path.to_string_lossy()).size(12),
                        )
                        .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Cancelled => widget::row!(
                        widget::column!(
                            widget::text("Cancelled"),
                            widget::text(&pi.path.to_string_lossy()).size(12),
                        )
                        .width(iced::Length::Fill),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                }
                .align_items(iced::Alignment::Center)
                .spacing(12),
            )
            .style(iced::theme::Container::Box)
            .width(iced::Length::Fill)
            .padding([6, 12, 6, 6]) // Extra padding on the right because of optional scrollbar.
            .into()
        });

        widget::column(publish_views).spacing(6).into()
    }

    /// Draw the main application controls when connected to a server.
    fn view_connected_page(&self, connected_state: &ConnectedState) -> iced::Element<Message> {
        /// Helper for creating a horizontal line.
        fn horizontal_line<'a>() -> widget::Container<'a, Message> {
            widget::container(horizontal_space())
                .height(3)
                .style(iced::theme::Container::Box)
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
        .align_items(iced::alignment::Alignment::Center)
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
                    (true, true) => iced::widget::space::Space::new(0, 0).into(),

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
    fn update_port_radio_changed(&mut self, label: &'static str) -> iced::Command<Message> {
        self.options.port_mapping = match label {
            "None" => {
                self.status_message = None;
                PortMappingGuiOptions::None
            }
            "Port forward" => PortMappingGuiOptions::PortForwarding({
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
            "NAT-PMP / PCP" => {
                self.status_message = None;
                PortMappingGuiOptions::TryPcpNatPmp
            }
            _ => unreachable!(),
        };
        iced::Command::none()
    }

    /// Update the state after the port forward text field was changed.
    fn update_port_forward_text(&mut self, text: String) -> iced::Command<Message> {
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
        iced::Command::none()
    }

    // Update the state after the gateway text field was changed.
    fn update_gateway_text(&mut self, text: String) -> iced::Command<Message> {
        if text.trim().is_empty() {
            self.options.gateway_address = None;
        } else {
            self.options.gateway_address = Some(text);
        }
        iced::Command::none()
    }

    /// Update the state after the connect button was clicked.
    fn update_connect_clicked(&mut self) -> iced::Command<Message> {
        // Clear the status message before starting the connection attempt.
        self.status_message = None;

        // Determine if a valid server address was entered.
        let regex_match = if self.options.server_address.trim().is_empty() {
            // If empty, use sane defaults.
            self.options.server_address = "localhost".to_owned();
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
            return iced::Command::none();
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
        iced::Command::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::prepare_server_connection(
                    server_address.as_deref(),
                    port,
                    gateway.as_deref(),
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
    fn update_animation_tick(&mut self) -> iced::Command<Message> {
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
        iced::Command::none()
    }

    /// Update the state after a connection attempt to the server completed.
    fn update_connect_resulted(
        &mut self,
        result: Result<PreparedConnection, Arc<anyhow::Error>>,
    ) -> iced::Command<Message> {
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
                if !self.options.last_publish_paths.is_empty() {
                    return iced::Command::batch(self.options.last_publish_paths.drain(..).map(
                        |p| {
                            iced::Command::perform(
                                std::future::ready(Some(p)),
                                Message::PublishPathChosen,
                            )
                        },
                    ));
                }
            }
            Err(e) => {
                self.status_message = Some(format!("Error connecting: {e}"));
                self.connection_state = ConnectionState::Disconnected;
            }
        }
        iced::Command::none()
    }

    /// Update the state after the publish button was clicked. Begins a publish request if a file was chosen.
    fn update_publish_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Command<Message> {
        self.modal = false;

        // Ensure a path was chosen.
        let Some(path) = path else {
            return iced::Command::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            server,
            publishes,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Ensure the transfer view is set to publishing to see the new item.
        *transfer_view = TransferView::Publishes;

        let server = server.clone();
        let progress = Arc::new(RwLock::new(0.));
        let nonce = rand::random();
        let cancellation_token = CancellationToken::new();
        let cancellation_path = path.clone();

        publishes.push(PublishItem::new(
            nonce,
            path.clone(),
            cancellation_token.clone(),
            progress.clone(),
        ));
        iced::Command::perform(
            async move {
                tokio::select! {
                    // Allow cancelling the publish request thread.
                    () = cancellation_token.cancelled() => (PublishRequestResult::Cancelled, cancellation_path),

                    r = async move {
                        // Get the file size and hash of the chosen file to publish.
                        let (file_size, hash) =
                            match crate::core::file_size_and_hash(&path, Some(progress)).await {
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
    ) -> iced::Command<Message> {
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
        iced::Command::none()
    }

    /// Update after the server has sent a peer to publish to, or there was an error.
    fn update_publish_peer_received(
        &mut self,
        nonce: Nonce,
        result: Result<SocketAddr, Arc<anyhow::Error>>,
    ) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState {
            endpoint,
            peers,
            publishes,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
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
                // TODO: A task will listen for connected peers. At that point we should only attempt something if not already connected.
                let data = if let Some((c, _)) = peers.get(&peer) {
                    Ok(c.clone())
                } else {
                    Err(endpoint.clone())
                };
                let hash = publish.hash;
                iced::Command::perform(
                    async move {
                        match data {
                            Ok(c) => crate::core::peer_connection_into_stream(
                                &c,
                                hash,
                                FileYeetCommandType::Pub,
                            )
                            .await
                            .map(|b| (c, b)),
                            Err(e) => {
                                crate::core::udp_holepunch(FileYeetCommandType::Pub, hash, e, peer)
                                    .await
                            }
                        }
                    },
                    move |r| {
                        Message::PublishPeerConnectResulted(
                            nonce,
                            r.map(Into::<PeerConnection>::into),
                        )
                    },
                )
            }
            (Err(e), _) => {
                self.status_message = Some(format!("Error receiving peer: {e}"));
                iced::Command::none()
            }
            (_, None) => iced::Command::none(),
        }
    }

    /// Update after a connection attempt to a peer for publishing has completed.
    fn update_publish_peer_connect_resulted(
        &mut self,
        pub_nonce: Nonce,
        peer: Option<PeerConnection>,
    ) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers,
            uploads,
            publishes,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };
        let Some(peer) = peer else {
            // Silently fail if the peer connection was not successful.
            return iced::Command::none();
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
            return iced::Command::none();
        };

        let upload_nonce = rand::random();
        let progress_lock = Arc::new(RwLock::new(0.));
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

        let peer_address = peer.connection.remote_address();
        match peers.entry(peer_address) {
            std::collections::hash_map::Entry::Vacant(e) => {
                // Add the peer into our map of known peer addresses.
                e.insert((peer.connection.clone(), HashSet::from([upload_nonce])));
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                // Add the transfer nonce to the peer's set of known transfer nonces.
                e.get_mut().1.insert(upload_nonce);
            }
        }

        let file_size = publishing.file_size;
        iced::Command::perform(
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
                let mut streams = peer.streams.lock().await;

                tokio::select! {
                    () = cancellation_token.cancelled() => TransferResult::Cancelled,
                    result = Box::pin(crate::core::upload_to_peer(
                        &mut streams,
                        file_size,
                        reader,
                        Some(progress_lock),
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
    fn update_subscribe_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Command<Message> {
        self.modal = false;

        // Ensure a path was chosen.
        let Some(path) = path else {
            return iced::Command::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected(ConnectedState {
            server,
            hash_input,
            transfer_view,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Ensure the hash is valid.
        let mut hash = HashBytes::default();
        if let Err(e) = faster_hex::hex_decode(hash_input.as_bytes(), &mut hash) {
            self.status_message = Some(format!("Invalid hash: {e}"));
            return iced::Command::none();
        }

        // Ensure the transfer view is set to downloads to see the new item.
        *transfer_view = TransferView::Downloads;

        let server = server.clone();
        iced::Command::perform(
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

    /// Update after server has responded to a subscribe request.
    fn update_subscribe_peers_result(
        &mut self,
        result: Result<IncomingSubscribePeers, Arc<anyhow::Error>>,
    ) -> iced::Command<Message> {
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
                        return iced::Command::none();
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
                                // Allow creating a new connection or opening a stream on an existing one.
                                // TODO: Create an enum for this instead of using a `Result`.
                                let data = {
                                    if let Some((c, _)) = peers.get(&peer) {
                                        Ok(c.clone())
                                    } else {
                                        Err(endpoint.clone())
                                    }
                                };
                                // The future to use to create the connection.
                                let future = async move {
                                    tokio::time::timeout(PEER_CONNECT_TIMEOUT, async move {
                                        match data {
                                            Ok(c) => crate::core::peer_connection_into_stream(
                                                &c,
                                                hash,
                                                FileYeetCommandType::Sub,
                                            )
                                            .await
                                            .map(|s| (c, s)),
                                            Err(e) => {
                                                crate::core::udp_holepunch(
                                                    FileYeetCommandType::Sub,
                                                    hash,
                                                    e,
                                                    peer,
                                                )
                                                .await
                                            }
                                        }
                                        .map(PeerConnection::from)
                                    })
                                    .await
                                    .ok()
                                    .flatten()
                                };
                                iced::Command::perform(future, move |r| {
                                    Message::SubscribePeerConnectResulted(nonce, r)
                                })
                            };

                            // Return the pair to be separated later.
                            (transfer, command)
                        });

                    // Create a new transfer for each peer.
                    let (mut new_transfers, connect_commands): (
                        Vec<Transfer>,
                        Vec<iced::Command<Message>>,
                    ) = transfers_commands_iter.unzip();

                    // Add the new transfers to the list of active transfers.
                    downloads.append(&mut new_transfers);
                    iced::Command::batch(connect_commands)
                } else {
                    iced::Command::none()
                }
            }
            Err(e) => {
                self.status_message = Some(format!("Error subscribing to the server: {e}"));
                iced::Command::none()
            }
        }
    }

    /// Update the state after a subscribe connection attempt to a peer completed.
    fn update_subscribe_connect_resulted(
        &mut self,
        nonce: Nonce,
        result: Option<PeerConnection>,
    ) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState {
            peers, downloads, ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Find the transfer with the matching nonce.
        let Some((index, transfer)) = downloads
            .iter_mut()
            .enumerate()
            .find(|(_, t)| t.nonce == nonce)
        else {
            return iced::Command::none();
        };

        // Update the state of the transfer with the result.
        if let Some(connection) = result {
            let peer_address = connection.connection.remote_address();
            // TODO: Refactor into a function.
            match peers.entry(peer_address) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    // Add the peer into our map of known peer addresses.
                    e.insert((connection.connection.clone(), HashSet::from([nonce])));
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Add the transfer nonce to the peer's set of known transfers.
                    e.get_mut().1.insert(nonce);
                }
            }

            transfer.progress = TransferProgress::Consent(connection);
        } else {
            // Remove unreachable peers from view.
            downloads.remove(index);
        }
        iced::Command::none()
    }

    /// Tell the peer to send the file and begin recieving and writing the file.
    fn update_accept_download(&mut self, nonce: Nonce) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState { downloads, .. }) =
            &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Get the current transfer status.
        let Some(transfer) = downloads.iter_mut().find(|t| t.nonce == nonce) else {
            return iced::Command::none();
        };
        let hash = transfer.hash;
        let file_size = transfer.file_size;
        let peer_streams = if let TransferProgress::Consent(p) = &mut transfer.progress {
            p.clone()
        } else {
            return iced::Command::none();
        };

        // Begin the transfer.
        let byte_progress = Arc::new(RwLock::new(0.));
        transfer.progress =
            TransferProgress::Transferring(peer_streams.clone(), byte_progress.clone(), 0.);
        let output_path = transfer.path.clone();
        let cancellation_token = transfer.cancellation_token.clone();

        iced::Command::perform(
            async move {
                let mut peer_streams_lock = peer_streams.streams.lock().await;

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
                        Some(byte_progress),
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

    /// Update the state after a transfer was cancelled.
    fn update_cancel_publish(&mut self, nonce: Nonce) -> iced::Command<Message> {
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
        }
        iced::Command::none()
    }

    /// Update the state after a transfer was cancelled.
    fn update_cancel_transfer(
        &mut self,
        nonce: Nonce,
        transfer_type: FileYeetCommandType,
    ) -> iced::Command<Message> {
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
        }
        iced::Command::none()
    }

    /// Update the state after a transfer was completed.
    fn update_transfer_resulted(
        &mut self,
        nonce: Nonce,
        result: TransferResult,
        transfer_type: FileYeetCommandType,
    ) -> iced::Command<Message> {
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
        }
        iced::Command::none()
    }

    /// Update the state after the user has chosen to remove a transfer entry.
    fn update_remove_from_transfers(
        &mut self,
        nonce: Nonce,
        transfer_type: FileYeetCommandType,
    ) -> iced::Command<Message> {
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
        }
        iced::Command::none()
    }

    /// Try to safely close.
    fn safely_close(&mut self, close_type: CloseType) -> iced::Command<Message> {
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
                    if matches!(d.progress, TransferProgress::Transferring(_, _, _)) {
                        Some((d.path, d.hash))
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
            iced::Command::perform(
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
                // Force exist after completing the request or after a timeout.
                move |_| match close_type {
                    CloseType::Application => Message::ForceExit,
                    CloseType::Connections => Message::LeftServer,
                },
            )
        } else {
            match close_type {
                // Immediately exit if there isn't a port mapping to remove.
                CloseType::Application => window::close(window::Id::MAIN),

                CloseType::Connections => {
                    self.connection_state = ConnectionState::Disconnected;
                    iced::Command::none()
                }
            }
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
