use std::{
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
use iced::{widget, window, Element};
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
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
    Consent(PeerConnection, u64),
    Transfering(PeerConnection, Arc<RwLock<u64>>, u64, f32),
    Done(TransferResult),
}

/// Nonce used to identifying items locally.
type Nonce = u64;

/// A file transfer with a peer in any state.
#[derive(Debug)]
struct Transfer {
    pub nonce: Nonce,
    pub hash: HashBytes,
    pub hash_hex: String,
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

    /// List of download requests to peers.
    downloads: Vec<Transfer>,

    /// List of file publish requests to the server.
    publishes: Vec<PublishItem>,

    /// List of file uploads to peers.
    uploads: Vec<Transfer>,
}
impl ConnectedState {
    fn new(endpoint: quinn::Endpoint, server: quinn::Connection, external_address: String) -> Self {
        Self {
            endpoint,
            server,
            external_address,
            hash_input: String::new(),
            downloads: Vec::new(),
            publishes: Vec::new(),
            uploads: Vec::new(),
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

/// The current settings for the app.
#[derive(Default, serde::Deserialize, serde::Serialize)]
struct AppSettings {
    pub server_address: String,
    pub port_forwarding_text: String,
    pub port_mapping: PortMappingGuiOptions,
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
    SubscribePeersResult(Result<(Vec<SocketAddr>, PathBuf, HashBytes), Arc<anyhow::Error>>),

    /// A subscribe connection attempt was completed.
    SubscribePeerConnectResulted(Nonce, Option<(PeerConnection, u64)>),

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
    type Flags = (Option<String>, Option<NonZeroU16>, bool);

    /// Create a new application state.
    fn new((server_address, port, nat_map): Self::Flags) -> (AppState, iced::Command<Message>) {
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
        if let Some(server_address) = &server_address {
            settings.server_address = server_address.clone();
        }
        if let Some(port) = port {
            settings.port_forwarding_text = port.to_string();
            settings.port_mapping = PortMappingGuiOptions::PortForwarding(Some(port));
        } else if nat_map {
            settings.port_mapping = PortMappingGuiOptions::TryPcpNatPmp;
        }

        (
            Self {
                options: settings,
                ..Self::default()
            },
            iced::Command::none(),
        )
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
                                result = crate::core::read_publish_response(&mut server.recv) => {
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

        widget::container(
            widget::column!(
                widget::vertical_space(),
                server_address,
                connect_button,
                widget::vertical_space().height(iced::Length::FillPortion(2)),
                choose_port_mapping
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
        let spinner = widget::container::Container::new(widget::progress_bar(
            0.0..=1.,
            (tick - start)
                .as_secs_f32()
                .div(max_duration.as_secs_f32())
                .fract(),
        ))
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
                TransferProgress::Consent(_, size) => widget::row!(
                    widget::text(format!("Accept download of size {}", humanize_bytes(*size)))
                        .width(iced::Length::Fill),
                    widget::button(widget::text("Accept").size(12))
                        .on_press(Message::AcceptDownload(t.nonce)),
                    widget::button(widget::text("Cancel").size(12))
                        .on_press(Message::CancelTransfer(t.nonce, transfer_type))
                )
                .spacing(12)
                .into(),
                TransferProgress::Transfering(_, _, _, p) => widget::row!(
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
            .padding(6)
            .into()
        }))
        .spacing(6)
        .into()
    }

    /// Draw the main application controls when connected to a server.
    fn view_connected_page(&self, connected_state: &ConnectedState) -> iced::Element<Message> {
        let mut publish_button = widget::button("Publish");
        let mut download_button = widget::button("Download");
        let mut hash_text_input = widget::text_input("Hash", &connected_state.hash_input);

        // Disable the inputs while a modal is open.
        if !self.modal {
            publish_button = publish_button.on_press(Message::PublishClicked);
            hash_text_input = hash_text_input.on_input(Message::HashInputChanged);

            // Enable the download button if the hash is valid.
            if connected_state.hash_input.len() == file_yeet_shared::HASH_BYTE_COUNT << 1
                && faster_hex::hex_check(connected_state.hash_input.as_bytes())
            {
                download_button = download_button.on_press(Message::SubscribeStarted);
                hash_text_input = hash_text_input.on_submit(Message::SubscribeStarted);
            }
        }

        // Hash input and download button.
        let download_input = widget::row!(hash_text_input, download_button).spacing(6);

        // Create a list of downloads.
        let downloads: Element<Message> =
            Self::draw_transfers(connected_state.downloads.iter(), FileYeetCommandType::Sub);

        // Create a list of uploads.
        let uploads =
            Self::draw_transfers(connected_state.uploads.iter(), FileYeetCommandType::Pub);

        // Create a list of files being published.
        let pubs = widget::column(connected_state.publishes.iter().map(|pi| {
            widget::container(
                match &pi.state {
                    PublishState::Hashing(progress) => widget::row!(
                        widget::column!(
                            widget::row!(
                                widget::text("Hashing..."),
                                widget::progress_bar(0.0..=1., *progress.read().unwrap())
                                    .width(iced::Length::Fill),
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
                        widget::text(format!("Failed to publish: {e}"))
                            .style(iced::theme::Text::Color(ERROR_RED_COLOR)),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                    PublishState::Cancelled => widget::row!(
                        widget::text("Cancelled"),
                        widget::button(widget::text("Remove").size(12))
                            .on_press(Message::CancelPublish(pi.nonce))
                    ),
                }
                .align_items(iced::Alignment::Center)
                .spacing(12),
            )
            .style(iced::theme::Container::Box)
            .padding(6)
            .into()
        }))
        .spacing(6);

        widget::container(
            widget::column!(
                widget::row!(
                    widget::text("Server address:"),
                    widget::text(&self.options.server_address),
                    widget::button(widget::text("Copy").size(12)).on_press(Message::CopyServer),
                    widget::button(widget::text("Leave").size(12))
                        .on_press(Message::SafelyLeaveServer),
                    widget::horizontal_space(),
                    widget::text("Our External Address:"),
                    widget::text(&connected_state.external_address),
                )
                .align_items(iced::alignment::Alignment::Center)
                .spacing(6),
                widget::row!(publish_button, download_input).spacing(6),
                widget::row!(widget::column!(pubs, uploads).spacing(6), downloads).spacing(6),
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
                let o = self.options.port_forwarding_text.parse::<NonZeroU16>().ok();
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
        self.connection_state = ConnectionState::Stalling {
            start: Instant::now(),
            tick: Instant::now(),
        };

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

        // Try to connect to the server in a new task.
        iced::Command::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::prepare_server_connection(
                    server_address.as_deref(),
                    port,
                    None,
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
                    if let TransferProgress::Transfering(_, lock, total, progress) = &mut t.progress
                    {
                        let Ok(p) = lock.read() else {
                            t.progress = TransferProgress::Done(TransferResult::Failure(Arc::new(
                                anyhow::anyhow!("Lock poisoned"),
                            )));
                            continue;
                        };

                        #[allow(clippy::cast_precision_loss)]
                        {
                            *progress = *p as f32 / *total as f32;
                        }
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
                iced::Command::none()
            }
            Err(e) => {
                self.status_message = Some(format!("Error connecting: {e}"));
                self.connection_state = ConnectionState::Disconnected;
                iced::Command::none()
            }
        }
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
            server, publishes, ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

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
                            match crate::core::publish(&server, bb, hash).await {
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
            (Ok(peer), Some(publish)) => iced::Command::perform(
                crate::core::udp_holepunch(
                    FileYeetCommandType::Pub,
                    publish.hash,
                    endpoint.clone(),
                    peer,
                ),
                move |r| {
                    Message::PublishPeerConnectResulted(nonce, r.map(Into::<PeerConnection>::into))
                },
            ),
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
            publishes, uploads, ..
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
        let progress_lock = Arc::new(RwLock::new(0));
        let cancellation_token = CancellationToken::new();
        uploads.push(Transfer {
            nonce: upload_nonce,
            hash: publishing.hash,
            hash_hex: faster_hex::hex_string(&publishing.hash),
            peer_string: peer.connection.remote_address().to_string(),
            path: path.clone(),
            progress: TransferProgress::Transfering(
                peer.clone(),
                progress_lock.clone(),
                publishing.file_size,
                0.,
            ),
            cancellation_token: cancellation_token.clone(),
        });

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
            server, hash_input, ..
        }) = &self.connection_state
        else {
            return iced::Command::none();
        };

        // Ensure the hash is valid.
        let mut hash = HashBytes::default();
        if let Err(e) = faster_hex::hex_decode(hash_input.as_bytes(), &mut hash) {
            self.status_message = Some(format!("Invalid hash: {e}"));
            return iced::Command::none();
        }

        let server = server.clone();
        iced::Command::perform(
            async move {
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                crate::core::subscribe(&server, &mut bb, hash)
                    .await
                    .map(|peers| (peers, path, hash))
                    .map_err(Arc::new)
            },
            Message::SubscribePeersResult,
        )
    }

    /// Update after server has responded to a subscribe request.
    fn update_subscribe_peers_result(
        &mut self,
        result: Result<(Vec<SocketAddr>, PathBuf, HashBytes), Arc<anyhow::Error>>,
    ) -> iced::Command<Message> {
        match result {
            Ok((peers, path, hash)) => {
                // Helper to get the file size from the peer after a successful connection.
                async fn get_size_from_peer(
                    (c, mut b): (quinn::Connection, BiStream),
                ) -> Option<(PeerConnection, u64)> {
                    b.recv
                        .read_u64()
                        .await
                        .ok()
                        .map(|file_size| (PeerConnection::new(c, b), file_size))
                }

                if let ConnectionState::Connected(ConnectedState {
                    endpoint,
                    hash_input,
                    downloads: transfers,
                    ..
                }) = &mut self.connection_state
                {
                    // Let the user know why nothing else is happening.
                    if peers.is_empty() {
                        self.status_message = Some("No peers available".to_owned());
                        return iced::Command::none();
                    }

                    // Create a new transfer state and connection attempt for each peer.
                    let transfers_commands_iter = peers.into_iter().map(|peer| {
                        // Create a nonce to identify the transfer.
                        let nonce = rand::random();

                        // New transfer state for this request.
                        let transfer = Transfer {
                            nonce,
                            hash,
                            hash_hex: hash_input.clone(),
                            peer_string: peer.to_string(),
                            path: path.clone(),
                            progress: TransferProgress::Connecting,
                            cancellation_token: CancellationToken::new(),
                        };

                        // New connection attempt for this peer with result command identified by the nonce.
                        let command = {
                            let endpoint = endpoint.clone();
                            let future = async move {
                                tokio::time::timeout(
                                    PEER_CONNECT_TIMEOUT,
                                    futures_util::future::OptionFuture::from(
                                        crate::core::udp_holepunch(
                                            FileYeetCommandType::Sub,
                                            hash,
                                            endpoint,
                                            peer,
                                        )
                                        .await
                                        .map(get_size_from_peer),
                                    ),
                                )
                                .await
                                .ok()
                                .flatten()
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
                    transfers.append(&mut new_transfers);
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
        result: Option<(PeerConnection, u64)>,
    ) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState {
            downloads: transfers,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Find the transfer with the matching nonce.
        let Some(transfer) = transfers.iter_mut().find(|t| t.nonce == nonce) else {
            return iced::Command::none();
        };

        // Handle the result of the connection attempt.
        if let Some((connection, file_size)) = result {
            transfer.progress = TransferProgress::Consent(connection, file_size);
        } else {
            transfer.progress = TransferProgress::Done(TransferResult::Failure(Arc::new(
                anyhow::anyhow!("Connection attempt failed"),
            )));
        }
        iced::Command::none()
    }

    /// Tell the peer to send the file and begin recieving and writing the file.
    fn update_accept_download(&mut self, nonce: Nonce) -> iced::Command<Message> {
        let ConnectionState::Connected(ConnectedState {
            downloads: transfers,
            ..
        }) = &mut self.connection_state
        else {
            return iced::Command::none();
        };

        // Get the current transfer status.
        let Some(transfer) = transfers.iter_mut().find(|t| t.nonce == nonce) else {
            return iced::Command::none();
        };
        let hash = transfer.hash;
        let (peer_streams, file_size) =
            if let TransferProgress::Consent(p, s) = &mut transfer.progress {
                (p.clone(), *s)
            } else {
                return iced::Command::none();
            };

        // Begin the transfer.
        let byte_progress = Arc::new(RwLock::new(0));
        transfer.progress = TransferProgress::Transfering(
            peer_streams.clone(),
            byte_progress.clone(),
            file_size,
            0.,
        );
        let output_path = transfer.path.clone();
        let cancellation_token = transfer.cancellation_token.clone();

        iced::Command::perform(
            async move {
                let mut peer_streams_lock = peer_streams.streams.lock().await;
                tokio::select! {
                    // Let the transfer be cancelled. This is not an error if cancelled.
                    () = cancellation_token.cancelled() => TransferResult::Cancelled,

                    // Await the file to be downloaded.
                    result = Box::pin(crate::core::download_from_peer(
                        hash,
                        &mut peer_streams_lock,
                        file_size,
                        &output_path,
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
                if matches!(t.progress, TransferProgress::Consent(_, _)) {
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
            downloads, uploads, ..
        }) = &mut self.connection_state
        {
            let mut transfers = match transfer_type {
                FileYeetCommandType::Sub => downloads.iter_mut(),
                FileYeetCommandType::Pub => uploads.iter_mut(),
            };

            if let Some(t) = transfers.find(|t| t.nonce == nonce) {
                t.progress = TransferProgress::Done(result);
            }
        }
        iced::Command::none()
    }

    /// Try to safely close.
    fn safely_close(&mut self, close_type: CloseType) -> iced::Command<Message> {
        if let ConnectionState::Connected(ConnectedState {
            endpoint,
            publishes,
            ..
        }) = &mut self.connection_state
        {
            // Save the settings before closing the application.
            if let Err(e) = settings_path()
                .ok_or_else(|| {
                    anyhow::anyhow!("Could not determine a settings path for this environment.")
                })
                .and_then(|p| Ok(std::fs::File::create(p)?))
                .and_then(|f| Ok(serde_json::to_writer_pretty(f, &self.options)?))
            {
                eprintln!("{} Could not save settings: {e}", local_now_fmt());
            }

            // Cancel all publish tasks.
            for p in publishes.iter() {
                p.cancellation_token.cancel();
            }

            // TODO: Allow current downloads to be recontinued after a restart.
            endpoint.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());
        };

        if let Some(port_mapping) = self.port_mapping.take() {
            let start = Instant::now();
            let delta = Duration::from_millis(500);

            // Set the state to `Stalling` before waiting for the safe close to complete.
            self.connection_state = ConnectionState::Stalling { start, tick: start };
            self.safely_closing = true;
            iced::Command::perform(
                tokio::time::timeout(delta, async move {
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
                // Immediately exit if there is no port mapping to remove.
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
