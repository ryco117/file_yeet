use std::{
    net::SocketAddr,
    num::NonZeroU16,
    ops::Div as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::{local_now_fmt, HashBytes, DEFAULT_PORT, GOODBYE_CODE, GOODBYE_MESSAGE};
use iced::{widget, window, Element};
use tokio::sync::RwLock;

use crate::core::{
    self, PortMappingConfig, MAX_PEER_COMMUNICATION_SIZE, SERVER_CONNECTION_TIMEOUT,
};

/// Lazyily initialized regex for parsing server addresses.
/// Produces match groups `host` and `port` for the server address and optional port.
static SERVER_ADDRESS_REGEX: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^(?P<host>[^:]+)(?::(?P<port>\d+))?$").unwrap()
    });

/// The maximum time to wait before forcing the application to exit.
const MAX_SHUTDOWN_WAIT: Duration = Duration::from_secs(3);

/// The labels for the port mapping radio buttons.
const PORT_MAPPING_OPTIONS: [&str; 3] = ["None", "Port forward", "NAT-PMP / PCP"];

/// The state of the port mapping options in the GUI.
#[derive(Default, Debug)]
enum PortMappingGuiOptions {
    #[default]
    None,
    PortForwarding(Option<NonZeroU16>),
    TryPcpNatPmp,
}

#[derive(Debug)]
enum TransferProgress {
    Connecting,
    Consent(u64),
    Transfering(Arc<RwLock<u64>>),
    Done(bool),
}

#[derive(Debug)]
struct Transfer {
    pub hash: String,
    pub path: PathBuf,
    pub progress: TransferProgress,
}

/// The state of the connection to a `file_yeet` server.
#[derive(Default, Debug)]
enum ConnectionState {
    /// No server connection is active.
    #[default]
    Disconnected,

    /// Connecting to the server or safely closing the application.
    Stalling { start: Instant, tick: Instant },

    /// A connection to the server is active.
    Connected {
        // Local QUIC endpoint for server and peer connections.
        endpoint: quinn::Endpoint,
        // Connection with the server.
        server: quinn::Connection,
        // The hash input field for creating new subscribe requests.
        hash_input: String,
        // A list of active file transfers.
        transfers: Vec<Transfer>,
    },
}

/// The state of the application for interacting with the GUI.
#[derive(Default)]
pub struct AppState {
    connection_state: ConnectionState,
    server_address: String,
    status_message: Option<String>,
    modal: bool,
    safely_closing: bool,
    port_mapping: Option<crab_nat::PortMapping>,

    // TODO: Separate into "state options" struct or similar.
    port_forwarding_text: String,
    port_mapping_options: PortMappingGuiOptions,
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

    /// A moment in time has passed, update the spin animation.
    SpinTick,

    /// The result of a server connection attempt.
    ConnectResulted(Result<core::PreparedConnection, Arc<anyhow::Error>>),

    /// The hash input field was changed.
    HashInputChanged(String),

    /// The publish button was clicked.
    PublishClicked,

    /// The path to a file to publish was chosen or cancelled.
    PublishPathChosen(Option<PathBuf>),

    /// The subscribe button was clicked or the hash field was submitted.
    SubscribeStarted,

    /// The path to save a file to was chosen or cancelled.
    SubscribePathChosen(Option<PathBuf>),

    /// A subscribe request was completed.
    SubscribePeersResult(Result<(Vec<SocketAddr>, PathBuf), Arc<anyhow::Error>>),

    /// An unhandled event occurred.
    UnhandledEvent(iced::Event),

    /// Exit the application immediately. Ensure we aren't waiting for async tasks forever.
    ForceExit,
}

/// The application state and logic.
impl iced::Application for AppState {
    type Message = Message;
    type Theme = iced::Theme;
    type Executor = iced::executor::Default;
    type Flags = ();

    /// Create a new application state.
    fn new(_flags: ()) -> (AppState, iced::Command<Message>) {
        (Self::default(), iced::Command::none())
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
                self.server_address = address;
                iced::Command::none()
            }

            // Handle the port mapping radio button being changed.
            Message::PortMappingRadioChanged(label) => {
                self.port_mapping_options = match label {
                    "None" => {
                        self.status_message = None;
                        PortMappingGuiOptions::None
                    }
                    "Port forward" => PortMappingGuiOptions::PortForwarding({
                        let o = self.port_forwarding_text.parse::<NonZeroU16>().ok();
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

            // Handle the port forward text field being changed.
            Message::PortForwardTextChanged(text) => {
                self.port_forwarding_text = text;
                if let PortMappingGuiOptions::PortForwarding(port) = &mut self.port_mapping_options
                {
                    if let Ok(p) = self.port_forwarding_text.parse::<NonZeroU16>() {
                        *port = Some(p);
                        self.status_message = None;
                    } else {
                        *port = None;
                        self.status_message = Some(INVALID_PORT_FORWARD.to_owned());
                    }
                }
                iced::Command::none()
            }

            // Handle the publish button being clicked by picking a file to publish.
            Message::ConnectClicked => self.update_connect_clicked(),

            // The spin animation tick doesn't need anything special besides updating the tick state.
            Message::SpinTick => {
                if let ConnectionState::Stalling { tick, .. } = &mut self.connection_state {
                    *tick = Instant::now();
                }
                iced::Command::none()
            }

            // Handle the result of a connection attempt.
            Message::ConnectResulted(r) => match r {
                Ok(prepared) => {
                    self.connection_state = ConnectionState::Connected {
                        endpoint: prepared.endpoint,
                        server: prepared.server_connection,
                        hash_input: String::new(),
                        transfers: Vec::new(),
                    };
                    self.port_mapping = prepared.port_mapping;
                    iced::Command::none()
                }
                Err(e) => {
                    self.status_message = Some(format!("Error connecting: {e:?}"));
                    self.connection_state = ConnectionState::Disconnected;
                    iced::Command::none()
                }
            },

            // Handle the hash input being changed.
            Message::HashInputChanged(hash) => {
                if let ConnectionState::Connected { hash_input, .. } = &mut self.connection_state {
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
            Message::PublishPathChosen(path) => {
                self.modal = false;

                // Ensure a path was chosen.
                let Some(_path) = path else {
                    return iced::Command::none();
                };

                // Ensure the client is connected to a server.
                let ConnectionState::Connected { .. } = &self.connection_state else {
                    return iced::Command::none();
                };

                iced::Command::none()
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
            Message::SubscribePeersResult(r) => {
                match r {
                    Ok((peers, path)) => {
                        if let ConnectionState::Connected {
                            hash_input,
                            transfers,
                            ..
                        } = &mut self.connection_state
                        {
                            transfers.append(
                                &mut peers
                                    .into_iter()
                                    .map(|_addr| Transfer {
                                        hash: hash_input.clone(),
                                        path: path.clone(),
                                        progress: TransferProgress::Connecting,
                                    })
                                    .collect(),
                            );
                        }
                    }
                    Err(e) => {
                        self.status_message = Some(format!("Error subscribing: {e:?}"));
                    }
                }
                iced::Command::none()
            }

            // Handle an event that iced did not handle itself.
            // This is used to allow for custom exit handling in this instance.
            Message::UnhandledEvent(event) => match event {
                iced::Event::Window(id, window::Event::CloseRequested) => {
                    if id == window::Id::MAIN {
                        if self.safely_closing {
                            // If we are already closing, force exit immediately.
                            window::close(window::Id::MAIN)
                        } else {
                            self.safely_close()
                        }
                    } else {
                        // Non-main windows (if ever implemented) can be closed immediately.
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
        let close_event = iced::event::listen().map(Message::UnhandledEvent);

        match self.connection_state {
            ConnectionState::Stalling { .. } => {
                let animation =
                    iced::time::every(Duration::from_millis(33)).map(|_| Message::SpinTick);
                iced::Subscription::batch([close_event, animation])
            }
            _ => close_event,
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
            ConnectionState::Connected {
                hash_input,
                transfers,
                ..
            } => self.view_connected_page(hash_input, transfers),
        };

        // Always display the status bar at the bottom.
        let status_bar = widget::container(if let Some(status_message) = &self.status_message {
            Element::from(
                widget::text(status_message)
                    .style(iced::theme::Text::Color(iced::Color::from_rgb8(
                        0xF0, 0x60, 0x80,
                    )))
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
        let mut server_address =
            widget::text_input("Server address. E.g., localhost:7828", &self.server_address);

        let mut connect_button = widget::button("Connect");
        let mut port_forward_text = widget::text_input(
            "External port forward. E.g., 8888",
            &self.port_forwarding_text,
        );

        if !self.modal {
            server_address = server_address
                .on_input(Message::ServerAddressChanged)
                .on_submit(Message::ConnectClicked);
            connect_button = connect_button.on_press(Message::ConnectClicked);

            if let PortMappingGuiOptions::PortForwarding(_) = &self.port_mapping_options {
                port_forward_text = port_forward_text.on_input(Message::PortForwardTextChanged);
            }
        }

        let selected = match self.port_mapping_options {
            PortMappingGuiOptions::None => PORT_MAPPING_OPTIONS[0],
            PortMappingGuiOptions::PortForwarding(_) => PORT_MAPPING_OPTIONS[1],
            PortMappingGuiOptions::TryPcpNatPmp => PORT_MAPPING_OPTIONS[2],
        };

        // Create a bottom section for choosing port forwaring/mapping options.
        let choose_port_mapping = widget::column!(
            widget::radio(
                PORT_MAPPING_OPTIONS[0],
                PORT_MAPPING_OPTIONS[0],
                Some(selected),
                Message::PortMappingRadioChanged,
            ),
            widget::row!(
                widget::radio(
                    PORT_MAPPING_OPTIONS[1],
                    PORT_MAPPING_OPTIONS[1],
                    Some(selected),
                    Message::PortMappingRadioChanged,
                ),
                port_forward_text,
            )
            .spacing(32),
            widget::radio(
                PORT_MAPPING_OPTIONS[2],
                PORT_MAPPING_OPTIONS[2],
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

    /// Draw the main application controls when connected to a server.
    fn view_connected_page(
        &self,
        hash_input: &str,
        transfers: &[Transfer],
    ) -> iced::Element<Message> {
        let mut publish_button = widget::button("Publish");
        let mut download_button = widget::button("Download");
        let mut hash_text_input = widget::text_input("Hash", hash_input);

        // Disable the inputs while a modal is open.
        if !self.modal {
            publish_button = publish_button.on_press(Message::PublishClicked);
            hash_text_input = hash_text_input.on_input(Message::HashInputChanged);

            // Enable the download button if the hash is valid.
            if hash_input.len() == file_yeet_shared::HASH_BYTE_COUNT << 1
                && faster_hex::hex_check(hash_input.as_bytes())
            {
                download_button = download_button.on_press(Message::SubscribeStarted);
                hash_text_input = hash_text_input.on_submit(Message::SubscribeStarted);
            }
        }

        // Hash input and download button.
        let download_input = widget::row!(
            hash_text_input.width(iced::Length::FillPortion(2)),
            download_button,
        )
        .spacing(6);

        // Create a list of active downloads.
        let downloads = widget::column(transfers.iter().map(|t| {
            let progress = match &t.progress {
                TransferProgress::Connecting => "Connecting...",
                TransferProgress::Consent(_) => "Waiting for consent...",
                TransferProgress::Transfering(_) => "Transfering...",
                TransferProgress::Done(_) => "Done",
            };

            widget::container(widget::column!(
                widget::row!(widget::text(&t.hash), widget::text(progress),).spacing(6),
                widget::text(&t.path.to_string_lossy()),
            ))
            .padding(6)
            .into()
        }));

        widget::container(
            widget::row!(
                publish_button,
                widget::horizontal_space(),
                widget::column!(download_input, downloads).spacing(6),
            )
            .spacing(6),
        )
        .width(iced::Length::Fill)
        .height(iced::Length::Fill)
        .padding(12)
        .center_x()
        .center_y()
        .into()
    }

    /// Update the state after the connect button was clicked.
    fn update_connect_clicked(&mut self) -> iced::Command<Message> {
        // Clear the status message before starting the connection attempt.
        self.status_message = None;

        // Determine if a valid server address was entered.
        let regex_match = if self.server_address.is_empty() {
            // If empty, allow for defaults to be used.
            Some((None, DEFAULT_PORT))
        } else {
            // Otherwise, parse the server address and optional port.
            SERVER_ADDRESS_REGEX
                .captures(&self.server_address)
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
        let port_mapping = match self.port_mapping_options {
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
                core::prepare_server_connection(
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

    /// Update the state after the publish button was clicked. Begins a subscribe request.
    fn update_subscribe_path_chosen(&mut self, path: Option<PathBuf>) -> iced::Command<Message> {
        self.modal = false;

        // Ensure a path was chosen.
        let Some(path) = path else {
            return iced::Command::none();
        };

        // Ensure the client is connected to a server.
        let ConnectionState::Connected {
            server, hash_input, ..
        } = &self.connection_state
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
                core::subscribe(&server, &mut bb, hash).await
            },
            |r| Message::SubscribePeersResult(r.map(|peers| (peers, path)).map_err(Arc::new)),
        )
    }

    /// Try to safely close the application.
    fn safely_close(&mut self) -> iced::Command<Message> {
        // TODO: Ensure current uploads/downloads are gracefully closed.(/paused?)
        if let ConnectionState::Connected { endpoint, .. } = &mut self.connection_state {
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
                |_| Message::ForceExit,
            )
        } else {
            // Immediately exit if there is no port mapping to remove.
            window::close(window::Id::MAIN)
        }
    }
}

const INVALID_PORT_FORWARD: &str = "Invalid port forward. Defaults to no port mappings.";
