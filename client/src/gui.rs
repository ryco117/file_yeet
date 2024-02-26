use std::{
    num::NonZeroU16,
    ops::Div as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::{HashBytes, DEFAULT_PORT};
use iced::{widget, Element};

use crate::core::{self, MAX_PEER_COMMUNICATION_SIZE};

/// Lazyily initialized regex for parsing server addresses.
static SERVER_ADDRESS_REGEX: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"^(?P<host>[^:]+)(?::(?P<port>\d+))?$").unwrap()
    });

/// The state of the connection to a `file_yeet` server.
#[derive(Default, Debug)]
enum ConnectionState {
    /// No server connection is active.
    #[default]
    Disconnected,

    /// Connecting to the server is in progress.
    Connecting { start: Instant, tick: Instant },

    /// A connection to the server is active.
    Connected {
        endpoint: quinn::Endpoint,
        server: quinn::Connection,
        hash_input: String,
    },
}

/// The state of the application for interacting with the GUI.
#[derive(Default)]
pub struct AppState {
    connection_state: ConnectionState,
    server_address: String,
    status_message: Option<String>,
    modal: bool,
}

/// The messages that can be sent to the update loop of the application.
#[derive(Clone, Debug)]
pub enum Message {
    /// The server text field was changed.
    ServerAddressChanged(String),

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

    /// The subscribe button was clicked.
    SubscribeClicked,

    /// The path to save a file to was chosen or cancelled.
    SubscribePathChosen(Option<PathBuf>),
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

            // Handle the publish button being clicked by picking a file to publish.
            Message::ConnectClicked => {
                // Clear the status message before starting the connection attempt.
                self.status_message = None;

                // Set the state to `Connecting` before starting the connection attempt.
                self.connection_state = ConnectionState::Connecting {
                    start: Instant::now(),
                    tick: Instant::now(),
                };

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
                    self.connection_state = ConnectionState::Disconnected;
                    return iced::Command::none();
                };

                iced::Command::perform(
                    async move {
                        let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                        core::prepare_server_connection(
                            server_address.as_deref(),
                            port,
                            None,
                            core::PortMappingConfig::None,
                            &mut bb,
                        )
                        .await
                        .map_err(Arc::new)
                    },
                    Message::ConnectResulted,
                )
            }

            // The spin animation tick doesn't need anything special besides updating the tick state.
            Message::SpinTick => {
                if let ConnectionState::Connecting { tick, .. } = &mut self.connection_state {
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
                    };
                    iced::Command::none()
                }
                Err(e) => {
                    self.status_message = Some({
                        let e = format!("Error connecting: {e:?}");
                        eprintln!("{e}");
                        e
                    });
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
            Message::PublishPathChosen(_) => {
                self.modal = false;
                iced::Command::none()
            }

            // Handle the subscribe button being clicked by choosing a save location.
            Message::SubscribeClicked => {
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
            Message::SubscribePathChosen(p) => {
                self.modal = false;

                // Ensure a path was chosen.
                let Some(path) = p else {
                    return iced::Command::none();
                };

                // Ensure the client is connected to a server.
                let ConnectionState::Connected { hash_input, .. } = &self.connection_state else {
                    return iced::Command::none();
                };

                // Ensure the hash is valid.
                let mut hash = HashBytes::default();
                if let Err(e) = faster_hex::hex_decode(hash_input.as_bytes(), &mut hash) {
                    self.status_message = Some(format!("Invalid hash: {e}"));
                    return iced::Command::none();
                }

                iced::Command::none()
                // iced::Command::perform(
                //     async move {
                //         let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);
                //         core::(hash, ).await
                //     },
                //     Message::ConnectClicked,
                // )
            }
        }
    }

    /// Listen for events that should be translated into messages.
    fn subscription(&self) -> iced::Subscription<Message> {
        match self.connection_state {
            ConnectionState::Connecting { .. } => {
                iced::time::every(Duration::from_millis(33)).map(|_| Message::SpinTick)
            }
            _ => iced::Subscription::none(),
        }
    }

    /// Draw the application GUI.
    fn view(&self) -> iced::Element<Message> {
        // Create a different top-level page based on the connection state.
        let page: Element<Message> = match &self.connection_state {
            // Display a prompt for the server address when disconnected.
            ConnectionState::Disconnected => {
                let server_address = widget::text_input(
                    "Server address. E.g., localhost:7828",
                    &self.server_address,
                )
                .on_input(Message::ServerAddressChanged)
                .on_submit(Message::ConnectClicked);

                let connect_button = widget::button("Connect").on_press(Message::ConnectClicked);

                widget::container(
                    widget::column!(server_address, connect_button)
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

            // Display a spinner while connecting.
            &ConnectionState::Connecting { start, tick } => {
                let spinner = widget::container::Container::new(widget::progress_bar(
                    0.0..=1.,
                    (tick - start)
                        .as_secs_f32()
                        .div(core::SERVER_CONNECTION_TIMEOUT.as_secs_f32())
                        .fract(),
                ))
                .width(iced::Length::Fill)
                .height(iced::Length::Fill)
                .padding(24)
                .center_x()
                .center_y();

                spinner.into()
            }

            // Display the main application controls when connected.
            ConnectionState::Connected { hash_input, .. } => {
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
                        download_button = download_button.on_press(Message::SubscribeClicked);
                    }
                }

                widget::container(
                    widget::row!(
                        publish_button,
                        widget::horizontal_space(),
                        hash_text_input,
                        download_button
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
