use std::{
    ops::Div as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use file_yeet_shared::DEFAULT_PORT;
use iced::widget;

use crate::core::{self, MAX_PEER_COMMUNICATION_SIZE};

/// The state of the connection to a `file_yeet` server.
#[derive(Default, Debug)]
enum ConnectionState {
    #[default]
    Disconnected,
    Connecting {
        start: Instant,
        tick: Instant,
    },
    Connected {
        endpoint: quinn::Endpoint,
        server: quinn::Connection,
        modal: bool,
    },
}

/// The state of the application for interacting with the GUI.
#[derive(Default)]
pub struct AppState {
    connection_state: ConnectionState,
    server_address: String,
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
                let server_address = self.server_address.clone();
                let mut bb = bytes::BytesMut::with_capacity(MAX_PEER_COMMUNICATION_SIZE);

                // Set the state to `Connecting` before starting the connection attempt.
                self.connection_state = ConnectionState::Connecting {
                    start: Instant::now(),
                    tick: Instant::now(),
                };

                // TODO: Use regex to determine if a port number was provided.

                iced::Command::perform(
                    async move {
                        core::prepare_server_connection(
                            Some(&server_address),
                            DEFAULT_PORT,
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
                        modal: false,
                    };
                    iced::Command::none()
                }
                Err(e) => {
                    // TODO: Show an error message based on a real error value.
                    eprintln!("Error connecting: {e:?}");
                    self.connection_state = ConnectionState::Disconnected;
                    iced::Command::none()
                }
            },

            // Handle the publish button being clicked by picking a file to publish.
            Message::PublishClicked => {
                if let ConnectionState::Connected { modal, .. } = &mut self.connection_state {
                    *modal = true;
                }

                iced::Command::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file to publish")
                        .pick_file(),
                    |f| Message::PublishPathChosen(f.map(PathBuf::from)),
                )
            }

            // Begin the process of publishing a file to the server.
            Message::PublishPathChosen(_) => {
                if let ConnectionState::Connected { modal, .. } = &mut self.connection_state {
                    *modal = false;
                }

                iced::Command::none()
            }

            // Handle the subscribe button being clicked by choosing a save location.
            Message::SubscribeClicked => {
                if let ConnectionState::Connected { modal, .. } = &mut self.connection_state {
                    *modal = true;
                }

                iced::Command::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title("Choose a file path to save to")
                        .save_file(),
                    |f| Message::SubscribePathChosen(f.map(PathBuf::from)),
                )
            }

            // Begin the process of subscribing to a file from the server.
            Message::SubscribePathChosen(_) => {
                if let ConnectionState::Connected { modal, .. } = &mut self.connection_state {
                    *modal = false;
                }

                iced::Command::none()
            }
        }
    }

    /// Listen for events that should be translated into messages.
    fn subscription(&self) -> iced::Subscription<Message> {
        match self.connection_state {
            ConnectionState::Connecting { .. } => {
                iced::time::every(Duration::from_millis(10)).map(|_| Message::SpinTick)
            }
            _ => iced::Subscription::none(),
        }
    }

    /// Draw the application GUI.
    fn view(&self) -> iced::Element<Message> {
        match self.connection_state {
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
            ConnectionState::Connecting { start, tick } => {
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
            ConnectionState::Connected { modal, .. } => {
                let mut publish_button = widget::button("Publish");
                let mut download_button = widget::button("Download");

                // Disable the buttons while a modal is open.
                if !modal {
                    publish_button = publish_button.on_press(Message::PublishClicked);
                    download_button = download_button.on_press(Message::SubscribeClicked);
                }

                widget::container(widget::row!(publish_button, download_button).spacing(6))
                    .width(iced::Length::Fill)
                    .height(iced::Length::Fill)
                    .padding(12)
                    .center_x()
                    .center_y()
                    .into()
            }
        }
    }

    /// Prefer a dark theme.
    fn theme(&self) -> iced::Theme {
        iced::Theme::Dark
    }
}
