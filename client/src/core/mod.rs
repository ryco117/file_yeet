use std::{
    collections::{hash_map, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU16,
    sync::Arc,
    time::Duration,
};

use file_yeet_shared::QUIC_TIMEOUT_MILLIS;
use futures_util::TryFutureExt;
use tokio::sync::RwLock;

pub mod file;
pub mod intervals;
pub mod peer;
pub mod server;

/// Type alias for SHA-256 hash state used by the client.
pub type Hasher = sha2::Sha256;

/// The name of the application.
pub static APP_TITLE: &str = env!("CARGO_PKG_NAME");

/// Lazily initialized regex for parsing hash hex strings.
/// Produces capture groups `bytes`, `hash`, and `ext` for the byte count, hash, and file extension, respectively.
pub static HASH_EXT_REGEX: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^\s*(?:(?P<bytes>[0-9]+):)?(?P<hash>[0-9a-fA-F]{64})(?::(?P<ext>\w+))?\s*$")
        .expect("Failed to compile the hash hex regex")
});

/// Lazily initialized shared QUIC transport configuration. Sets sane timeouts and keep-alive policies.
static DEFAULT_TRANSPORT_CONFIG: std::sync::LazyLock<Arc<quinn::TransportConfig>> =
    std::sync::LazyLock::new(|| {
        // Set custom keep alive policies.
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            QUIC_TIMEOUT_MILLIS,
        ))));

        // Send keep alive packets at a fraction of the idle timeout.
        transport_config
            .keep_alive_interval(Some(Duration::from_millis(QUIC_TIMEOUT_MILLIS as u64 / 6)));

        Arc::new(transport_config)
    });

/// Helper for building the agreed upon QUIC transport configuration for connections.
#[inline]
fn default_transport_config() -> Arc<quinn::TransportConfig> {
    DEFAULT_TRANSPORT_CONFIG.clone()
}

/// Expected error indicating that a read operation failed because we closed the connection elsewhere.
pub const LOCALLY_CLOSED_READ: quinn::ReadError =
    quinn::ReadError::ConnectionLost(quinn::ConnectionError::LocallyClosed);

/// Expected error indicating that a write operation failed because we closed the connection elsewhere.
pub const LOCALLY_CLOSED_WRITE: quinn::WriteError =
    quinn::WriteError::ConnectionLost(quinn::ConnectionError::LocallyClosed);

/// Specifies the IP version to use when creating a local endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}
impl From<IpAddr> for IpVersion {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        }
    }
}

/// Errors that may occur when preparing a server connection and endpoint to communicate with.
#[derive(Debug, thiserror::Error)]
pub enum CreateLocalEndpointError {
    #[error("Self-signed certificate generation failed: {0}")]
    SelfSignedCertificate(#[from] rcgen::Error),

    #[error("Failed to create server config: {0}")]
    ServerConfig(#[from] rustls::Error),

    #[error("Failed to create local endpoint: {0}")]
    EndpointCreation(#[from] std::io::Error),
}

/// Creates a local QUIC endpoint bound to the specified internal port and unspecified IP address for the given IP version.
#[allow(clippy::needless_pass_by_value)]
#[tracing::instrument()]
pub fn create_local_endpoint(
    internal_port: Option<NonZeroU16>,
    ip_version: IpVersion,
) -> Result<quinn::Endpoint, CreateLocalEndpointError> {
    tracing::debug!("Creating local endpoint");

    // Create a self-signed certificate for the peer communications.
    let (server_cert, server_key) = file_yeet_shared::generate_self_signed_cert()?;
    let mut server_config = quinn::ServerConfig::with_single_cert(vec![server_cert], server_key)?;

    // Set custom keep alive policies.
    server_config.transport_config(file_yeet_shared::server_transport_config());

    // Determine the local socket address to bind to. Use an unspecified address since we don't have any preference.
    let bind_port = internal_port.map_or(0, NonZeroU16::get);
    let bind_address = match ip_version {
        IpVersion::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port)),
        IpVersion::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, bind_port, 0, 0)),
    };
    tracing::debug!("Binding local endpoint to {bind_address}");
    let mut endpoint = quinn::Endpoint::server(server_config, bind_address)?;

    // Use an insecure client configuration when connecting to peers.
    endpoint.set_default_client_config(peer::configure_peer_verification());
    tracing::debug!("Local endpoint created successfully");

    Ok(endpoint)
}

/// Specify whether any existing port forwarding can be used or if a new mapping should be attempted.
#[derive(Debug)]
pub enum PortMappingConfig {
    /// No port forwarding is used, relies entirely on UDP hole punching.
    None,

    /// Use a port forward configured outside of this application.
    PortForwarding(NonZeroU16),

    /// Attempt to use PCP or NAT-PMP to create a port mapping.
    PcpNatPmp(Option<crab_nat::PortMapping>),
}

/// The command relationship between the two peers. Useful for asserting synchronization roles based on the command type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileYeetCommandType {
    Pub,
    Sub,
}

/// Errors that may occur when attempting to get the default interface's IP address.
#[derive(Debug, thiserror::Error)]
pub enum ProbeLocalAddressError {
    /// Failed to get the default interface.
    #[error("Failed to get a default interface: {0}")]
    DefaultInterface(String),

    /// Failed to get a default IPv4 address.
    #[error("Failed to get a default IPv4 address")]
    NoDefaultIpv4,

    /// Failed to get a default IPv6 address.
    #[error("Failed to get a default IPv6 address")]
    NoDefaultIpv6,
}

/// Helper to determine the default interface's IP address.
#[tracing::instrument()]
fn probe_local_address(ip_version: IpVersion) -> Result<IpAddr, ProbeLocalAddressError> {
    let interface =
        netdev::get_default_interface().map_err(ProbeLocalAddressError::DefaultInterface)?;
    let ip = match ip_version {
        IpVersion::V4 => IpAddr::V4(
            interface
                .ipv4
                .first()
                .ok_or(ProbeLocalAddressError::NoDefaultIpv4)?
                .addr(),
        ),
        IpVersion::V6 => IpAddr::V6(
            interface
                .ipv6
                .first()
                .ok_or(ProbeLocalAddressError::NoDefaultIpv6)?
                .addr(),
        ),
    };

    tracing::debug!("Probed local interface address: {ip}");
    Ok(ip)
}

/// Attempt to create a port mapping using NAT-PMP or PCP.
#[tracing::instrument]
async fn try_port_mapping(
    gateway: IpAddr,
    local_address: SocketAddr,
) -> Result<crab_nat::PortMapping, crab_nat::MappingFailure> {
    crab_nat::PortMapping::new(
        gateway.into(),
        local_address.ip(),
        crab_nat::InternetProtocol::Udp,
        std::num::NonZeroU16::new(local_address.port()).expect("Socket address has no port"),
        crab_nat::PortMappingOptions {
            timeout_config: Some(crab_nat::natpmp::TIMEOUT_CONFIG_DEFAULT),
            ..Default::default()
        },
    )
    .await
}

/// Helper to convert an `Instant` into a `DateTime` string.
pub fn instant_to_datetime_string(i: std::time::Instant) -> String {
    chrono::TimeDelta::from_std(i.duration_since(std::time::Instant::now()))
        .ok()
        .and_then(|d| chrono::Local::now().checked_add_signed(d))
        .map_or_else(
            || String::from("UNKNOWN"),
            |t| t.format("%Y-%m-%d %H:%M:%S").to_string(),
        )
}

/// Helper to configure a waiting period based on a port mapping lifetime.
/// The interval is set to one-third of the lifetime, with a minimum of 120 seconds.
pub async fn new_renewal_interval(lifetime_seconds: u64) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(
        Duration::from_secs(lifetime_seconds)
            .div_f64(3.)
            .max(Duration::from_secs(120)),
    );
    interval.tick().await; // Skip the first tick.
    interval
}

/// Try to renew the port mapping.
/// On success, returns whether any mapping parameters changed.
#[tracing::instrument(skip_all)]
pub async fn renew_port_mapping(
    port_mapping: &mut crab_nat::PortMapping,
) -> Result<bool, crab_nat::MappingFailure> {
    tracing::debug!("Attempting port mapping renewal...");
    let last_lifetime = port_mapping.lifetime();
    let last_port = port_mapping.external_port();

    port_mapping.renew().await?;
    let mut mapping_changed = false;

    let lifetime = port_mapping.lifetime();
    if lifetime != last_lifetime {
        tracing::debug!(
            "Port mapping renewal changed lifetime from {last_lifetime} to {lifetime} seconds"
        );
        mapping_changed = true;
    }

    let port = port_mapping.external_port();
    if port != last_port {
        tracing::debug!("Port mapping renewal changed port from {last_port} to {port}");
        mapping_changed = true;
    }

    let expiration_time = instant_to_datetime_string(port_mapping.expiration());
    tracing::debug!("Port mapping renewal succeeded. Expiration at {expiration_time}");
    Ok(mapping_changed)
}

/// Helper to get `quinn::ReadError` info from a `std::io::Error` if available, otherwise falls back to the `std::io::ErrorKind`.
/// The given arguments are used to get this info into a chosen error type.
fn read_error_from_io<E, F, G>(e: std::io::Error, with_read_err: F, with_kind: G) -> E
where
    F: FnOnce(quinn::ReadError) -> E,
    G: FnOnce(std::io::ErrorKind) -> E,
{
    let kind = e.kind();
    e.downcast::<quinn::ReadError>()
        .map_or_else(|_| with_kind(kind), with_read_err)
}

/// Turn a byte count into a human readable string.
#[allow(clippy::cast_precision_loss)]
pub fn humanize_bytes(bytes: u64) -> String {
    // TODO: Replace with something that can write to a buffer instead of allocating a new string.
    human_bytes::human_bytes(bytes as f64)
}

/// Type for determining whether a peer connection is being requested or has already been established.
pub enum IncomingPeerState {
    Awaiting(Vec<tokio::sync::oneshot::Sender<quinn::Connection>>),
    Connected(quinn::Connection),
}

/// A manager for incoming and connected peers.
//  TODO: Use a task master to spawn tasks for each connected peer.
#[derive(Clone, Default)]
pub struct ConnectionsManager {
    map: Arc<RwLock<HashMap<SocketAddr, IncomingPeerState>>>,
}

impl ConnectionsManager {
    /// Get a smart pointer to the `ConnectionsManager` singleton that maps incoming and connected peers.
    pub fn instance() -> Self {
        static MANAGER: std::sync::LazyLock<ConnectionsManager> =
            std::sync::LazyLock::<_>::new(ConnectionsManager::default);
        MANAGER.clone()
    }

    /// Await the connection of a peer from a specified socket address.
    #[tracing::instrument(skip(self, peer_address))]
    pub async fn await_peer(
        &self,
        peer_address: SocketAddr,
        timeout: Duration,
    ) -> Option<quinn::Connection> {
        let rx = {
            let mut map = self.map.write().await;
            match map.entry(peer_address) {
                // This peer has already been mapped, determine the state.
                hash_map::Entry::Occupied(mut e) => {
                    let rx = match e.get_mut() {
                        // If the peer is already connected, return the connection.
                        IncomingPeerState::Connected(c) => {
                            // Check if the connection is still alive.
                            if let Some(r) = c.close_reason() {
                                if cfg!(debug_assertions) {
                                    tracing::warn!(
                                        "Peer connection {peer_address} is already closed: {r}"
                                    );
                                } else {
                                    tracing::warn!("Peer connection is already closed: {r}");
                                }
                                None
                            } else {
                                if cfg!(debug_assertions) {
                                    tracing::debug!(
                                        "Awaited peer connection {peer_address} is already established"
                                    );
                                } else {
                                    tracing::debug!(
                                        "Awaited peer connection is already established"
                                    );
                                }
                                return Some(c.clone());
                            }
                        }

                        // Otherwise, append another receiver to the list.
                        IncomingPeerState::Awaiting(v) => {
                            if cfg!(debug_assertions) {
                                tracing::debug!(
                                    "Joining wait at index {} for peer connection {peer_address}",
                                    v.len()
                                );
                            } else {
                                tracing::debug!(
                                    "Joining wait at index {} for peer connection",
                                    v.len()
                                );
                            }

                            let (tx, rx) = tokio::sync::oneshot::channel();
                            v.push(tx);

                            // Return the receive channel for awaiting.
                            Some(rx)
                        }
                    };

                    if let Some(rx) = rx {
                        rx
                    } else {
                        if cfg!(debug_assertions) {
                            tracing::debug!("Creating wait for peer connection {peer_address}");
                        } else {
                            tracing::debug!("Creating wait for peer connection");
                        }
                        let (tx, rx) = tokio::sync::oneshot::channel();
                        e.insert(IncomingPeerState::Awaiting(vec![tx]));
                        rx
                    }
                }

                // No mapping exists for this peer address, create one.
                hash_map::Entry::Vacant(e) => {
                    if cfg!(debug_assertions) {
                        tracing::debug!("Creating wait for peer connection {peer_address}");
                    } else {
                        tracing::debug!("Creating wait for peer connection");
                    }

                    let (tx, rx) = tokio::sync::oneshot::channel();
                    e.insert(IncomingPeerState::Awaiting(vec![tx]));

                    // Return the receive channel for awaiting.
                    rx
                }
            }
        };

        // Wait for the peer to connect or timeout.
        let incoming_connection = tokio::time::timeout(timeout, rx.into_future())
            .await
            .ok()
            .and_then(Result::ok);

        // Log the time when the incoming wait completes.
        tracing::debug!("Peer connection awaited");

        incoming_connection
    }

    /// Accept a peer connection and hand-off to any threads awaiting the connection.
    /// If a connection is mapped for the peer, it is replaced with the new connection.
    #[tracing::instrument(skip_all)]
    async fn accept_peer(&self, connection: quinn::Connection) {
        let mut map = self.map.write().await;
        let peer_address = connection.remote_address();
        match map.entry(peer_address) {
            // Update the entry and handle any waiting threads.
            hash_map::Entry::Occupied(mut e) => {
                let old = e.insert(IncomingPeerState::Connected(connection.clone()));

                // Let all waiting threads know that the peer has connected.
                if let IncomingPeerState::Awaiting(txs) = old {
                    for tx in txs {
                        // Fails if the receiver is no longer waiting for this message.
                        if tx.send(connection.clone()).is_err() {
                            tracing::warn!(
                                "Waiting thread closed before peer connection was accepted"
                            );
                        }
                    }
                }
            }

            // Create a new entry for the peer connection.
            hash_map::Entry::Vacant(e) => {
                e.insert(IncomingPeerState::Connected(connection));
            }
        }

        if cfg!(debug_assertions) {
            tracing::debug!("Peer connection accepted by manager: {peer_address}");
        } else {
            tracing::debug!("Peer connection accepted by manager");
        }
    }

    /// Remove a specific peer connection from the manager, with asynchronous lock behavior.
    #[tracing::instrument(skip(self, peer_address))]
    pub async fn remove_peer(&mut self, peer_address: SocketAddr, connection_id: usize) {
        // Remove entry for peer if the stable IDs match.
        match self.map.write().await.entry(peer_address) {
            hash_map::Entry::Occupied(e) => {
                if let IncomingPeerState::Connected(c) = e.get() {
                    if c.stable_id() == connection_id {
                        e.remove();
                        tracing::info!("Connection manager removed peer");
                    } else {
                        tracing::debug!(
                            "Connection manager found peer, but stable IDs did not match"
                        );
                    }
                }
            }

            hash_map::Entry::Vacant(_) => {
                tracing::warn!("Connection manager asked to remove a non-existent peer");
            }
        }
    }

    /// Create a new task to manage incoming peer connections in the background.
    #[tracing::instrument(skip_all)]
    pub async fn manage_incoming_loop(endpoint: quinn::Endpoint) {
        let manager = Self::instance();

        // Use a timer to avoid spamming logging in case of bad endpoint state.
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.tick().await; // Skip the first tick.

        while let Some(connecting) = endpoint.accept().await {
            let connecting = match connecting.accept() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to accept an incoming peer connection: {e}");

                    // Skip incomplete connections.
                    interval.tick().await;
                    continue;
                }
            };
            let connection = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("Failed to complete a peer connection: {e}");

                    // Skip incomplete connections.
                    interval.tick().await;
                    continue;
                }
            };

            // Notify any thread waiting for this connection if available, and store it.
            manager.accept_peer(connection).await;
        }

        tracing::debug!("Incoming peer connection loop closed");
    }

    /// Iterate over all peers and collect the result.
    pub fn filter_map<F, T>(&self, map: F) -> Vec<T>
    where
        F: Fn((&SocketAddr, &IncomingPeerState)) -> Option<T>,
    {
        self.map.blocking_read().iter().filter_map(map).collect()
    }

    /// Get the connection state of a peer.
    /// # Panics
    /// Cannot be used in async contexts. Will panic if used in an async runtime.
    #[tracing::instrument(skip_all)]
    pub fn get_connection_sync(&self, peer_address: SocketAddr) -> Option<quinn::Connection> {
        if let hash_map::Entry::Occupied(e) = self.map.blocking_write().entry(peer_address) {
            if let IncomingPeerState::Connected(c) = e.get() {
                // Check if the connection is still alive.
                if let Some(r) = c.close_reason() {
                    if cfg!(debug_assertions) {
                        tracing::warn!("Peer connection {peer_address} is already closed: {r}");
                    } else {
                        tracing::warn!("Peer connection is already closed: {r}");
                    }
                    e.remove();
                } else {
                    if cfg!(debug_assertions) {
                        tracing::debug!(
                            "Synchronous get for peer connection {peer_address} is already established"
                        );
                    } else {
                        tracing::debug!(
                            "Synchronous get for peer connection is already established"
                        );
                    }
                    return Some(c.clone());
                }
            }
        }

        tracing::debug!("Synchronous get found no active connection");
        None
    }

    /// Get the connection state of a peer.
    #[tracing::instrument(skip_all)]
    pub async fn get_connection_async(
        &self,
        peer_address: SocketAddr,
    ) -> Option<quinn::Connection> {
        if let hash_map::Entry::Occupied(e) = self.map.write().await.entry(peer_address) {
            if let IncomingPeerState::Connected(c) = e.get() {
                // Check if the connection is still alive.
                if let Some(r) = c.close_reason() {
                    if cfg!(debug_assertions) {
                        tracing::warn!("Peer connection {peer_address} is already closed: {r}");
                    } else {
                        tracing::warn!("Peer connection is already closed: {r}");
                    }
                    e.remove();
                } else {
                    if cfg!(debug_assertions) {
                        tracing::debug!(
                            "Asynchronous get for peer connection {peer_address} is already established"
                        );
                    } else {
                        tracing::debug!(
                            "Asynchronous get for peer connection is already established"
                        );
                    }
                    return Some(c.clone());
                }
            }
        }

        tracing::debug!("Asynchronous get found no active connection");
        None
    }
}
