use std::{net::SocketAddr, sync::Arc};

use crab_nat::PortMapping;
use file_yeet_shared::{BiStream, HashBytes, ReadIpPortError, GOODBYE_CODE, GOODBYE_MESSAGE};
use iced::Subscription;
use tokio::io::AsyncWriteExt as _;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::{
    core::{ConnectionsManager, ReadSubscribingPeerError},
    gui::{
        publish::{Publish, PublishItem, PublishRequestResult, PublishState},
        Message, Nonce, PeerRequestStream,
    },
};

/// Helper to listen for runtime events that Iced did not handle internally. Used for safe exit handling.
#[inline]
fn unhandled_events() -> Subscription<Message> {
    iced::event::listen_with(|event, status, window| match status {
        iced::event::Status::Ignored => Some(Message::UnhandledEvent(window, event)),
        iced::event::Status::Captured => None,
    })
}

/// Helper to listen for timing intervals to update animations.
#[inline]
fn animation() -> Subscription<Message> {
    iced::time::every(std::time::Duration::from_millis(40)).map(|_| Message::AnimationTick)
}

/// Listen for close events and animation ticks when connecting/stalling.
#[inline]
pub fn stalling() -> Subscription<Message> {
    Subscription::batch([unhandled_events(), animation()])
}

/// Data for `incoming_connections_loop`.
struct IncomingConnectionsData {
    pub endpoint: quinn::Endpoint,
}
impl std::hash::Hash for IncomingConnectionsData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.endpoint.local_addr().ok().hash(state);
    }
}

/// Helper to listen for incoming connections to our QUIC endpoint.
fn incoming_connections_loop(
    data: &IncomingConnectionsData,
) -> impl futures_util::stream::Stream<Item = Message> {
    let endpoint = data.endpoint.clone();
    iced::stream::channel(4, move |_output| {
        ConnectionsManager::manage_incoming_loop(endpoint)
    })
}

/// Data for `port_mapping_loop`.
struct PortMappingData {
    pub mapping: PortMapping,
}
impl std::hash::Hash for PortMappingData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.mapping.gateway().hash(state);
    }
}

/// Helper to manage port mapping renewals over PCP/NAT-PMP.
fn port_mapping_loop(
    port_mapping: &PortMappingData,
) -> impl futures_util::stream::Stream<Item = Message> {
    let mut mapping = port_mapping.mapping.clone();
    iced::stream::channel(
        2,
        move |mut output: futures_channel::mpsc::Sender<Message>| {
            async move {
                let mut last_lifetime = mapping.lifetime() as u64;
                let mut interval = crate::core::new_renewal_interval(last_lifetime).await;
                loop {
                    // Ensure a reasonable wait time before each renewal attempt.
                    interval.tick().await;

                    match crate::core::renew_port_mapping(&mut mapping).await {
                        Ok(changed) if changed => {
                            if let Err(e) =
                                output.try_send(Message::PortMappingUpdated(Some(mapping.clone())))
                            {
                                let e = e.into_send_error();
                                tracing::error!("Failed to send port mapping update: {e}");
                            }

                            // Update interval if the lifetime has changed.
                            let lifetime = mapping.lifetime() as u64;
                            if lifetime != last_lifetime {
                                last_lifetime = lifetime;
                                interval = crate::core::new_renewal_interval(lifetime).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to renew port mapping: {e}");
                        }
                        _ => {}
                    }
                }
            }
            .instrument(tracing::info_span!("Port mapping renewal loop"))
        },
    )
}

/// For the given publish, await peers that desire to receive the file.
#[tracing::instrument(skip(publish, cancellation_token, output, our_external_address))]
async fn peers_requesting_publish_inner_loop(
    publish: Publish,
    nonce: Nonce,
    cancellation_token: &CancellationToken,
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
                if let Err(e) = result {
                    match e {
                        // Our address was sent as a peer, expected while testing.
                        ReadSubscribingPeerError::SelfAddress => {
                            tracing::debug!("Expected failure to read peer introduction: {e}");
                            continue;
                        }

                        // Unexpected error, log and continue.
                        ReadSubscribingPeerError::ReadSocket(e) => {
                            if matches!(e, ReadIpPortError::ReadIp(
                                quinn::ReadExactError::ReadError(crate::core::LOCALLY_CLOSED_READ)
                            )) {
                                // Locally closed connection, expected.
                                tracing::debug!("Expected failure to read peer introduction: Locally closed connection");
                                return;
                            }
                            tracing::warn!("Failed to read peer introduction: {e}");

                            // Try to tell the client to cancel the publish task.
                            if let Err(e) = output.try_send(Message::PublishRequestResulted(nonce, PublishRequestResult::Failure(Arc::new(e.into())))) {
                                tracing::error!("Failed to perform internal message passing for subscription peer: {e}");
                            }
                            return;
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
                    return;
                }
            }
        }
    }
}

/// Data for `peers_requesting_publish_loop`.
struct PeerRequestingPublishData {
    pub publish: Publish,
    pub nonce: Nonce,
    pub cancellation_token: CancellationToken,
    pub our_external_address: SocketAddr,
}
impl std::hash::Hash for PeerRequestingPublishData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.publish.hash.hash(state);
        self.nonce.hash(state);
    }
}

/// For the given publish, await peers that desire to receive the file.
fn peers_requesting_publish_loop(
    data: &PeerRequestingPublishData,
) -> impl futures_util::stream::Stream<Item = Message> {
    let PeerRequestingPublishData {
        publish,
        nonce,
        cancellation_token,
        our_external_address,
    } = data;

    let publish = publish.clone();
    let nonce = *nonce;
    let cancellation_token = cancellation_token.clone();
    let our_external_address = *our_external_address;

    iced::stream::channel(8, async move |output| {
        peers_requesting_publish_inner_loop(
            publish,
            nonce,
            &cancellation_token,
            our_external_address,
            output,
        )
        .await;

        // If we needed to return from the loop, then cancel this item.
        cancellation_token.cancel();
    })
}

/// An asynchronous loop to await new requests from a peer connection.
#[tracing::instrument(skip_all)]
async fn connected_peer_request_inner_loop(
    connection: &quinn::Connection,
    peer_address: &SocketAddr,
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
                    return;
                }
            }

            Err(e) => {
                if cfg!(debug_assertions) {
                    tracing::debug!("Peer connection closed: {peer_address} {e:?}");
                } else {
                    tracing::debug!("Peer connection closed: {e:?}");
                }
                return;
            }
        }
    }
}

/// Data for `connected_peer_request_loop`.
struct ConnectedPeerRequestData {
    pub connection: quinn::Connection,
    pub peer_addr: SocketAddr,
}
impl std::hash::Hash for ConnectedPeerRequestData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.connection.stable_id().hash(state);
    }
}

/// For the given peer connection, await new requests.
fn connected_peer_request_loop(
    data: &ConnectedPeerRequestData,
) -> impl futures_util::stream::Stream<Item = Message> {
    let ConnectedPeerRequestData {
        connection,
        peer_addr,
    } = data;

    let connection = connection.clone();
    let peer_addr = *peer_addr;

    iced::stream::channel(8, async move |output| {
        connected_peer_request_inner_loop(&connection, &peer_addr, output).await;

        // If we needed to return from the loop, then close this connection.
        let id = connection.stable_id();
        connection.close(GOODBYE_CODE, GOODBYE_MESSAGE.as_bytes());
        ConnectionsManager::instance()
            .remove_peer(peer_addr, id)
            .await;
    })
}

/// Listen for incoming QUIC connections, renew NAT traversal port mappings, and manage new publish requests from peers directly and from the server.
pub fn connected<'a, I>(
    endpoint: &quinn::Endpoint,
    external_address: &SocketAddr,
    port_mapping: Option<&PortMapping>,
    publishes: I,
) -> Subscription<Message>
where
    I: IntoIterator<Item = &'a PublishItem>,
{
    // Create a task to listen for incoming connections to our QUIC endpoint.
    let incoming_connections = {
        let endpoint = endpoint.clone();
        Subscription::run_with(
            IncomingConnectionsData { endpoint },
            incoming_connections_loop,
        )
    };

    // Create a task to renew the port mapping in a loop.
    let port_mapping = port_mapping.into_iter().map(|mapping| {
        Subscription::run_with(
            PortMappingData {
                mapping: mapping.clone(),
            },
            port_mapping_loop,
        )
    });

    // For each active publish, listen to the server for new peers requesting the file.
    let pubs = publishes.into_iter().filter_map(|publish| {
        // If the publish is still hashing, skip for now.
        let PublishItem {
            nonce,
            cancellation_token,
            state: PublishState::Publishing(publish),
            ..
        } = publish
        else {
            return None;
        };
        if cancellation_token.is_cancelled() {
            // If the cancellation token is cancelled, skip this publish.
            // This shouldn't happen but this check is included out of an abundance of caution.
            return None;
        }

        // Subscribe to the server for new peers to upload to.
        Some(Subscription::run_with(
            PeerRequestingPublishData {
                publish: publish.clone(),
                nonce: *nonce,
                cancellation_token: cancellation_token.clone(),
                our_external_address: *external_address,
            },
            peers_requesting_publish_loop,
        ))
    });

    // Create a listener for each peer that may want a new request stream.
    let peer_requests = ConnectionsManager::instance().filter_map(|(peer_addr, connection)| {
        let crate::core::IncomingPeerState::Connected(connection) = connection else {
            return None;
        };

        let peer_addr = *peer_addr;
        Some(Subscription::run_with(
            ConnectedPeerRequestData {
                connection: connection.clone(),
                peer_addr,
            },
            connected_peer_request_loop,
        ))
    });

    // Batch all the listeners together.
    Subscription::batch(
        [unhandled_events(), animation(), incoming_connections]
            .into_iter()
            .chain(port_mapping)
            .chain(pubs)
            .chain(peer_requests),
    )
}

/// Listen for application close events when disconnected.
#[inline]
pub fn disconnected() -> Subscription<Message> {
    unhandled_events()
}
