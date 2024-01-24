use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs as _};

/// Magic number for the default port.
pub const DEFAULT_PORT: u16 = 7828;

/// Define a sane maximum payload size for the client.
pub const MAX_PAYLOAD_SIZE: usize = 1024;

// TODO: Create a custom `chrono` datetime format

/// A helper to access often used socket address info.
pub struct SocketAddrHelper {
    pub addr: SocketAddr,
    pub hostname: String,
}

/// Helper to get either the socket address corresponding to the user's input, or the default of IPv4 localhost.
///
/// # Errors
/// If there is `Some(..)` non-empty server address, then it must be of the format `hostname:port`
/// to be able to parse into a socket address using `ToSocketAddrs`. If the address cannot be parsed, it will
/// fail with a `std::io::Error` instead of using the default.
pub fn get_server_or_default(
    server_address: &Option<String>,
    port: u16,
) -> Result<SocketAddrHelper, std::io::Error> {
    // Parse the server address if one was specified.
    server_address
        .iter()
        .find_map(|s| {
            if s.is_empty() {
                None
            } else {
                match (s.as_str(), port).to_socket_addrs() {
                    Ok(mut addrs) => addrs.next().map(|addr| {
                        Ok(SocketAddrHelper {
                            addr,
                            hostname: s.clone(),
                        })
                    }),
                    Err(e) => Some(Err(e)),
                }
            }
        })
        .unwrap_or_else(|| {
            Ok(SocketAddrHelper {
                addr: (Ipv4Addr::LOCALHOST, port).into(),
                hostname: Ipv4Addr::LOCALHOST.to_string(),
            })
        })
}
