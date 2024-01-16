use std::{
    collections::HashMap,
    io::Write,
    net::{IpAddr, TcpListener, TcpStream},
    time::Duration,
};

use chrono::Local;
use clap::Parser;
use file_yeet_shared::Address;

struct Client {
    stream: TcpStream,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The IP address the server will bind to. The default is local for testing.
    #[arg(short = 'b', long)]
    bind_ip: Option<String>,

    /// The port the server will bind to.
    #[arg(short='p', long, default_value_t = file_yeet_shared::DEFAULT_PORT)]
    bind_port: u16,
}

// Set a sensible timeout for TCP streams.
const STREAM_TIMEOUT: Duration = Duration::from_millis(1200);

fn main() {
    // Parse command line arguments.
    let args = Cli::parse();

    // Determine which address to bind to.
    // TODO: Allow using an IPv6 address to bind to.
    let bind_address = Address {
        ip: IpAddr::V4(
            args.bind_ip
                .as_ref()
                .map_or(file_yeet_shared::DEFAULT_IPV4, String::as_str)
                .parse()
                .expect("Invalid IP address"),
        ),
        port: args.bind_port,
    };

    // Print out the address we're going to bind to.
    println!("{} Using bind address: {bind_address:?}", Local::now());

    // Attempt to bind to the address.
    let listener = TcpListener::bind(bind_address).expect("Failed to bind to the address");

    // Maintain a collection of clients, indexed by their address.
    let mut client_set = HashMap::new();

    // Iterate over incoming connections.
    for incoming_peer in listener.incoming() {
        // Handle the incoming connection.
        if let Err(err) = handle_incoming(incoming_peer, &mut client_set) {
            eprintln!(
                "{} Failed to handle incoming connection: {err}",
                Local::now()
            );
        }
    }
}

// Handle incoming connections.
fn handle_incoming(
    incoming_peer: std::io::Result<TcpStream>,
    client_set: &mut HashMap<String, Client>,
) -> Result<(), std::io::Error> {
    match incoming_peer {
        // Print out the peer's address on a successful connection.
        Ok(mut stream) => {
            let new_address = stream.peer_addr()?.to_string();
            println!("{} New connection from: {}", Local::now(), &new_address);

            // Set custom timeouts for the stream to ensure we don't block threads forever.
            stream.set_read_timeout(Some(STREAM_TIMEOUT))?;
            stream.set_write_timeout(Some(STREAM_TIMEOUT))?;

            // TODO: Handle the new connection by determining if it is posting a new file or requesting a file...
            // // Create a scratch space for reading data from the stream.
            // let mut buf = [0; file_yeet_shared::MAX_PAYLOAD_SIZE];
            // file_yeet_shared::read_stream(&mut stream, &mut buf)

            // Maintain a list of clients to drop from memory.
            let mut clients_to_drop = Vec::new();

            // Update every other peer with the new peer's address,
            // and send the new peer the address of every other peer.
            for (existing_address, client) in client_set.iter_mut() {
                if let Err(err) = client.stream.write_all(new_address.as_bytes()) {
                    eprintln!("Failed to send peer address to: {existing_address} {err}");
                    clients_to_drop.push(existing_address.clone());
                } else {
                    stream.write_all(existing_address.as_bytes())?;
                }
            }

            // Drop any clients that failed to receive the new peer's address.
            for address in clients_to_drop {
                client_set.remove(&address);
            }

            // Add the new client to the our managed set.
            client_set.insert(new_address, Client { stream });
        }

        // Print error on failed connection.
        Err(e) => eprintln!("Failed to receive connection: {e:?}"),
    }

    // Return success.
    Ok(())
}
