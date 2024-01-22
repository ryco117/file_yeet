# File Yeet

A minimal client/server model to allow peers to share files directly by using the server for peer discovery to establish a peer-to-peer connection.

Uses TCP hole punching techniques to allow peers to transfer data directly. Special thanks to [TheOnlyArtz](https://github.com/TheOnlyArtz) for [this repo](https://github.com/TheOnlyArtz/rust-tcp-holepunch) because it served as a reference for hole punching techniques.

## Usage

### Server
```bash
$ cargo r --release --bin file_yeet_server -- -h
Usage: file_yeet_server [OPTIONS]

Options:
  -b, --bind-ip <BIND_IP>      The IP address the server will bind to. The default is local for testing
  -p, --bind-port <BIND_PORT>  The port the server will bind to [default: 7828]
  -h, --help                   Print help
  -V, --version                Print version
```

#### Docker
I've also created a docker container specific to the server to simplify the deployment of the file yeet servers to different machines and clouds.
An official container build is available at `ryco117/file_yeet_server:latest`. However, a local container instance can be built with:
```bash
docker build -t file_yeet_server:local .
```
**Note**: The docker container must be run with `--net=host` to ensure that the container has visibility of the client's IP address, instead of a docker intermediary.


### Client
*TODO*

## License
This project is licensed under the MIT License
