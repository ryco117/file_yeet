# Use a basic Rust image as a base
FROM rust:1.75.0-alpine

# Copy the source code into the container
WORKDIR /usr/src/file_yeet
COPY . .

# Install dependencies
RUN apk add musl-dev

# Build and install the server
RUN cargo install --bin file_yeet_server --path server

# Expose the port that the server will be running on
EXPOSE 7828

CMD ["file_yeet_server", "--bind-ip=0.0.0.0", "--bind-port=7828"]