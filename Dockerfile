# Use a basic Rust image as a base
FROM rust:1.89.0-alpine

# Copy the source code into the container
WORKDIR /usr/src/file_yeet
RUN mkdir -p ./server/
COPY server/Cargo.toml ./server/
COPY server/Cargo.lock ./server/
COPY server/src ./server/src/
RUN mkdir -p ./shared/
COPY shared/Cargo.toml ./shared/
COPY shared/src ./shared/src/
WORKDIR /usr/src/file_yeet/server

# Install dependencies
RUN apk add musl-dev

# Build and install the server
RUN cargo install --path . --bin file_yeet_server
RUN cargo clean

# Expose the port that the server will be running on
EXPOSE 7828

CMD ["file_yeet_server", "--bind-ip=0.0.0.0", "--bind-port=7828"]