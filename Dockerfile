# Use a basic Rust image as a base
FROM rust:1.75.0-alpine

# Copy the source code into the container
WORKDIR /usr/src/file_yeet
COPY Cargo.toml ./
COPY Cargo.lock ./
RUN mkdir -p ./client/
COPY client/Cargo.toml ./client/
COPY client/Cargo.lock ./client/
COPY client/src ./client/src/
RUN mkdir -p ./server/
COPY server/Cargo.toml ./server/
COPY server/Cargo.lock ./server/
COPY server/src ./server/src/
RUN mkdir -p ./shared/
COPY shared/Cargo.toml ./shared/
COPY shared/src ./shared/src/

# Install dependencies
RUN apk add musl-dev

# Build and install the server
RUN cargo install --bin file_yeet_server --path server

# Expose the port that the server will be running on
EXPOSE 7828 80

CMD ["file_yeet_server", "--bind-ip=0.0.0.0", "--bind-port=7828"]