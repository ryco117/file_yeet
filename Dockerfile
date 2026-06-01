# Build stage - use the official Rust image with Alpine
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Set up workspace
WORKDIR /usr/src/file_yeet

# Copy workspace manifests and lock file first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Copy client manifest only (no source needed — satisfies workspace member resolution)
COPY client/Cargo.toml ./client/

# Copy shared library and server source
COPY shared/ ./shared/
COPY server/ ./server/

# Build the server binary in release mode for smaller size
RUN cargo build --release -p file_yeet_server

# Runtime stage - minimal Alpine Linux
FROM alpine:latest

# Install only the runtime dependencies (if any)
RUN apk add --no-cache ca-certificates

# Create a non-root user for security
RUN addgroup -g 1000 -S file_yeet && \
    adduser -u 1000 -S file_yeet -G file_yeet

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/file_yeet/target/release/file_yeet_server /usr/local/bin/file_yeet_server
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/file_yeet_server /usr/local/bin/docker-entrypoint.sh

# Switch to non-root user
USER file_yeet

# Expose the port that the server will be running on
EXPOSE 7828

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
