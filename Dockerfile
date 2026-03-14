# Build stage - use the official Rust image with Alpine
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Set up workspace
WORKDIR /usr/src/file_yeet

# Copy shared library first (dependency)
COPY shared/ ./shared/

# Copy server code
COPY server/ ./server/

# Build the server binary in release mode for smaller size
WORKDIR /usr/src/file_yeet/server
RUN cargo build --release --bin file_yeet_server

# Runtime stage - minimal Alpine Linux
FROM alpine:latest

# Install only the runtime dependencies (if any)
RUN apk add --no-cache ca-certificates

# Create a non-root user for security
RUN addgroup -g 1000 -S file_yeet && \
    adduser -u 1000 -S file_yeet -G file_yeet

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/file_yeet/server/target/release/file_yeet_server /usr/local/bin/file_yeet_server

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/file_yeet_server

# Switch to non-root user
USER file_yeet

# Expose the port that the server will be running on
EXPOSE 7828

# TODO: Allow user to choose either the self-signed certificate arg or specify the path to the certificate and key files
CMD ["file_yeet_server", "--bind-ip=0.0.0.0", "--bind-port=7828", "--self-sign-certificate"]