# Use the nightly Rust image
FROM rustlang/rust:nightly-slim AS builder

# Set the working directory
WORKDIR /app

# Copy the project files
COPY . .

# Build the project in release mode
RUN cargo build --release

# Use a minimal base image for the final image
FROM debian:bullseye-slim

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder
COPY --from=builder /app/target/release/echopod /usr/local/bin/echopod

# Expose the port the app runs on
EXPOSE 8040

# Set environment variables
ENV RUST_LOG=info \
    ECHOPOD_PORT=8040 \
    ECHOPOD_DATA=/app/data \
    ECHOPOD_DOWNLOADS=/app/downloads

# Create directories for persistent data
RUN mkdir -p /app/data /app/downloads

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/echopod"]

# Default command
CMD ["--help"]
