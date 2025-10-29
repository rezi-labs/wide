# Build stage - use nightly for 2024 edition support
FROM rustlang/rust:nightly AS builder

# Set environment variables for faster builds
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# Create app directory
WORKDIR /app

# Copy Cargo files first - this layer will be cached unless dependencies change
COPY Cargo.toml Cargo.lock ./

# Create dummy source structure to match your project
RUN mkdir -p src/certificate
RUN echo "pub mod certificate; pub mod config; pub mod proxy; fn main() {}" > src/main.rs
RUN echo "pub fn dummy() {}" > src/config.rs
RUN echo "pub fn dummy() {}" > src/proxy.rs
RUN echo "pub fn dummy() {}" > src/certificate/mod.rs

# Build dependencies - this layer will be cached unless Cargo.toml/Cargo.lock changes  
RUN cargo build --release
RUN rm -rf src

# Copy actual source code (this layer invalidates only when source changes)
COPY src ./src

# Build the application with dependencies already cached
RUN cargo build --release

# Strip the binary to reduce size
RUN strip /app/target/release/wide

# Runtime stage - optimized debian slim
FROM debian:bookworm-slim

# Install runtime dependencies in single layer and clean up
RUN apt-get update && apt-get install -y \
    ca-certificates \
    --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --user-group --uid 1000 wide

# Create app directory and set ownership
WORKDIR /app
RUN mkdir -p certs && chown -R wide:wide /app

# Copy files with correct ownership
COPY --from=builder --chown=wide:wide /app/target/release/wide ./wide
COPY --chown=wide:wide start.sh ./start.sh
COPY --chown=wide:wide proxy.toml* ./

# Make start script executable
RUN chmod +x ./start.sh

# Switch to non-root user
USER wide

# Expose ports
EXPOSE 80 443

# Use the start script as entrypoint
ENTRYPOINT ["./start.sh"]