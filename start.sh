#!/bin/bash

# Start script for WIDE reverse proxy
echo "Starting WIDE reverse proxy..."

# Set default environment variables if not provided
export DISABLE_HTTPS=${DISABLE_HTTPS:-"false"}
export HTTP_PORT=${HTTP_PORT:-"80"}
export HTTPS_PORT=${HTTPS_PORT:-"443"}

echo "Configuration:"
echo "  DISABLE_HTTPS: $DISABLE_HTTPS"
echo "  HTTP_PORT: $HTTP_PORT"
echo "  HTTPS_PORT: $HTTPS_PORT"

# You can add additional startup tasks here
# For example:
# - Wait for dependencies
# - Initialize configuration
# - Run health checks
# - Start monitoring services

echo "Launching WIDE..."
exec ./wide
