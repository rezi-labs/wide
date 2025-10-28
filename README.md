# wide
a low memory reverse-proxy with automatic Let's Encrypt support

## Features

- **Automatic HTTPS**: Automatic Let's Encrypt certificate provisioning and renewal
- **HTTP to HTTPS redirect**: Automatically redirects HTTP traffic to HTTPS
- **Domain-based routing**: Route requests to different backends based on the host header
- **Environment-based configuration**: Disable HTTPS for local development
- **Low memory footprint**: Efficient reverse proxy built with Rust and Axum

## Configuration

Create a `proxy.yaml` file with your routing configuration:

```yaml
routes:
  example.com:
    backend: "127.0.0.1:3000"
    https: false  # backend uses HTTP
  api.example.com:
    backend: "127.0.0.1:3001"
    https: false

# Optional ACME configuration
acme:
  email: "admin@example.com"
  cert_dir: "./certs"
  staging: false  # Set to true for testing
```

## Environment Variables

- `DISABLE_HTTPS=true` - Disable HTTPS and Let's Encrypt for local development
- `DEFAULT_DOMAIN=example.com` - Set default domain for TLS configuration

## Usage

### Production (with HTTPS)
```bash
cargo run
```

### Local Development (HTTP only)
```bash
DISABLE_HTTPS=true cargo run
```

## ACME Challenge Handling

The proxy automatically handles ACME HTTP-01 challenges on port 80. Make sure:
1. Port 80 and 443 are accessible from the internet
2. DNS points to your server
3. No other services are using these ports

## Certificate Storage

Certificates are automatically stored in the configured `cert_dir` (default: `./certs/`) and are automatically renewed before expiration.
