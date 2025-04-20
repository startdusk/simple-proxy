# Simple Reverse Proxy with Pingora

A high-performance HTTP/HTTPS proxy built with Cloudflare's [Pingora](https://github.com/cloudflare/pingora), forwarding requests to an example Axum web server.

## Features

**Proxy Server (main.rs/lib.rs)**
- HTTP/1.1 and HTTP/2 support
- Request/Response header modification
- Upstream connection pooling
- Adds custom headers:
  - `X-Simple-Version`: Proxy version
  - `User-Agent`: Identifies proxy
  - `Server`: Hides upstream server info

**Example Backend (server.rs)**
- REST API for user management
- CRUD operations with in-memory storage (DashMap)
- Secure password hashing with Argon2
- Request/Response logging
- Health check endpoint
- Full test coverage

## Prerequisites
- Rust 1.75+
- Cargo
- OpenSSL

## Getting Started

```bash
git clone https://github.com/yourusername/simple-proxy.git
cd simple-proxy
# Start the proxy (port 8080)
RUST_LOG=info cargo run --release

# In another terminal, start the example server (port 3000)
RUST_LOG=info cargo run --example server
```

## LICENSE
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
