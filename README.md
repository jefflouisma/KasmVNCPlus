# KasmVNC Plus

[![KasmVNC](https://img.shields.io/badge/KasmVNC-1.4.x-blue)](https://github.com/kasmtech/KasmVNC)

This is an enhanced fork of [KasmVNC](https://github.com/kasmtech/KasmVNC) that adds:

- **OAuth 2.0/OIDC Authentication**: Secure SSO integration with Keycloak, Okta, Zitadel, and other OIDC providers
- **Session Recording**: High-quality recording of KasmVNC sessions

## Plus Features

### OAuth Server (`oauth/`)
A standalone OAuth 2.0/OIDC authentication server that provides:
- Authorization Code Flow with PKCE
- JWT validation with cached JWKS
- WebSocket authentication for VNC connections
- Session management and VNC display allocation
- TOML configuration with environment variable support

### Session Recorder (`novnc_recorder/`)
A powerful session recorder that provides:
- High-quality video recording via `x11grab`
- Optional PulseAudio capture
- Multiple output formats (mp4, webm, avi)
- Customizable resolution and frame rate

---

## Building

### Prerequisites
- **Rust 1.70+** for Plus components
- **CMake, GCC/Clang** for KasmVNC C++ build
- **OpenSSL development libraries**

### Build Plus Components Only
```bash
cargo build --release
```

### Build Full KasmVNC + Plus (Docker)
```bash
docker build -t kasmvnc-plus -f docker/Dockerfile.plus .
```

---

## Configuration

### OAuth Configuration
Create `oauth.toml` with your OIDC provider settings:

```toml
enabled = true
provider = "keycloak"

[endpoints]
issuer = "http://localhost:8089/realms/test"
authorization = "http://localhost:8089/realms/test/protocol/openid-connect/auth"
token = "http://localhost:8089/realms/test/protocol/openid-connect/token"
jwks = "http://localhost:8089/realms/test/protocol/openid-connect/certs"
# For containerized deployment - server-to-server communication
internal_base_url = "http://host.docker.internal:8089"

[client]
client_id = "kasmvnc"
client_secret = "${OAUTH_CLIENT_SECRET}"
redirect_uri = "http://localhost:8443/auth/callback"
scope = "openid profile email"

[security]
use_pkce = true
require_state = true
```

---

## License

See [LICENSE.TXT](LICENSE.TXT) for the KasmVNC license.

---

## Upstream KasmVNC

This project is based on [KasmVNC](https://github.com/kasmtech/KasmVNC), a modern open-source VNC server with advanced features. See the original repository for full documentation on the core VNC functionality.
