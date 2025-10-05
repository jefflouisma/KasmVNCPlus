# KasmVNC Recorder & OAuth

This project provides a comprehensive session recording and authentication solution for KasmVNC, built in Rust. It consists of two primary components within a Cargo workspace:

- **`novnc_recorder`**: A powerful and flexible session recorder that uses `ffmpeg` to capture the desktop, along with optional audio, from a running KasmVNC session.
- **`kasmvnc-oauth-server`**: A modern, standalone OAuth 2.0/OIDC authentication service that provides secure, token-based access to KasmVNC sessions, replacing or supplementing the default HTTP Basic Authentication.

## Features

- **Session Recording (`novnc_recorder`)**
  - High-quality video recording of KasmVNC sessions via `x11grab`.
  - Optional audio capture using PulseAudio.
  - Support for multiple output formats (`mp4`, `webm`, `avi`).
  - Customizable resolution, frame rate, and encoding presets.
  - Automatic file naming with session identifiers and timestamps.
  - Graceful shutdown on signals or when a configured time limit is reached.

- **Authentication (`kasmvnc-oauth-server`)**
  - Implements the OAuth 2.0 Authorization Code Flow with PKCE for enhanced security.
  - Validates JWTs using a cached JWKS for high performance.
  - Secures the VNC WebSocket connection with a first-message authentication pattern.
  - Manages user sessions and VNC display allocation.
  - Highly configurable via a TOML file with support for environment variable overrides.

## Project Structure

This project is organized as a Rust workspace with two separate crates:

- **`novnc_recorder/`**: Contains the session recording service.
- **`oauth/`**: Contains the OAuth 2.0/OIDC authentication server.

This structure ensures a clean separation of concerns and allows each component to be developed and deployed independently.

## Getting Started

### Prerequisites

- **Rust**: Ensure you have Rust 1.70+ installed. You can install it using `rustup`:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **OpenSSL**: The project requires OpenSSL development libraries.
  - **Debian/Ubuntu**: `sudo apt-get install libssl-dev`
  - **CentOS/RHEL**: `sudo yum install openssl-devel`
  - **macOS**: `brew install openssl`

### Building

To build both the recorder and the authentication server, run the following command from the root of the project:

```bash
cargo build --release
```

The compiled binaries will be available in the `target/release/` directory:
- `novnc_recorder`
- `kasmvnc-oauth-server`

## `kasmvnc-oauth-server`

The `kasmvnc-oauth-server` is a standalone service that provides robust OAuth 2.0/OIDC authentication for KasmVNC.

### Configuration

Create a TOML file (e.g., `config/oauth.toml`) to configure the service. You can specify the path to this file using the `OAUTH_CONFIG` environment variable.

```toml
# KasmVNC OAuth Configuration

# Enable or disable the OAuth service.
enabled = true
# The name of the OAuth provider (e.g., "zitadel", "google", "okta").
provider = "zitadel"

[endpoints]
# The issuer URL of your OAuth provider.
issuer = "https://your-instance.zitadel.cloud"
# The authorization, token, jwks, and userinfo endpoints.
# If a discovery URL is provided, these will be fetched automatically.
authorization = "https://your-instance.zitadel.cloud/oauth/v2/authorize"
token = "https://your-instance.zitadel.cloud/oauth/v2/token"
jwks = "https://your-instance.zitadel.cloud/oauth/v2/keys"
userinfo = "https://your-instance.zitadel.cloud/oidc/v1/userinfo"
# OIDC discovery endpoint for automatic configuration.
discovery = "https://your-instance.zitadel.cloud/.well-known/openid-configuration"

[client]
# Your OAuth client ID and secret. Use environment variables for secrets.
client_id = "${OAUTH_CLIENT_ID}"
client_secret = "${OAUTH_CLIENT_SECRET}"
# The redirect URI registered with your OAuth provider.
redirect_uri = "https://your-server.com/auth/callback"
# The scopes to request from the provider.
scope = "openid profile email"

[security]
use_pkce = true
pkce_method = "S256"
require_state = true

[security.token_validation]
# Enable or disable validation of various JWT claims.
verify_signature = true
verify_issuer = true
verify_audience = true
verify_expiration = true
# Clock skew tolerance in seconds for token validation.
clock_skew_seconds = 60

[tokens]
# Lifetimes for tokens and JWKS cache TTL (in seconds).
access_token_lifetime = 3600      # 1 hour
refresh_token_lifetime = 7776000  # 90 days
jwks_cache_ttl = 86400           # 24 hours

[session]
# Session configuration.
timeout_seconds = 28800          # 8 hours
idle_timeout_seconds = 3600      # 1 hour
allow_multiple_sessions = true
max_sessions_per_user = 5

[logging]
# Logging configuration.
level = "info"
log_tokens = false
log_claims = true
```

### Running

To run the authentication server, use the following command:

```bash
OAUTH_CONFIG=/path/to/oauth.toml cargo run --bin kasmvnc-oauth-server
```

## `novnc_recorder`

`novnc_recorder` launches `ffmpeg` to capture the desktop and audio of a KasmVNC session.

### Configuration

Create a YAML file (e.g., `config/novnc_recorder.yaml`). The path can be provided as a command-line argument or via the `NOVNC_RECORDER_CONFIG` environment variable. The default location is `/etc/novnc_recorder.yaml`.

```yaml
# The directory where recordings will be saved.
output_dir: /recordings
# The output format for the recording. Supported formats: mp4, webm, avi.
format: mp4
# The frame rate of the recording.
frame_rate: 30
# The resolution of the recording.
width: 1280
height: 720
# Enable or disable audio capture.
audio: true
# The maximum duration of a recording in seconds.
max_duration: 3600
# The path to the ffmpeg binary.
ffmpeg_path: ffmpeg
# The libx264 preset for encoding quality (e.g., ultrafast, superfast, medium).
preset: medium
# The libx264 Constant Rate Factor (0-51). Lower values mean higher quality.
crf: 23
```

### Running

To run the session recorder, use the following command:

```bash
cargo run --bin novnc_recorder /path/to/config.yaml
```

The recorder will spawn `ffmpeg` with the specified parameters. When the process is stopped, the output file will be finalized and saved.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.