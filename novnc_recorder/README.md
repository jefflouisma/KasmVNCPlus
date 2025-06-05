# NoVNC Recorder

NoVNCRecorder is a Rust-based session recording service designed for integration with KasmVNC container environments. Its primary function is to capture VNC sessions (video and potentially audio) and save them as standard video files (e.g., MP4, WebM, AVI).

This project is currently under development.

## Current Status & Known Issues

**IMPORTANT:** The project is currently experiencing build issues within the development environment. `cargo build` and even `cargo check` commands are timing out. This is suspected to be due to resource constraints in the environment when compiling dependencies, particularly those with heavy `build.rs` scripts or procedural macros (e.g., `ffmpeg-sys-next`, `x11rb`, `clap`).

As a result, much of the implemented Rust code is **unverified by the Rust compiler/checker**. The features listed below under "Implemented (but Unverified)" are coded but could not be confirmed to compile or pass tests in the current environment.

## Features

### Implemented (but Unverified)

*   **Configuration Management:**
    *   Loads settings from a YAML file (default: `config.yaml`, customizable via `--config` CLI arg or `NOVNC_RECORDER_CONFIG_PATH` env var).
    *   See `config.example.yaml` for options.
*   **Session Lifecycle (Basic Structure):**
    *   Application structure to start, run, and handle shutdown signals (SIGINT, SIGTERM).
    *   Placeholder tasks for screen capture, audio capture, and encoding.
*   **Inter-Task Communication (Basic Structure):**
    *   Uses Tokio MPSC channels to pass video/audio data between capture and encoding tasks.
*   **Screen Capture (Partial Implementation - Unverified):**
    *   Code to connect to X11 server and grab screen images.
    *   Intended to send `RawVideoFrame` data to an encoding task.
*   **File Management Utilities (Unverified):**
    *   Generates unique filenames for recordings (e.g., `session_<id>_<timestamp>.<ext>`).
    *   Ensures the output directory exists.
*   **Command-Line Interface (Unverified):**
    *   Parses CLI arguments using `clap`.
    *   `--config <path>`: Specify configuration file.
    *   `--dry-run`: Load config, check paths, generate sample filename, and exit.
*   **Core Data Types:**
    *   Defined `RawVideoFrame` and `RawAudioSamples` for internal data representation.

### Planned / Deferred (due to build issues)

*   **Verified compilation and functionality of all above features.**
*   **Audio Capture:** Full implementation of capturing audio via PulseAudio.
*   **Encoding Pipeline:** Full implementation of video/audio encoding and muxing into specified file formats using FFmpeg.
*   **Robust Error Handling and Recovery.**
*   **Comprehensive Logging.**
*   **Unit and Integration Tests (beyond basic file utils).**

## Prerequisites and Setup

To build and run `novnc_recorder` locally (outside the currently problematic environment), you'll need a Rust environment and several system dependencies.

A setup script `setup_environment.sh` is provided for Debian-based systems (e.g., Ubuntu).

1.  **Ensure the script is executable:**
    ```bash
    chmod +x setup_environment.sh
    ```
2.  **Run the script:**
    ```bash
    sudo ./setup_environment.sh
    ```
    This will:
    *   Install Rust and Cargo via `rustup`.
    *   Install FFmpeg (libav) development libraries.
    *   Install X11 client development libraries.
    *   Install PulseAudio development libraries.
    *   Install Clang and libclang-dev (for `bindgen`).
    *   Install other build essentials.

## Configuration

NoVNCRecorder is configured via a YAML file. An example `config.example.yaml` should be provided in the repository (currently, a basic `config.yaml` is used for testing).

Key options (see `src/config.rs` for full structure):

*   `output-directory`: Path to save recordings (e.g., `/recordings/`).
*   `video-format`: `mp4`, `webm`, or `avi`.
*   `framerate`: Video frames per second (e.g., `15`).
*   `resolution` (optional):
    *   `width`: e.g., `1920`
    *   `height`: e.g., `1080`
    *   If not set, uses native resolution. Downscaling/upscaling behavior TBD.
*   `audio`: `true` or `false` to enable/disable audio capture.
*   `max-duration-seconds` (optional): Maximum recording length in seconds.
*   `log-level`: e.g., `info`, `debug`, `warn`, `error`.

## How to Run (Conceptual - Post Build Fix)

1.  **Build the project:**
    ```bash
    cargo build --release
    ```
2.  **Prepare your `config.yaml` file.**
3.  **Run NoVNCRecorder:**
    ```bash
    # Basic run with default config.yaml path
    ./target/release/novnc_recorder

    # Specify a config file
    ./target/release/novnc_recorder --config /path/to/your/custom_config.yaml

    # Dry run to check configuration
    ./target/release/novnc_recorder --config /path/to/config.yaml --dry-run
    ```
    Ensure the `DISPLAY` environment variable is set correctly if running in an X11 environment. For KasmVNC integration, the recorder would be launched as part of the container's startup sequence.

## Project Structure (Brief Overview)

*   `src/main.rs`: Main application entry point, task spawning, signal handling.
*   `src/config.rs`: Configuration struct definitions and loading logic.
*   `src/cli.rs`: Command-line argument parsing.
*   `src/file_utils.rs`: Filename generation, directory management.
*   `src/types.rs`: Core data structures (RawVideoFrame, RawAudioSamples).
*   `src/screen_capture.rs`: (Unverified) X11 screen capture logic.
*   `src/setup_environment.sh`: Dependency installation script.
*   `config.yaml`: Sample configuration file.
```
