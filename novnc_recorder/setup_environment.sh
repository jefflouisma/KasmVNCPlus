#!/bin/bash
# setup_environment.sh
# Script to install dependencies for building and running NoVNCRecorder.
# Assumes a Debian-based system (e.g., Ubuntu, Debian).

set -euxo pipefail

echo ">>> Updating package lists..."
apt-get update

echo ">>> Installing Rust and Cargo (via rustup)..."
if ! command -v cargo &> /dev/null
then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # Add cargo to PATH for current session
    source "$HOME/.cargo/env"
else
    echo "Rust/Cargo already installed."
fi

echo ">>> Installing FFmpeg (libav) development libraries..."
apt-get install -y \
    libavutil-dev \
    libavformat-dev \
    libavcodec-dev \
    libavfilter-dev \
    libavdevice-dev \
    pkg-config

echo ">>> Installing X11 client libraries (for x11rb)..."
apt-get install -y \
    libx11-dev \
    libxcb1-dev \
    libxkbcommon-dev \
    libxcb-randr0-dev \
    libxcb-shm0-dev \
    libxcb-image0-dev \
    libxcb-render0-dev \
    libxcb-xfixes0-dev \
    # Add other xcb libraries as needed by x11rb features if issues arise

echo ">>> Installing PulseAudio development libraries (for libpulse-binding)..."
apt-get install -y libpulse-dev

echo ">>> Installing Clang (for bindgen, used by some -sys crates)..."
apt-get install -y clang libclang-dev

echo ">>> Installing other build essentials..."
apt-get install -y build-essential gcc g++ make

echo ">>> Environment setup complete."
echo ">>> To build the project, navigate to the project directory and run: cargo build"
echo ">>> Ensure Rust is in your PATH (e.g., source \"\$HOME/.cargo/env\") if not already."
